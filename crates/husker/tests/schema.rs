//! Tests that `husker schema` output validates against the bundled clispec v0.3
//! JSON Schema fixture. This catches schema shape regressions without network
//! access and without running a daemon.

use assert_cmd::Command;

/// The vendored clispec v0.3 JSON Schema, embedded at compile time so the test
/// is fully self-contained.
const CLISPEC_V03_SCHEMA: &str = include_str!("fixtures/clispec-v0.3.json");

#[test]
fn schema_command_produces_valid_json() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    assert!(output.status.success(), "husker schema should exit 0");
    assert!(
        output.stderr.is_empty(),
        "husker schema should produce no stderr output"
    );

    let stdout = String::from_utf8(output.stdout).expect("schema output should be valid UTF-8");
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("husker schema should emit valid JSON");
}

#[test]
fn schema_validates_against_clispec_v03() {
    let schema_doc: serde_json::Value =
        serde_json::from_str(CLISPEC_V03_SCHEMA).expect("bundled schema should be valid JSON");

    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    assert!(output.status.success(), "husker schema should exit 0");
    let stdout = String::from_utf8(output.stdout).expect("schema output should be valid UTF-8");
    let instance: serde_json::Value =
        serde_json::from_str(&stdout).expect("husker schema should emit valid JSON");

    let validator = jsonschema::validator_for(&schema_doc)
        .expect("bundled clispec v0.3 schema should be a valid JSON Schema");

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| format!("{e}"))
        .collect();

    assert!(
        errors.is_empty(),
        "husker schema output should validate against clispec v0.3:\n{}",
        errors.join("\n")
    );
}

#[test]
fn schema_has_required_clispec_version() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        doc.get("clispec").and_then(|v| v.as_str()),
        Some("0.3"),
        "schema should declare clispec version 0.3"
    );
}

#[test]
fn schema_commands_are_array_with_mutating_markers() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let commands = doc
        .get("commands")
        .and_then(|v| v.as_array())
        .expect("commands should be an array");

    assert!(!commands.is_empty(), "commands array should not be empty");

    for command in commands {
        let name = command.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        assert!(
            command.get("mutating").is_some(),
            "command '{name}' should have a mutating marker"
        );
        assert!(
            command.get("effects").is_some(),
            "command '{name}' should declare effects"
        );
        assert!(command.get("subcommands").is_none());
    }
}

#[test]
fn schema_errors_have_exit_codes() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let errors = doc
        .get("errors")
        .and_then(|v| v.as_array())
        .expect("errors should be an array");

    assert!(!errors.is_empty(), "errors array should not be empty");

    for entry in errors {
        let kind = entry.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
        assert!(
            entry.get("exit_code").and_then(|c| c.as_u64()).is_some(),
            "error kind '{kind}' should have an exit_code"
        );
    }
}

#[test]
fn schema_works_without_config_or_network() {
    // Run with a non-existent config file to prove schema doesn't need one.
    let output = Command::cargo_bin("husker")
        .unwrap()
        .args(["--config", "/nonexistent/path/husker.toml", "schema"])
        .output()
        .expect("husker schema should run");

    assert!(
        output.status.success(),
        "husker schema should succeed even with a non-existent config path"
    );
}

#[test]
fn schema_does_not_resolve_the_daemon_target() {
    // Schema is a local introspection command. An invalid daemon URL must not
    // prevent it from running or turn it into an accidental network command.
    let output = Command::cargo_bin("husker")
        .unwrap()
        .args(["--api-url", "ssh://", "schema"])
        .output()
        .expect("husker schema should run");

    assert!(
        output.status.success(),
        "husker schema should ignore daemon target resolution: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_global_args_is_array() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let global_args = doc
        .get("global_args")
        .and_then(|v| v.as_array())
        .expect("global_args should be an array");

    assert!(
        !global_args.is_empty(),
        "global_args should not be empty (at least --output should be listed)"
    );

    // Every global arg must have name and type.
    for arg in global_args {
        let name = arg.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        assert!(
            arg.get("type").and_then(|t| t.as_str()).is_some(),
            "global arg '{name}' should have a type"
        );
    }
}
