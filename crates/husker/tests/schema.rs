//! Tests that `husker schema` output validates against the bundled clispec v0.3
//! JSON Schema fixture. This catches schema shape regressions without network
//! access and without running a daemon.

use assert_cmd::Command;

/// The vendored clispec v0.3 JSON Schema, embedded at compile time so the test
/// is fully self-contained.
const CLISPEC_V03_SCHEMA: &str = include_str!("fixtures/clispec-v0.3.json");

fn schema_document() -> serde_json::Value {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .arg("schema")
        .output()
        .expect("husker schema should run");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).expect("husker schema should emit JSON")
}

fn command_at_path<'a>(document: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    document["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .find(|command| command["name"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("missing command path '{path}'"))
}

fn named_entry<'a>(entries: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    entries
        .as_array()
        .expect("metadata array")
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing metadata entry '{name}'"))
}

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

#[test]
fn schema_uses_semantic_output_types_and_full_command_paths() {
    let document = schema_document();

    let run = command_at_path(&document, "run");
    assert_eq!(named_entry(&run["output_fields"], "vm")["type"], "object");
    assert_eq!(
        named_entry(&run["output_fields"], "userdata_queued")["type"],
        "boolean"
    );

    let balloon = command_at_path(&document, "balloon");
    assert_eq!(
        named_entry(&balloon["output_fields"], "amount_mib")["type"],
        "integer"
    );

    let list = command_at_path(&document, "list");
    assert_eq!(
        named_entry(&list["output_fields"], "vcpu_count")["type"],
        "integer"
    );
    assert_eq!(
        named_entry(&list["output_fields"], "auto_resume")["type"],
        "boolean"
    );
    assert_eq!(
        named_entry(&list["output_fields"], "auto_resume")["nullable"],
        true
    );

    let port_forward_add = command_at_path(&document, "port-forward add");
    assert_eq!(
        named_entry(&port_forward_add["output_fields"], "host_port")["type"],
        "integer"
    );
    assert!(port_forward_add["mutating"].as_bool().unwrap());

    let setup_storage = command_at_path(&document, "setup storage");
    assert_eq!(setup_storage["mutating"], true);
}

#[test]
fn schema_derives_argument_types_and_defaults_from_clap() {
    let document = schema_document();
    let run = command_at_path(&document, "run");
    assert_eq!(named_entry(&run["args"], "rootfs")["type"], "path");
    assert_eq!(
        named_entry(&run["args"], "--idle-timeout")["type"],
        "integer"
    );
    assert_eq!(named_entry(&run["args"], "--env-file")["type"], "path[]");

    let list = command_at_path(&document, "list");
    let limit = named_entry(&list["args"], "--limit");
    assert_eq!(limit["type"], "integer");
    assert_eq!(limit["default"], 100);
}

#[test]
fn schema_advertises_every_stable_cli_error_kind() {
    let document = schema_document();
    let kinds: std::collections::BTreeSet<&str> = document["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|error| error["kind"].as_str())
        .collect();

    for kind in [
        "error",
        "not_found",
        "invalid_usage",
        "conflict",
        "permission_denied",
        "daemon_unreachable",
        "confirmation_required",
        "out_matched_nothing",
        "job_cleanup_failed",
        "vm_not_running",
    ] {
        assert!(kinds.contains(kind), "missing error kind '{kind}'");
    }
}
