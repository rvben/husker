use std::any::TypeId;
use std::path::PathBuf;

use anyhow::Result;

use crate::cli::{COMMAND_CONTRACTS, Cli};
use crate::cli_contract::{CliErrorKind, command_contract};

/// Extract a clean error message from an API error response.
///
/// Handles JSON error bodies, plain text, and empty responses gracefully
/// so the CLI never dumps raw stack traces at the user.
/// Exit codes husker returns for its own failures. `exec` and `shell` instead
/// pass through the guest command's exit code. Documented in `husker schema`.
pub(crate) mod exit_code {
    pub const GENERAL: i32 = 1;
    pub const NOT_FOUND: i32 = 2;
    pub const CONFLICT: i32 = 3;
    pub const DENIED: i32 = 4;
    pub const DAEMON_UNREACHABLE: i32 = 5;
    /// Destructive command attempted without confirmation (no TTY, no --yes).
    pub const CONFIRMATION_REQUIRED: i32 = 6;
}

/// Emit a clispec structured error envelope as a single JSON line.
/// The kind is derived from the ApiFailure code when available; falls back to
/// a generic kind derived from the exit code.
pub(crate) fn render_error_envelope(kind: &str, message: &str, hint: Option<&str>) -> String {
    let mut inner = serde_json::Map::new();
    inner.insert("kind".into(), serde_json::Value::from(kind));
    inner.insert("message".into(), serde_json::Value::from(message));
    if let Some(h) = hint {
        inner.insert("hint".into(), serde_json::Value::from(h));
    }
    let mut outer = serde_json::Map::new();
    outer.insert("error".into(), serde_json::Value::Object(inner));
    serde_json::Value::Object(outer).to_string()
}

/// Build the machine-readable CLI contract emitted by `husker schema`.
/// Conforms to The CLI Spec v0.3 (https://clispec.dev/schema/v0.3.json):
/// `global_args` is an array, `commands` is an array, `errors` is an array.
pub(crate) fn build_cli_schema() -> serde_json::Value {
    use clap::CommandFactory;
    validate_contract_registry().expect("clap commands and CLI contracts must match");
    let root = Cli::command();
    let mut commands: Vec<serde_json::Value> = Vec::new();
    for sub in root.get_subcommands() {
        collect_schema_command(sub, &[], &mut commands);
    }
    // Sort so read-only commands appear before mutating ones, with `list`
    // first (the canonical list command that consumers use for introspection),
    // then other read-only commands, then mutating commands.
    commands.sort_by(|a, b| {
        let priority = |v: &serde_json::Value| -> u8 {
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let mutating = v.get("mutating").and_then(|m| m.as_bool());
            match (name, mutating) {
                ("list", _) => 0,
                (_, Some(false)) => 1,
                (_, Some(true)) => 3,
                _ => 2,
            }
        };
        priority(a).cmp(&priority(b))
    });
    let mut schema = serde_json::json!({
        "$schema": "https://clispec.dev/schema/v0.3.json",
        "clispec": "0.3",
        "name": "husker",
        "version": env!("CARGO_PKG_VERSION"),
        "description": root.get_about().map(|s| s.to_string()).unwrap_or_default(),
        "global_args": schema_global_args(&root),
        "commands": commands,
        "errors": CliErrorKind::ALL.map(|kind| serde_json::json!({
            "kind": kind.name(),
            "exit_code": kind.exit_code(),
            "retryable": kind.retryable(),
            "description": kind.description(),
        })),
        "output": {"tty": "text", "piped": "json"}
    });
    enrich_v0_3(&mut schema);
    schema
}

/// Build a clap arg into the clispec `arg` shape.
fn clap_arg_to_schema(a: &clap::Arg) -> serde_json::Value {
    let id = a.get_id().as_str();
    let flag_name = if let Some(long) = a.get_long() {
        format!("--{long}")
    } else {
        id.to_string()
    };
    let scalar_type = if matches!(
        a.get_action(),
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count
    ) {
        "boolean"
    } else {
        let type_id = a.get_value_parser().type_id();
        if type_id == TypeId::of::<PathBuf>() {
            "path"
        } else if [
            TypeId::of::<u8>(),
            TypeId::of::<u16>(),
            TypeId::of::<u32>(),
            TypeId::of::<u64>(),
            TypeId::of::<usize>(),
            TypeId::of::<i8>(),
            TypeId::of::<i16>(),
            TypeId::of::<i32>(),
            TypeId::of::<i64>(),
            TypeId::of::<isize>(),
        ]
        .into_iter()
        .any(|candidate| type_id == candidate)
        {
            "integer"
        } else if [TypeId::of::<f32>(), TypeId::of::<f64>()]
            .into_iter()
            .any(|candidate| type_id == candidate)
        {
            "number"
        } else {
            "string"
        }
    };
    let type_str = if matches!(a.get_action(), clap::ArgAction::Append) {
        format!("{scalar_type}[]")
    } else {
        scalar_type.to_string()
    };
    let mut o = serde_json::Map::new();
    o.insert("name".into(), serde_json::Value::from(flag_name));
    o.insert("type".into(), serde_json::Value::from(type_str));
    o.insert(
        "required".into(),
        serde_json::Value::from(a.is_required_set()),
    );
    if let Some(help) = a.get_help() {
        o.insert(
            "description".into(),
            serde_json::Value::from(help.to_string()),
        );
    }
    let defaults: Vec<serde_json::Value> = a
        .get_default_values()
        .iter()
        .map(|value| {
            let value = value.to_string_lossy();
            match scalar_type {
                "integer" => value
                    .parse::<i64>()
                    .map(serde_json::Value::from)
                    .unwrap_or_else(|_| serde_json::Value::from(value.into_owned())),
                "number" => value
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::from(value.into_owned())),
                "boolean" => value
                    .parse::<bool>()
                    .map(serde_json::Value::from)
                    .unwrap_or_else(|_| serde_json::Value::from(value.into_owned())),
                _ => serde_json::Value::from(value.into_owned()),
            }
        })
        .collect();
    if defaults.len() == 1 {
        o.insert("default".into(), defaults[0].clone());
    } else if !defaults.is_empty() {
        o.insert("default".into(), serde_json::json!(defaults));
    }
    if let Some(vals) = a.get_possible_values().first() {
        let _ = vals; // ensure no dead-code warning; enum population below
        let enums: Vec<serde_json::Value> = a
            .get_possible_values()
            .iter()
            .map(|v| serde_json::Value::from(v.get_name()))
            .collect();
        if !enums.is_empty() {
            o.insert("enum".into(), serde_json::Value::Array(enums));
        }
    }
    serde_json::Value::Object(o)
}

/// Recursively collect clap subcommands into a clispec commands array.
/// Groups (commands that only hold subcommands) collect their own positional
/// args and pass them down to leaves, which combine inherited + own args.
/// `prefix` is the space-joined path of parent command names for annotation
/// lookups, e.g. "service" when processing children of the `service` group.
fn collect_schema_command(
    cmd: &clap::Command,
    parent_args: &[serde_json::Value],
    out: &mut Vec<serde_json::Value>,
) {
    collect_schema_command_inner(cmd, parent_args, "", out);
}

fn collect_schema_command_inner(
    cmd: &clap::Command,
    parent_args: &[serde_json::Value],
    prefix: &str,
    out: &mut Vec<serde_json::Value>,
) {
    let name = cmd.get_name();
    if name == "help" {
        return;
    }
    let full_path = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix} {name}")
    };

    let own_args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && !a.is_global_set()
        })
        .map(clap_arg_to_schema)
        .collect();

    let subs: Vec<&clap::Command> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();

    if subs.is_empty() {
        // Leaf command: emit it with combined args.
        let mut args = parent_args.to_vec();
        args.extend(own_args);

        let contract = command_contract(&full_path)
            .unwrap_or_else(|| panic!("missing CLI contract for clap leaf '{full_path}'"));
        let output_fields: Vec<serde_json::Value> = contract
            .clispec_fields()
            .iter()
            .map(|field| {
                let mut value = serde_json::json!({
                    "name": field.name,
                    "type": field.kind.name(),
                });
                if !field.required {
                    value["description"] = serde_json::Value::from("Optional field");
                }
                value
            })
            .collect();

        out.push(serde_json::json!({
            "name": full_path,
            "description": cmd.get_about().map(|s| s.to_string()).unwrap_or_default(),
            "mutating": contract.mutating,
            "args": args,
            "output_fields": output_fields,
        }));
    } else {
        // Group command: recurse, passing own positional args downward.
        let mut child_args = parent_args.to_vec();
        child_args.extend(own_args);

        for sub in subs {
            collect_schema_command_inner(sub, &child_args, &full_path, out);
        }
    }
}

fn enrich_v0_3(schema: &mut serde_json::Value) {
    let Some(commands) = schema["commands"].as_array_mut() else {
        return;
    };
    for command in commands {
        let Some(object) = command.as_object_mut() else {
            continue;
        };
        let name = object["name"].as_str().unwrap_or_default().to_string();
        let mutating = object["mutating"].as_bool().unwrap_or(false);
        let non_idempotent = name == "run"
            || name == "fork"
            || name.ends_with(" create")
            || name.ends_with(" import")
            || name.ends_with(" import-oci")
            || name.ends_with(" pull")
            || name.ends_with(" checkout");
        object.insert(
            "effects".into(),
            serde_json::json!(if !mutating {
                "read_only"
            } else if non_idempotent {
                "non_idempotent"
            } else {
                "idempotent"
            }),
        );

        if matches!(
            name.as_str(),
            "daemon" | "shell" | "config check" | "setup storage" | "completions"
        ) {
            object.insert("output_kind".into(), serde_json::json!("opaque"));
            object.insert("media_type".into(), serde_json::json!("text/plain"));
            object.remove("output_fields");
            continue;
        }

        object.insert("cardinality".into(), serde_json::json!("bounded"));
        if name == "list" {
            object.insert("cardinality".into(), serde_json::json!("unbounded"));
            object.insert(
                "pagination".into(),
                serde_json::json!({
                    "style": "offset",
                    "limit_arg": "--limit",
                    "offset_arg": "--offset"
                }),
            );
            object.insert("fields_arg".into(), serde_json::json!("--fields"));
        }
        if name == "schema" {
            object.insert("cardinality".into(), serde_json::json!("single"));
            object.insert(
                "stdout_schema".into(),
                serde_json::json!({"$ref": "https://clispec.dev/schema/v0.3.json"}),
            );
        }
        if name == "capabilities" {
            object.insert("cardinality".into(), serde_json::json!("single"));
            object.insert(
                "example".into(),
                serde_json::json!({"args": ["capabilities"]}),
            );
        }
        if object
            .get("args")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|args| args.iter().any(|arg| arg["name"] == "--yes"))
        {
            object.insert("confirmation_bypass_arg".into(), serde_json::json!("--yes"));
        }
        if object
            .get("output_fields")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
            && !object.contains_key("stdout_schema")
        {
            object.insert("stdout_schema".into(), serde_json::json!({}));
        }
    }
}

/// Global args accepted by every command, derived from the root command.
/// Returns a clispec-compliant array of arg objects.
fn schema_global_args(root: &clap::Command) -> Vec<serde_json::Value> {
    root.get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version"
        })
        .map(clap_arg_to_schema)
        .collect()
}

/// Verify the deletion-test invariant for semantic command metadata: every
/// clap leaf has exactly one contract, and no stale contract survives after a
/// command is removed or renamed.
pub(crate) fn validate_contract_registry() -> Result<()> {
    use clap::CommandFactory;
    use std::collections::BTreeSet;

    fn collect(command: &clap::Command, prefix: &str, paths: &mut Vec<String>) {
        for subcommand in command
            .get_subcommands()
            .filter(|subcommand| subcommand.get_name() != "help")
        {
            let path = if prefix.is_empty() {
                subcommand.get_name().to_string()
            } else {
                format!("{prefix} {}", subcommand.get_name())
            };
            if subcommand
                .get_subcommands()
                .any(|child| child.get_name() != "help")
            {
                collect(subcommand, &path, paths);
            } else {
                paths.push(path);
            }
        }
    }

    let mut clap_paths = Vec::new();
    collect(&Cli::command(), "", &mut clap_paths);
    let clap_paths: BTreeSet<String> = clap_paths.into_iter().collect();
    let contract_paths: BTreeSet<String> = COMMAND_CONTRACTS
        .iter()
        .map(|contract| contract.path.to_string())
        .collect();
    anyhow::ensure!(
        contract_paths.len() == COMMAND_CONTRACTS.len(),
        "CLI contract registry contains duplicate command paths"
    );
    let missing: Vec<_> = clap_paths.difference(&contract_paths).cloned().collect();
    let stale: Vec<_> = contract_paths.difference(&clap_paths).cloned().collect();
    anyhow::ensure!(
        missing.is_empty() && stale.is_empty(),
        "CLI contract registry drift (missing: {missing:?}; stale: {stale:?})"
    );
    Ok(())
}
