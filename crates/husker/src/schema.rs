use crate::cli::Cli;

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
        "errors": [
            {
                "kind": "error",
                "exit_code": 1,
                "retryable": false,
                "description": "General client or server error"
            },
            {
                "kind": "not_found",
                "exit_code": 2,
                "retryable": false,
                "description": "VM, image, snapshot, volume, or secret not found"
            },
            {
                "kind": "invalid_usage",
                "exit_code": 2,
                "retryable": false,
                "description": "Invalid command-line usage (unknown flag, missing or invalid argument). Shares exit code 2 with not_found; the error `kind` field disambiguates the two."
            },
            {
                "kind": "conflict",
                "exit_code": 3,
                "retryable": false,
                "description": "Resource already exists or is in an incompatible state"
            },
            {
                "kind": "permission_denied",
                "exit_code": 4,
                "retryable": false,
                "description": "Authentication or authorization failure"
            },
            {
                "kind": "daemon_unreachable",
                "exit_code": 5,
                "retryable": true,
                "description": "Cannot connect to the husker daemon"
            },
            {
                "kind": "confirmation_required",
                "exit_code": 6,
                "retryable": false,
                "description": "Destructive command attempted without confirmation; re-run with --yes"
            }
        ],
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
    let type_str = match a.get_action() {
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count => "boolean",
        clap::ArgAction::Append => "string[]",
        _ => {
            // Heuristic: detect integer args by looking at default values or
            // known numeric arg names.
            if matches!(
                id,
                "limit"
                    | "offset"
                    | "amount_mib"
                    | "cpus"
                    | "memory"
                    | "desired_instances"
                    | "timeout"
                    | "tail"
                    | "host_port"
                    | "guest_port"
                    | "vcpus"
            ) {
                "integer"
            } else {
                "string"
            }
        }
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

        let (mutating, output_field_names) = schema_command_annotations(&full_path);
        let output_fields: Vec<serde_json::Value> = output_field_names
            .iter()
            .map(|f| serde_json::json!({"name": f, "type": "string"}))
            .collect();

        out.push(serde_json::json!({
            "name": full_path,
            "description": cmd.get_about().map(|s| s.to_string()).unwrap_or_default(),
            "mutating": mutating,
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

/// Manual annotations clap cannot derive: whether a command mutates state, and
/// the fields its JSON output emits. Read-only commands are listed explicitly;
/// everything else is treated as mutating. `output_fields` are provided for the
/// core commands and left empty for the rest.
pub(crate) fn schema_command_annotations(path: &str) -> (bool, Vec<&'static str>) {
    let read_only = matches!(
        path,
        "list"
            | "info"
            | "logs"
            | "wait"
            | "version"
            | "schema"
            | "capabilities"
            | "config check"
            | "port-forward list"
            | "host-group list"
            | "host-group get"
            | "service list"
            | "service get"
            | "pool list"
            | "pool get"
            | "snapshot list"
            | "snapshot get"
            | "image list"
            | "image get"
            | "volume list"
            | "volume get"
            | "secret list"
            | "secret get"
            | "secret reveal"
            | "context list"
            | "context show"
            | "profile list"
            | "doctor"
            | "completions"
            | "setup storage"
    );
    let output_fields: Vec<&'static str> = match path {
        "balloon" => vec!["status", "action", "vm", "amount_mib"],
        "run" => vec!["status", "action", "vm", "userdata_queued"],
        "job" => vec!["status", "action", "vm", "exit_code", "stdout", "stderr"],
        "list" => vec![
            "name",
            "state",
            "vcpu_count",
            "mem_size_mib",
            "guest_ip",
            "vmm",
            "idle_timeout_secs",
            "suspend_ttl_secs",
            "auto_resume",
            "suspended_at",
        ],
        "info" => vec![
            "name",
            "state",
            "vcpu_count",
            "mem_size_mib",
            "guest_ip",
            "host_ip",
            "userdata_status",
            "volume",
            "id",
            "vmm",
            "boot_mode",
            "kernel_path",
            "rootfs_path",
            "network",
            "idle_timeout_secs",
            "suspend_ttl_secs",
            "auto_resume",
            "suspended_at",
        ],
        "wait" => vec!["status", "action", "vm", "ready"],
        "fork" => vec!["status", "action", "source", "vm", "guest_ip"],
        "stop" | "pause" | "resume" | "suspend" | "destroy" => vec!["status", "action", "vm"],
        // The exec envelope nests the guest result under `result`
        // (`{status, action, vm, result:{exit_code, stdout, stderr}}`), so declare
        // the actual top-level fields rather than the inner ones.
        "exec" => vec!["status", "action", "vm", "result"],
        "version" => vec!["client_version", "server_version"],
        "service create" | "service scale" => vec!["status", "action", "service", "outcome"],
        "service delete" => vec!["status", "action", "name", "outcome"],
        "service get" => vec!["status", "action", "service", "instances"],
        "service list" => vec!["status", "action", "services"],
        "pool create" | "pool get" => vec!["status", "action", "pool"],
        "pool list" => vec!["status", "action", "pools"],
        "pool checkout" => vec!["status", "action", "vm"],
        "pool delete" => vec!["status", "action", "name"],
        "volume create" | "volume get" => vec!["status", "action", "volume"],
        "volume delete" => vec!["status", "action", "name"],
        "volume list" => vec!["status", "action", "volumes"],
        "context list" => vec!["contexts"],
        "context show" => vec!["current", "api_url"],
        "context add" => vec!["status", "action", "name", "api_url"],
        "context use" | "context remove" => vec!["status", "action", "name"],
        "profile list" => vec!["status", "action", "profiles"],
        "doctor" => vec!["name", "status", "message"],
        "setup storage" => vec!["status", "script_path", "unit_path"],
        _ => vec![],
    };
    (!read_only, output_fields)
}
