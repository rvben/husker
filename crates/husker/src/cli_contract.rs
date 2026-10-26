//! Machine-readable CLI contract and its runtime test surface.
//!
//! Command syntax comes from clap. Semantic policy that clap cannot express
//! lives in the exhaustive registry beside the command definitions in
//! `cli.rs`. This module turns that registry into clispec fields and validates
//! every structured success payload before it is printed.

use std::fmt;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::COMMAND_CONTRACTS;
use crate::schema::exit_code;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsonType {
    String,
    Integer,
    Boolean,
    Object,
    Array,
    NullableString,
    NullableInteger,
    NullableBoolean,
    NullableObject,
}

impl JsonType {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Object => "object",
            Self::Array => "array",
            Self::NullableString => "string|null",
            Self::NullableInteger => "integer|null",
            Self::NullableBoolean => "boolean|null",
            Self::NullableObject => "object|null",
        }
    }

    fn accepts(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            Self::Boolean => value.is_boolean(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::NullableString => value.is_null() || value.is_string(),
            Self::NullableInteger => {
                value.is_null() || value.as_i64().is_some() || value.as_u64().is_some()
            }
            Self::NullableBoolean => value.is_null() || value.is_boolean(),
            Self::NullableObject => value.is_null() || value.is_object(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FieldContract {
    pub(crate) name: &'static str,
    pub(crate) kind: JsonType,
    pub(crate) required: bool,
}

impl FieldContract {
    pub(crate) const fn required(name: &'static str, kind: JsonType) -> Self {
        Self {
            name,
            kind,
            required: true,
        }
    }

    pub(crate) const fn optional(name: &'static str, kind: JsonType) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OutputContract {
    /// One JSON object. Unknown top-level fields are rejected so additions must
    /// update the contract in the same change.
    Object(&'static [FieldContract]),
    /// A JSON envelope containing an array. Clispec describes one array item,
    /// as required by the schema contract, while runtime validation also checks the envelope.
    List {
        envelope: &'static [FieldContract],
        items_field: &'static str,
        item: &'static [FieldContract],
    },
    /// Structured output whose document is itself the contract (`schema`).
    SelfDescribing,
    /// No stable structured JSON result (interactive, streaming, or text-only).
    Unsupported,
}

/// What re-running a command does, declared per command so a consumer that
/// grants trust (auto-approval, automatic retry) reads an explicit claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effects {
    /// Does not modify state a consumer cares about.
    ReadOnly,
    /// May modify state, but repeating it converges to the same state, so a
    /// failed attempt can be retried.
    Idempotent,
    /// Repeating it may cause an additional effect (a second VM, a second
    /// command run, a new secret value), so it must not be retried blindly.
    NonIdempotent,
}

impl Effects {
    /// The clispec `effects` identifier.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Effects::ReadOnly => "read_only",
            Effects::Idempotent => "idempotent",
            Effects::NonIdempotent => "non_idempotent",
        }
    }

    /// The deprecated clispec v0.2 `mutating` marker, which the v0.3 contract
    /// still emits beside `effects`; the spec requires the two to agree.
    pub(crate) const fn mutating(self) -> bool {
        !matches!(self, Effects::ReadOnly)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CommandContract {
    pub(crate) path: &'static str,
    pub(crate) effects: Effects,
    pub(crate) output: OutputContract,
}

impl CommandContract {
    pub(crate) const fn object(
        path: &'static str,
        effects: Effects,
        fields: &'static [FieldContract],
    ) -> Self {
        Self {
            path,
            effects,
            output: OutputContract::Object(fields),
        }
    }

    pub(crate) const fn list(
        path: &'static str,
        effects: Effects,
        envelope: &'static [FieldContract],
        items_field: &'static str,
        item: &'static [FieldContract],
    ) -> Self {
        Self {
            path,
            effects,
            output: OutputContract::List {
                envelope,
                items_field,
                item,
            },
        }
    }

    pub(crate) const fn self_describing(path: &'static str, effects: Effects) -> Self {
        Self {
            path,
            effects,
            output: OutputContract::SelfDescribing,
        }
    }

    pub(crate) const fn unsupported(path: &'static str, effects: Effects) -> Self {
        Self {
            path,
            effects,
            output: OutputContract::Unsupported,
        }
    }

    pub(crate) const fn mutating(self) -> bool {
        self.effects.mutating()
    }

    pub(crate) fn clispec_fields(self) -> &'static [FieldContract] {
        match self.output {
            OutputContract::Object(fields) => fields,
            OutputContract::List { item, .. } => item,
            OutputContract::SelfDescribing | OutputContract::Unsupported => &[],
        }
    }
}

pub(crate) fn command_contract(path: &str) -> Option<&'static CommandContract> {
    COMMAND_CONTRACTS
        .iter()
        .find(|contract| contract.path == path)
}

/// A `--fields` selection named something the command's contract does not
/// declare.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnknownField {
    pub(crate) name: String,
    pub(crate) valid: Vec<&'static str>,
}

impl UnknownField {
    pub(crate) fn message(&self) -> String {
        if self.name.is_empty() {
            "--fields contains an empty field name".to_string()
        } else {
            format!("unknown field `{}` in --fields", self.name)
        }
    }

    pub(crate) fn hint(&self) -> String {
        format!("valid fields: {}", self.valid.join(", "))
    }
}

/// Resolve a comma-separated `--fields` selection against the item fields the
/// command's contract declares, keeping the caller's order. Names are trimmed;
/// an empty name (`name,` or `,name`) is reported rather than silently dropped.
pub(crate) fn select_fields(path: &str, spec: &str) -> Result<Vec<&'static str>, UnknownField> {
    let valid: Vec<&'static str> = command_contract(path)
        .unwrap_or_else(|| panic!("missing CLI contract for command '{path}'"))
        .clispec_fields()
        .iter()
        .map(|field| field.name)
        .collect();
    spec.split(',')
        .map(str::trim)
        .map(|name| {
            valid
                .iter()
                .copied()
                .find(|known| *known == name)
                .ok_or_else(|| UnknownField {
                    name: name.to_string(),
                    valid: valid.clone(),
                })
        })
        .collect()
}

pub(crate) fn structured_output<T: Serialize>(path: &str, value: &T) -> Result<serde_json::Value> {
    let value = serde_json::to_value(value).context("serializing structured CLI output")?;
    validate_output(path, &value)?;
    Ok(value)
}

pub(crate) fn validate_output(path: &str, value: &serde_json::Value) -> Result<()> {
    let contract = command_contract(path)
        .with_context(|| format!("missing CLI contract for command '{path}'"))?;
    match contract.output {
        OutputContract::Object(fields) => validate_object(path, value, fields, true),
        OutputContract::List {
            envelope,
            items_field,
            item,
        } => {
            validate_object(path, value, envelope, true)?;
            let items = value
                .get(items_field)
                .and_then(serde_json::Value::as_array)
                .with_context(|| {
                    format!("structured output for '{path}' needs array field '{items_field}'")
                })?;
            for (index, value) in items.iter().enumerate() {
                validate_object(
                    &format!("{path}.{items_field}[{index}]"),
                    value,
                    item,
                    false,
                )?;
            }
            Ok(())
        }
        OutputContract::SelfDescribing => Ok(()),
        OutputContract::Unsupported => {
            anyhow::bail!("command '{path}' does not define structured JSON output")
        }
    }
}

fn validate_object(
    subject: &str,
    value: &serde_json::Value,
    fields: &[FieldContract],
    reject_unknown: bool,
) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("structured output for '{subject}' must be an object"))?;
    for field in fields {
        match object.get(field.name) {
            Some(value) if field.kind.accepts(value) => {}
            Some(_) => anyhow::bail!(
                "structured output field '{subject}.{}' must be {}, got {}",
                field.name,
                field.kind.name(),
                json_kind(object.get(field.name).expect("field exists"))
            ),
            None if field.required && reject_unknown => anyhow::bail!(
                "structured output for '{subject}' is missing required field '{}'",
                field.name
            ),
            None => {}
        }
    }
    if reject_unknown {
        for name in object.keys() {
            anyhow::ensure!(
                fields.iter().any(|field| field.name == name),
                "structured output for '{subject}' has undeclared field '{name}'"
            );
        }
    }
    Ok(())
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CliErrorKind {
    Error,
    NotFound,
    InvalidUsage,
    Conflict,
    PermissionDenied,
    DaemonUnreachable,
    ConfirmationRequired,
    ConfirmationDeclined,
    OutMatchedNothing,
    JobCleanupFailed,
    VmNotRunning,
    Timeout,
}

impl CliErrorKind {
    pub(crate) const ALL: [Self; 12] = [
        Self::Error,
        Self::NotFound,
        Self::InvalidUsage,
        Self::Conflict,
        Self::PermissionDenied,
        Self::DaemonUnreachable,
        Self::ConfirmationRequired,
        Self::ConfirmationDeclined,
        Self::OutMatchedNothing,
        Self::JobCleanupFailed,
        Self::VmNotRunning,
        Self::Timeout,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::NotFound => "not_found",
            Self::InvalidUsage => "invalid_usage",
            Self::Conflict => "conflict",
            Self::PermissionDenied => "permission_denied",
            Self::DaemonUnreachable => "daemon_unreachable",
            Self::ConfirmationRequired => "confirmation_required",
            Self::ConfirmationDeclined => "confirmation_declined",
            Self::OutMatchedNothing => "out_matched_nothing",
            Self::JobCleanupFailed => "job_cleanup_failed",
            Self::VmNotRunning => "vm_not_running",
            Self::Timeout => "timeout",
        }
    }

    pub(crate) const fn exit_code(self) -> i32 {
        match self {
            Self::NotFound | Self::InvalidUsage => exit_code::NOT_FOUND,
            // A VM in the wrong state for a command is a conflict: the daemon
            // answers 409 for it, so a refusal the CLI makes itself exits alike.
            Self::Conflict | Self::VmNotRunning => exit_code::CONFLICT,
            Self::PermissionDenied => exit_code::DENIED,
            Self::DaemonUnreachable => exit_code::DAEMON_UNREACHABLE,
            // Both confirmation outcomes leave the system unchanged, so a
            // caller testing the exit code alone treats them alike; the kind
            // tells a missing TTY apart from an operator who answered no.
            Self::ConfirmationRequired | Self::ConfirmationDeclined => {
                exit_code::CONFIRMATION_REQUIRED
            }
            Self::Error | Self::OutMatchedNothing | Self::JobCleanupFailed | Self::Timeout => {
                exit_code::GENERAL
            }
        }
    }

    pub(crate) const fn retryable(self) -> bool {
        matches!(self, Self::DaemonUnreachable)
    }

    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Error => "General client or server error",
            Self::NotFound => "Requested resource was not found",
            Self::InvalidUsage => {
                "Invalid command-line usage, or a request argument the daemon rejected"
            }
            Self::Conflict => "Resource exists or is in an incompatible state",
            Self::PermissionDenied => "Authentication, authorization, or policy failure",
            Self::DaemonUnreachable => "Cannot connect to the husker daemon",
            Self::ConfirmationRequired => {
                "A destructive command reached its confirmation gate without a TTY; re-run with --yes"
            }
            Self::ConfirmationDeclined => {
                "The confirmation prompt was answered no; nothing was changed"
            }
            Self::OutMatchedNothing => "A requested job output pattern matched nothing",
            Self::JobCleanupFailed => "A completed job VM could not be destroyed",
            Self::VmNotRunning => "The requested VM is not running",
            Self::Timeout => "The operation did not finish in time",
        }
    }

    /// The CLI kind for the HTTP status of a refused daemon request whose
    /// kind the CLI does not know. A 400 is a request argument the daemon
    /// rejected: the caller's usage is at fault, exactly as with a flag the
    /// parser refuses, so it is reported the same way.
    pub(crate) const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::InvalidUsage,
            404 => Self::NotFound,
            409 => Self::Conflict,
            401 | 403 => Self::PermissionDenied,
            _ => Self::Error,
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The CLI kind for a kind the daemon sent. A daemon kind that names a
    /// CLI kind maps to it. The daemon's operation-specific timeout kinds fold
    /// into `Timeout`, since the CLI reports every "did not finish in time"
    /// outcome under one kind. Any other daemon kind is unknown here and is
    /// classified by status instead.
    pub(crate) fn from_daemon_kind(name: &str) -> Option<Self> {
        match name {
            "exec_timeout" => Some(Self::Timeout),
            other => Self::from_name(other),
        }
    }

    /// Keep the CLI's advertised error vocabulary finite. Daemon-specific
    /// kinds are useful inside the HTTP API, but the CLI files a refusal under
    /// its stable category unless the kind is explicitly part of the CLI
    /// contract: a kind the CLI knows maps to it, any other is classified by
    /// the status the daemon answered with, and a failure that carries
    /// neither is a general error.
    pub(crate) fn from_daemon(kind: Option<&str>, status: Option<u16>) -> Self {
        kind.and_then(Self::from_daemon_kind)
            .unwrap_or_else(|| status.map_or(Self::Error, Self::from_status))
    }
}

impl fmt::Display for CliErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The `status` of a command that ran a guest command and passes its exit
/// code through. It reports the guest command's own result: a nonzero code is
/// `error` without an error envelope, since the tool itself did not fail.
pub(crate) fn guest_command_status(exit_code: i32) -> &'static str {
    if exit_code == 0 { "ok" } else { "error" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_validation_rejects_drift_in_names_and_types() {
        let wrong_type = serde_json::json!({
            "status": "ok",
            "action": "balloon",
            "vm": "x",
            "amount_mib": "128",
        });
        assert!(validate_output("balloon", &wrong_type).is_err());

        let extra_field = serde_json::json!({
            "status": "ok",
            "action": "wait",
            "vm": "x",
            "ready": true,
            "surprise": true,
        });
        assert!(validate_output("wait", &extra_field).is_err());
    }

    #[test]
    fn daemon_error_kinds_are_normalized_to_the_finite_cli_vocabulary() {
        // A daemon kind the CLI does not list is classified by the status.
        assert_eq!(
            CliErrorKind::from_daemon(Some("vm_already_exists"), Some(409)),
            CliErrorKind::Conflict
        );
        assert_eq!(
            CliErrorKind::from_daemon(Some("vm_not_found"), Some(404)),
            CliErrorKind::NotFound
        );
        assert_eq!(
            CliErrorKind::from_daemon(Some("denied"), Some(403)),
            CliErrorKind::PermissionDenied
        );
        assert_eq!(
            CliErrorKind::from_daemon(Some("vmm_error"), Some(500)),
            CliErrorKind::Error
        );
        // A daemon kind that names a CLI kind maps to it whatever the status.
        assert_eq!(
            CliErrorKind::from_daemon(Some("vm_not_running"), Some(500)),
            CliErrorKind::VmNotRunning
        );
        // A refusal that names neither a kind nor a status is a general error.
        assert_eq!(CliErrorKind::from_daemon(None, None), CliErrorKind::Error);
        assert_eq!(
            CliErrorKind::from_daemon(None, Some(404)),
            CliErrorKind::NotFound
        );
    }

    /// The daemon answers 400 for a request argument it rejects, under
    /// `invalid_argument` or a handler-specific kind. Either way the caller's
    /// usage is at fault, so the CLI reports it as it reports a flag the
    /// parser refuses.
    #[test]
    fn a_request_argument_the_daemon_rejected_is_invalid_usage() {
        for kind in [None, Some("invalid_argument"), Some("invalid_mount_spec")] {
            assert_eq!(
                CliErrorKind::from_daemon(kind, Some(400)),
                CliErrorKind::InvalidUsage,
                "{kind:?}"
            );
        }
        assert_eq!(CliErrorKind::from_status(400), CliErrorKind::InvalidUsage);
        assert_eq!(CliErrorKind::InvalidUsage.exit_code(), 2);
    }

    #[test]
    fn a_daemon_exec_timeout_is_reported_as_a_timeout() {
        let timeout = CliErrorKind::from_daemon(Some("exec_timeout"), Some(408));
        assert_eq!(timeout, CliErrorKind::Timeout);
        assert_eq!(timeout.name(), "timeout");
        assert_eq!(timeout.exit_code(), exit_code::GENERAL);
        // A timed-out command may have run to completion in the guest, so a
        // blind retry could repeat its effect.
        assert!(!timeout.retryable());
        // The status alone does not say an operation timed out.
        assert_eq!(CliErrorKind::from_status(408), CliErrorKind::Error);
    }

    #[test]
    fn a_vm_in_the_wrong_state_exits_as_a_conflict() {
        let not_running = CliErrorKind::VmNotRunning;
        assert_eq!(not_running.exit_code(), exit_code::CONFLICT);
        assert_eq!(not_running.exit_code(), CliErrorKind::Conflict.exit_code());
        // The daemon's 409 says the VM's state refused the command; only the
        // kind says that the state was "not running".
        assert_eq!(CliErrorKind::from_status(409), CliErrorKind::Conflict);
    }

    #[test]
    fn confirmation_outcomes_share_an_exit_code_but_keep_distinct_kinds() {
        let required = CliErrorKind::ConfirmationRequired;
        let declined = CliErrorKind::ConfirmationDeclined;
        assert_eq!(required.exit_code(), declined.exit_code());
        assert_ne!(required.name(), declined.name());
        assert_eq!(
            CliErrorKind::from_name("confirmation_declined"),
            Some(declined)
        );
        assert!(!declined.retryable());
    }

    #[test]
    fn documented_json_examples_are_valid_contract_samples() {
        let docs = include_str!("../../../docs/api/cli-output-json.md");
        let examples: Vec<serde_json::Value> = docs
            .split("```json\n")
            .skip(1)
            .map(|section| section.split("\n```").next().unwrap())
            .map(|json| serde_json::from_str(json).expect("documented JSON must parse"))
            .collect();
        assert_eq!(
            examples.len(),
            4,
            "keep the documented examples intentional"
        );

        validate_output("list", &examples[0]).unwrap();
        validate_output("info", &examples[1]).unwrap();
        validate_output("exec", &examples[2]).unwrap();
        assert_eq!(examples[3]["error"]["kind"], "not_found");
        assert!(examples[3]["error"]["message"].is_string());
    }

    #[test]
    fn select_fields_keeps_the_requested_order_and_rejects_unknown_names() {
        assert_eq!(
            select_fields("list", " state ,name").unwrap(),
            vec!["state", "name"]
        );

        let unknown = select_fields("list", "name,nosuchfield").unwrap_err();
        assert_eq!(unknown.name, "nosuchfield");
        assert_eq!(unknown.message(), "unknown field `nosuchfield` in --fields");
        assert!(
            unknown
                .hint()
                .starts_with("valid fields: id, name, state, ")
        );
        assert!(unknown.hint().contains("boot_mode"));

        assert_eq!(
            select_fields("list", "name,").unwrap_err().message(),
            "--fields contains an empty field name"
        );
    }
}
