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
    /// as required by v0.2, while runtime validation also checks the envelope.
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct CommandContract {
    pub(crate) path: &'static str,
    pub(crate) mutating: bool,
    pub(crate) output: OutputContract,
}

impl CommandContract {
    pub(crate) const fn object(
        path: &'static str,
        mutating: bool,
        fields: &'static [FieldContract],
    ) -> Self {
        Self {
            path,
            mutating,
            output: OutputContract::Object(fields),
        }
    }

    pub(crate) const fn list(
        path: &'static str,
        mutating: bool,
        envelope: &'static [FieldContract],
        items_field: &'static str,
        item: &'static [FieldContract],
    ) -> Self {
        Self {
            path,
            mutating,
            output: OutputContract::List {
                envelope,
                items_field,
                item,
            },
        }
    }

    pub(crate) const fn self_describing(path: &'static str, mutating: bool) -> Self {
        Self {
            path,
            mutating,
            output: OutputContract::SelfDescribing,
        }
    }

    pub(crate) const fn unsupported(path: &'static str, mutating: bool) -> Self {
        Self {
            path,
            mutating,
            output: OutputContract::Unsupported,
        }
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
    OutMatchedNothing,
    JobCleanupFailed,
    VmNotRunning,
}

impl CliErrorKind {
    pub(crate) const ALL: [Self; 10] = [
        Self::Error,
        Self::NotFound,
        Self::InvalidUsage,
        Self::Conflict,
        Self::PermissionDenied,
        Self::DaemonUnreachable,
        Self::ConfirmationRequired,
        Self::OutMatchedNothing,
        Self::JobCleanupFailed,
        Self::VmNotRunning,
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
            Self::OutMatchedNothing => "out_matched_nothing",
            Self::JobCleanupFailed => "job_cleanup_failed",
            Self::VmNotRunning => "vm_not_running",
        }
    }

    pub(crate) const fn exit_code(self) -> i32 {
        match self {
            Self::NotFound | Self::InvalidUsage => 2,
            Self::Conflict => 3,
            Self::PermissionDenied => 4,
            Self::DaemonUnreachable => 5,
            Self::ConfirmationRequired => 6,
            Self::Error | Self::OutMatchedNothing | Self::JobCleanupFailed | Self::VmNotRunning => {
                1
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
            Self::InvalidUsage => "Invalid command-line usage",
            Self::Conflict => "Resource exists or is in an incompatible state",
            Self::PermissionDenied => "Authentication, authorization, or policy failure",
            Self::DaemonUnreachable => "Cannot connect to the husker daemon",
            Self::ConfirmationRequired => "Destructive command needs --yes confirmation",
            Self::OutMatchedNothing => "A requested job output pattern matched nothing",
            Self::JobCleanupFailed => "A completed job VM could not be destroyed",
            Self::VmNotRunning => "The requested VM is not running",
        }
    }

    pub(crate) const fn from_exit_code(exit_code: i32) -> Self {
        match exit_code {
            2 => Self::NotFound,
            3 => Self::Conflict,
            4 => Self::PermissionDenied,
            5 => Self::DaemonUnreachable,
            6 => Self::ConfirmationRequired,
            _ => Self::Error,
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }
}

impl fmt::Display for CliErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Keep the CLI's advertised error vocabulary finite. Daemon-specific kinds
/// are useful inside the HTTP API, but the CLI normalizes them to its stable
/// status category unless they are explicitly part of the CLI contract.
pub(crate) fn normalize_error_kind(kind: Option<&str>, exit_code: i32) -> CliErrorKind {
    kind.and_then(CliErrorKind::from_name)
        .unwrap_or_else(|| CliErrorKind::from_exit_code(exit_code))
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
        assert_eq!(
            normalize_error_kind(Some("vm_already_exists"), 3),
            CliErrorKind::Conflict
        );
        assert_eq!(
            normalize_error_kind(Some("vm_not_running"), 1),
            CliErrorKind::VmNotRunning
        );
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
}
