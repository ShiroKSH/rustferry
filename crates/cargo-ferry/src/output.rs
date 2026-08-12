use serde::Serialize;
use serde_json::{Value, json};

use crate::error::CliError;

/// Stable CLI JSON schema version.
const OUTPUT_SCHEMA_VERSION: u32 = 1;

/// Human/JSON output boundary. JSON mode never emits terminal styling.
#[derive(Clone, Debug)]
pub struct Reporter {
    json: bool,
    quiet: bool,
    verbose: bool,
}

impl Reporter {
    /// Construct from validated global flags.
    pub const fn new(json: bool, quiet: bool, verbose: bool) -> Self {
        Self {
            json,
            quiet,
            verbose,
        }
    }

    /// Whether JSON output was requested.
    pub const fn is_json(&self) -> bool {
        self.json
    }

    /// Emit a successful result exactly once.
    pub fn success<T: Serialize>(
        &self,
        command: &'static str,
        data: &T,
        human: impl FnOnce() -> String,
        warnings: &[String],
    ) {
        if self.json {
            let data = serde_json::to_value(data)
                .unwrap_or_else(|error| json!({ "serialization_error": error.to_string() }));
            let warnings = warnings
                .iter()
                .map(|warning| strip_ansi(warning))
                .collect::<Vec<_>>();
            print_json(&json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "command": command,
                "status": "ok",
                "data": data,
                "warnings": warnings,
            }));
        } else if !self.quiet {
            println!("{}", human());
            for warning in warnings {
                eprintln!("Warning: {warning}");
            }
        }
    }

    /// Emit verbose progress in human mode only.
    pub fn verbose(&self, message: impl AsRef<str>) {
        if self.verbose && !self.json {
            eprintln!("{}", message.as_ref());
        }
    }

    /// Emit safe long-running progress in human mode without contaminating JSON output.
    pub fn progress(&self, message: impl AsRef<str>) {
        if !self.quiet && !self.json {
            eprintln!("{}", message.as_ref());
        }
    }

    /// Render a failure in the selected output mode.
    pub fn error(&self, error: &CliError) {
        if self.json {
            print_json(&json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "command": Value::Null,
                "status": "error",
                "error": error_value(error),
            }));
        } else {
            eprint!("{}", human_error(error, None));
        }
    }

    /// Emit one failed result that still carries independently established structured evidence.
    pub(crate) fn failure_with_data<T: Serialize>(
        &self,
        command: &'static str,
        data: &T,
        error: &CliError,
        human: impl FnOnce() -> String,
    ) {
        if self.json {
            print_json(&failure_value(command, data, error));
        } else {
            eprint!("{}", human_error(error, Some(&human())));
        }
    }

    /// Render command-line validation failures in the same stable JSON envelope.
    pub fn argument_error(&self, message: &str) {
        if self.json {
            print_json(&json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "command": Value::Null,
                "status": "error",
                "error": {
                    "code": "invalid_arguments",
                    "message": strip_ansi(message),
                    "help": "Run `cargo ferry --help` for valid arguments.",
                    "details": [],
                }
            }));
        } else {
            eprintln!("Error: {message}");
        }
    }
}

fn error_value(error: &CliError) -> Value {
    let details = error
        .details()
        .into_iter()
        .map(|detail| strip_ansi(&detail))
        .collect::<Vec<_>>();
    json!({
        "code": error.code(),
        "message": strip_ansi(&error.to_string()),
        "help": error.help().map(|help| strip_ansi(&help)),
        "details": details,
    })
}

fn failure_value<T: Serialize>(command: &'static str, data: &T, error: &CliError) -> Value {
    let data = serde_json::to_value(data).unwrap_or_else(
        |serialization| json!({ "serialization_error": serialization.to_string() }),
    );
    json!({
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "command": command,
        "status": "error",
        "data": data,
        "error": error_value(error),
    })
}

fn human_error(error: &CliError, data: Option<&str>) -> String {
    let mut output = format!("Error: {error}\n");
    if let Some(data) = data {
        for line in data.lines() {
            output.push_str("  ");
            output.push_str(line);
            output.push('\n');
        }
    }
    for detail in error.details() {
        output.push_str("  ");
        output.push_str(&detail);
        output.push('\n');
    }
    if let Some(help) = error.help() {
        output.push_str("\nFix:\n  ");
        output.push_str(&help);
        output.push('\n');
    }
    output
}

fn print_json(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(encoded) => println!("{encoded}"),
        Err(_) => println!(
            "{{\"schema_version\":{OUTPUT_SCHEMA_VERSION},\"status\":\"error\",\"error\":{{\"code\":\"json_serialization_failed\",\"message\":\"could not serialize command output\"}}}}"
        ),
    }
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            output.push(character);
            continue;
        }
        if characters.next_if_eq(&'[').is_some() {
            for next in characters.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{failure_value, human_error, strip_ansi};
    use crate::error::CliError;

    #[test]
    fn removes_terminal_escape_sequences_from_json_fields() {
        assert_eq!(strip_ansi("\u{1b}[31merror\u{1b}[0m"), "error");
    }

    #[test]
    fn failed_data_envelope_is_exact_and_redacted() {
        let error = evidence_unavailable_error();
        assert_eq!(
            failure_value(
                "artifact-verify",
                &json!({ "outcome": "evidence_unavailable" }),
                &error,
            ),
            json!({
                "schema_version": 1,
                "command": "artifact-verify",
                "status": "error",
                "data": { "outcome": "evidence_unavailable" },
                "error": {
                    "code": "artifact_evidence_unavailable",
                    "message": "strict artifact evidence is unavailable",
                    "help": "Retain the complete verified evidence set and retry verification.",
                    "details": ["artifact=offline-xcarchive"],
                },
            })
        );
    }

    #[test]
    fn failed_data_human_output_is_a_diagnostic_independent_of_quiet_mode() {
        let rendered = human_error(
            &evidence_unavailable_error(),
            Some("integrity verified; product evidence unavailable"),
        );
        assert_eq!(
            rendered,
            concat!(
                "Error: strict artifact evidence is unavailable\n",
                "  integrity verified; product evidence unavailable\n",
                "  artifact=offline-xcarchive\n",
                "\nFix:\n",
                "  Retain the complete verified evidence set and retry verification.\n",
            )
        );
    }

    fn evidence_unavailable_error() -> CliError {
        CliError::JobsLifecycle {
            code: "artifact_evidence_unavailable",
            message: "strict artifact evidence is unavailable".to_owned(),
            help: "Retain the complete verified evidence set and retry verification.".to_owned(),
            details: vec!["artifact=offline-xcarchive".to_owned()],
        }
    }
}
