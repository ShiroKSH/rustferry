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

    /// Render a failure in the selected output mode.
    pub fn error(&self, error: &CliError) {
        if self.json {
            let details = error
                .details()
                .into_iter()
                .map(|detail| strip_ansi(&detail))
                .collect::<Vec<_>>();
            print_json(&json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "command": Value::Null,
                "status": "error",
                "error": {
                    "code": error.code(),
                    "message": strip_ansi(&error.to_string()),
                    "help": error.help().map(|help| strip_ansi(&help)),
                    "details": details,
                }
            }));
        } else {
            eprintln!("Error: {error}");
            for detail in error.details() {
                eprintln!("  {detail}");
            }
            if let Some(help) = error.help() {
                eprintln!("\nFix:\n  {help}");
            }
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
    use super::strip_ansi;

    #[test]
    fn removes_terminal_escape_sequences_from_json_fields() {
        assert_eq!(strip_ansi("\u{1b}[31merror\u{1b}[0m"), "error");
    }
}
