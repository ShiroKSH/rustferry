use std::ffi::OsString;

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::cli::ProjectArgs;
use crate::error::CliError;
use crate::ide::protocol::{Diagnostic, DiagnosticSeverity, Position, SourceRange, redact_text};
use crate::output::Reporter;
use crate::project::{find_in_path, find_project_root, run_captured};

#[derive(Debug, Serialize)]
pub(crate) struct CheckResult {
    project: String,
    configuration: String,
    cargo_check: String,
}

pub(crate) struct StructuredCheckResult {
    pub(crate) result: CheckResult,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub(crate) struct StructuredCheckError {
    pub(crate) error: Box<CliError>,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl StructuredCheckError {
    fn plain(error: CliError) -> Self {
        Self {
            error: Box::new(error),
            diagnostics: Vec::new(),
        }
    }
}

pub fn run(arguments: &ProjectArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let result = check_project(&root, dry_run, reporter)?;
    reporter.success(
        "check",
        &result,
        || {
            if dry_run {
                format!("Check plan for {root}\n\n  ✓ Validate ferry.toml\n  • Run cargo check")
            } else {
                format!(
                    "✓ RustFerry project is valid\n\nProject:\n  {root}\n\nCargo check:\n  passed"
                )
            }
        },
        &[],
    );
    Ok(())
}

pub(crate) fn check_project(
    root: &Utf8Path,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<CheckResult, CliError> {
    check_project_structured(root, dry_run, reporter)
        .map(|outcome| outcome.result)
        .map_err(|failure| *failure.error)
}

pub(crate) fn check_project_structured(
    root: &Utf8Path,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<StructuredCheckResult, StructuredCheckError> {
    let config_path = root.join("ferry.toml");
    rustferry_core::FerryConfig::load(&config_path)
        .map_err(|error| StructuredCheckError::plain(error.into()))?;
    if dry_run {
        return Ok(StructuredCheckResult {
            result: CheckResult {
                project: root.to_string(),
                configuration: "valid".to_owned(),
                cargo_check: "planned".to_owned(),
            },
            diagnostics: Vec::new(),
        });
    }

    let cargo = find_in_path("cargo")
        .ok_or_else(|| CliError::ToolMissing {
            tool: "cargo".to_owned(),
            searched: vec!["PATH".to_owned()],
            help: "Install Rust with rustup, then run `cargo ferry check` again.".to_owned(),
        })
        .map_err(StructuredCheckError::plain)?;
    let output = run_captured(
        &cargo,
        &[
            OsString::from("check"),
            OsString::from("--all-targets"),
            OsString::from("--message-format=json"),
        ],
        root,
        "Rust project validation",
        reporter,
    )
    .map_err(StructuredCheckError::plain)?;
    let diagnostics = parse_cargo_diagnostics(&output.stdout, root);
    if !output.status.success() {
        let log = write_check_log(root, &output).map_err(StructuredCheckError::plain)?;
        return Err(StructuredCheckError {
            error: Box::new(CliError::CommandFailed {
                tool: "cargo".to_owned(),
                stage: "Rust project validation",
                status: output.status.code(),
                stderr: diagnostic(&output, &diagnostics),
                log: Some(log),
                help: format!(
                    "Fix the first Rust compiler error, then run `cargo ferry check` in {root}. The project was not removed."
                ),
            }),
            diagnostics,
        });
    }
    Ok(StructuredCheckResult {
        result: CheckResult {
            project: root.to_string(),
            configuration: "valid".to_owned(),
            cargo_check: "passed".to_owned(),
        },
        diagnostics,
    })
}

fn write_check_log(
    root: &Utf8Path,
    output: &std::process::Output,
) -> Result<camino::Utf8PathBuf, CliError> {
    let directory = root.join("target/ferry/logs");
    std::fs::create_dir_all(&directory).map_err(|source| CliError::Io {
        action: "create check log directory",
        path: directory.clone(),
        source,
    })?;
    let path = directory.join("cargo-check.log");
    let mut contents = String::from("[cargo diagnostics]\n");
    contents.push_str(&rendered_cargo_output(&output.stdout));
    contents.push_str("\n[stderr]\n");
    contents.push_str(&redact_log_text(&String::from_utf8_lossy(&output.stderr)));
    contents.push('\n');
    std::fs::write(&path, contents).map_err(|source| CliError::Io {
        action: "write check log",
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

fn diagnostic(output: &std::process::Output, diagnostics: &[Diagnostic]) -> String {
    const LIMIT: usize = 8_000;
    if let Some(first) = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .or_else(|| diagnostics.first())
    {
        return format_structured_diagnostic(first);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let mut result = redact_text(&combined.chars().take(LIMIT).collect::<String>());
    if combined.chars().count() > LIMIT {
        result.push_str("\n… diagnostic truncated; rerun with --verbose");
    }
    result
}

fn format_structured_diagnostic(diagnostic: &Diagnostic) -> String {
    format!(
        "{}:{}: {} [{}]",
        diagnostic.file,
        diagnostic.range.start.line.saturating_add(1),
        diagnostic.message,
        diagnostic.code
    )
}

fn rendered_cargo_output(stdout: &[u8]) -> String {
    let mut output = String::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        match serde_json::from_str::<CargoMessage>(line) {
            Ok(message) if message.reason == "compiler-message" => {
                if let Some(rendered) = message.message.and_then(|message| message.rendered) {
                    let rendered = redact_log_text(&rendered);
                    if !rendered.trim().is_empty() {
                        output.push_str(&rendered);
                        if !rendered.ends_with('\n') {
                            output.push('\n');
                        }
                    }
                }
            }
            Err(_) if !line.trim().is_empty() => {
                output.push_str(&redact_text(line));
                output.push('\n');
            }
            Ok(_) | Err(_) => {}
        }
    }
    if output.is_empty() {
        output.push_str("Cargo failed without rendered compiler diagnostics.\n");
    }
    output
}

fn redact_log_text(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let (body, terminator) = line
            .strip_suffix('\n')
            .map_or((line, ""), |body| (body, "\n"));
        output.push_str(&redact_text(body));
        output.push_str(terminator);
    }
    output
}

fn parse_cargo_diagnostics(stdout: &[u8], root: &Utf8Path) -> Vec<Diagnostic> {
    let mut diagnostics = String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .filter(|message| message.reason == "compiler-message")
        .filter_map(|message| message.message)
        .filter_map(|message| rustc_diagnostic(message, root))
        .collect::<Vec<_>>();
    diagnostics.sort_by(|left, right| {
        (
            &left.file,
            left.range.start.line,
            left.range.start.character,
            &left.code,
            &left.message,
        )
            .cmp(&(
                &right.file,
                right.range.start.line,
                right.range.start.character,
                &right.code,
                &right.message,
            ))
    });
    diagnostics.dedup_by(|left, right| {
        left.file == right.file
            && left.range == right.range
            && left.code == right.code
            && left.message == right.message
    });
    diagnostics
}

fn rustc_diagnostic(message: RustcDiagnostic, root: &Utf8Path) -> Option<Diagnostic> {
    let span = message
        .spans
        .iter()
        .find(|span| span.is_primary)
        .or_else(|| message.spans.first())?;
    let reported = Utf8Path::new(&span.file_name);
    let resolved = if reported.is_absolute() {
        reported.to_owned()
    } else {
        root.join(reported)
    };
    let file = resolved.canonicalize_utf8().unwrap_or(resolved);
    let start = Position {
        line: span.line_start.saturating_sub(1),
        character: span.text.first().map_or_else(
            || span.column_start.saturating_sub(1),
            |text| utf16_column(&text.text, text.highlight_start),
        ),
    };
    let mut end = Position {
        line: span.line_end.saturating_sub(1),
        character: span.text.last().map_or_else(
            || span.column_end.saturating_sub(1),
            |text| utf16_column(&text.text, text.highlight_end),
        ),
    };
    if end.line < start.line || (end.line == start.line && end.character < start.character) {
        end = start;
    }
    let raw_code = message.code.map(|code| code.code);
    let code = raw_code.as_deref().map_or_else(
        || format!("rustc.{}", message.level),
        |code| format!("rustc.{code}"),
    );
    let help = message
        .children
        .iter()
        .find(|child| matches!(child.level.as_str(), "help" | "note"))
        .map(|child| redact_text(&child.message));
    let documentation = raw_code
        .as_deref()
        .filter(|code| {
            code.starts_with('E')
                && code[1..]
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
        .map(|code| format!("https://doc.rust-lang.org/error_codes/{code}.html"));
    Some(Diagnostic {
        severity: match message.level.as_str() {
            "error" | "failure-note" | "ice" => DiagnosticSeverity::Error,
            "warning" => DiagnosticSeverity::Warning,
            "help" => DiagnosticSeverity::Hint,
            _ => DiagnosticSeverity::Information,
        },
        code,
        message: redact_text(&message.message),
        file: file.to_string(),
        range: SourceRange { start, end },
        help,
        documentation,
        fixes: Vec::new(),
    })
}

fn utf16_column(line: &str, one_based_column: u32) -> u32 {
    line.chars()
        .take(usize::try_from(one_based_column.saturating_sub(1)).unwrap_or(usize::MAX))
        .map(|character| u32::try_from(character.len_utf16()).unwrap_or(u32::MAX))
        .fold(0_u32, u32::saturating_add)
}

#[derive(Deserialize)]
struct CargoMessage {
    reason: String,
    message: Option<RustcDiagnostic>,
}

#[derive(Deserialize)]
struct RustcDiagnostic {
    message: String,
    code: Option<RustcDiagnosticCode>,
    level: String,
    spans: Vec<RustcSpan>,
    #[serde(default)]
    children: Vec<RustcChild>,
    rendered: Option<String>,
}

#[derive(Deserialize)]
struct RustcDiagnosticCode {
    code: String,
}

#[derive(Deserialize)]
struct RustcChild {
    message: String,
    level: String,
}

#[derive(Deserialize)]
struct RustcSpan {
    file_name: String,
    line_start: u32,
    line_end: u32,
    column_start: u32,
    column_end: u32,
    is_primary: bool,
    #[serde(default)]
    text: Vec<RustcSpanText>,
}

#[derive(Deserialize)]
struct RustcSpanText {
    text: String,
    highlight_start: u32,
    highlight_end: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_json_becomes_absolute_zero_based_utf16_diagnostic() {
        let temporary = tempfile::tempdir().unwrap();
        let root_path = temporary.path().join("workspace with space");
        let root = Utf8Path::from_path(&root_path).unwrap();
        let source = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "message": "mismatched types",
                "code": { "code": "E0308", "explanation": null },
                "level": "error",
                "spans": [{
                    "file_name": "src/main.rs",
                    "line_start": 3,
                    "line_end": 3,
                    "column_start": 3,
                    "column_end": 4,
                    "is_primary": true,
                    "text": [{
                        "text": "😀bad",
                        "highlight_start": 2,
                        "highlight_end": 5
                    }]
                }],
                "children": [{ "message": "use a string", "level": "help" }],
                "rendered": "error[E0308]: mismatched types\n  --> src/main.rs:3:5\n"
            }
        });

        let diagnostics = parse_cargo_diagnostics(format!("{source}\n").as_bytes(), root);

        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.file, root.join("src/main.rs"));
        assert_eq!(diagnostic.code, "rustc.E0308");
        assert_eq!(
            diagnostic.range.start,
            Position {
                line: 2,
                character: 2
            }
        );
        assert_eq!(
            diagnostic.range.end,
            Position {
                line: 2,
                character: 5
            }
        );
        assert_eq!(diagnostic.help.as_deref(), Some("use a string"));
        assert_eq!(
            diagnostic.documentation.as_deref(),
            Some("https://doc.rust-lang.org/error_codes/E0308.html")
        );
    }

    #[test]
    fn malformed_and_non_diagnostic_cargo_lines_are_ignored() {
        let diagnostics = parse_cargo_diagnostics(
            b"not-json\n{\"reason\":\"build-finished\",\"success\":false}\n",
            Utf8Path::new("/workspace"),
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn existing_rustc_path_is_canonicalized() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("src")).unwrap();
        std::fs::write(temporary.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let source = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "message": "warning",
                "code": null,
                "level": "warning",
                "spans": [{
                    "file_name": "src/../src/main.rs",
                    "line_start": 1,
                    "line_end": 1,
                    "column_start": 1,
                    "column_end": 2,
                    "is_primary": true,
                    "text": []
                }],
                "children": []
            }
        });

        let diagnostic = parse_cargo_diagnostics(format!("{source}\n").as_bytes(), root)
            .pop()
            .unwrap();

        assert_eq!(
            diagnostic.file,
            root.join("src/main.rs").canonicalize_utf8().unwrap()
        );
    }

    #[test]
    fn cargo_log_uses_rendered_diagnostics_and_redacts_fallback_text() {
        let json = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "message": "failed",
                "code": { "code": "E0308" },
                "level": "error",
                "spans": [],
                "children": [],
                "rendered": "error[E0308]: mismatched types\n  --> src/main.rs:3:5\n"
            }
        });
        let stdout = format!("{json}\nregistry token: visible-secret\n");

        let rendered = rendered_cargo_output(stdout.as_bytes());

        assert!(rendered.contains("error[E0308]: mismatched types"));
        assert!(rendered.contains("\n--> src/main.rs:3:5\n"));
        assert!(!rendered.contains("{\"reason\""));
        assert!(!rendered.contains("visible-secret"));
    }

    #[test]
    fn human_diagnostic_does_not_mislabel_utf16_offset_as_rustc_column() {
        let diagnostic = Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "rustc.E0308".to_owned(),
            message: "mismatched types".to_owned(),
            file: "/workspace/src/main.rs".to_owned(),
            range: SourceRange {
                start: Position {
                    line: 6,
                    character: 35,
                },
                end: Position {
                    line: 6,
                    character: 36,
                },
            },
            help: None,
            documentation: None,
            fixes: Vec::new(),
        };

        assert_eq!(
            format_structured_diagnostic(&diagnostic),
            "/workspace/src/main.rs:7: mismatched types [rustc.E0308]"
        );
    }
}
