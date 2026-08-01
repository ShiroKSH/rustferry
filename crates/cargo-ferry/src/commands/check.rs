use std::ffi::OsString;

use camino::Utf8Path;
use serde::Serialize;

use crate::cli::ProjectArgs;
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{find_in_path, find_project_root, run_captured};

#[derive(Debug, Serialize)]
pub(crate) struct CheckResult {
    project: String,
    configuration: String,
    cargo_check: String,
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
    let config_path = root.join("ferry.toml");
    rustferry_core::FerryConfig::load(&config_path)?;
    if dry_run {
        return Ok(CheckResult {
            project: root.to_string(),
            configuration: "valid".to_owned(),
            cargo_check: "planned".to_owned(),
        });
    }

    let cargo = find_in_path("cargo").ok_or_else(|| CliError::ToolMissing {
        tool: "cargo".to_owned(),
        searched: vec!["PATH".to_owned()],
        help: "Install Rust with rustup, then run `cargo ferry check` again.".to_owned(),
    })?;
    let output = run_captured(
        &cargo,
        &[OsString::from("check"), OsString::from("--all-targets")],
        root,
        "Rust project validation",
        reporter,
    )?;
    if !output.status.success() {
        let log = write_check_log(root, &output)?;
        return Err(CliError::CommandFailed {
            tool: "cargo".to_owned(),
            stage: "Rust project validation",
            status: output.status.code(),
            stderr: diagnostic(&output),
            log: Some(log),
            help: format!(
                "Fix the first Rust compiler error, then run `cargo ferry check` in {root}. The project was not removed."
            ),
        });
    }
    Ok(CheckResult {
        project: root.to_string(),
        configuration: "valid".to_owned(),
        cargo_check: "passed".to_owned(),
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
    let mut contents = Vec::new();
    contents.extend_from_slice(b"[stdout]\n");
    contents.extend_from_slice(&output.stdout);
    contents.extend_from_slice(b"\n[stderr]\n");
    contents.extend_from_slice(&output.stderr);
    std::fs::write(&path, contents).map_err(|source| CliError::Io {
        action: "write check log",
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

fn diagnostic(output: &std::process::Output) -> String {
    const LIMIT: usize = 8_000;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let mut result = combined.chars().take(LIMIT).collect::<String>();
    if combined.chars().count() > LIMIT {
        result.push_str("\n… diagnostic truncated; rerun with --verbose");
    }
    result
}
