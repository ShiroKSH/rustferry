//! `cargo ferry` command-line entry point.

mod cli;
mod commands;
mod error;
mod output;
mod project;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, error::ErrorKind};

use crate::cli::Cli;
use crate::output::Reporter;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().collect::<Vec<OsString>>();
    if arguments.get(1).is_some_and(|value| value == "ferry") {
        arguments.remove(1);
    }
    let wants_json = arguments.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            if wants_json {
                Reporter::new(true, false, false).argument_error(&error.to_string());
            } else {
                let _ = error.print();
            }
            return ExitCode::from(2);
        }
    };
    let wants_json = cli.json;
    let reporter = Reporter::new(cli.json, cli.quiet, cli.verbose);
    if let Err(source) = rustferry_core::process_control::install_interrupt_handler() {
        reporter.error(&crate::error::CliError::InterruptHandler { source });
        return ExitCode::from(5);
    }
    let result = commands::run(cli.command, cli.dry_run, &reporter);
    if rustferry_core::process_control::interrupt_requested() {
        if wants_json {
            reporter.error(&crate::error::CliError::CommandInterrupted {
                tool: "active child process".to_owned(),
                stage: "command execution",
            });
        }
        return ExitCode::from(130);
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            reporter.error(&error);
            ExitCode::from(error.exit_code())
        }
    }
}
