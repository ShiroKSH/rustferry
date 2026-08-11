//! `cargo ferry` command-line entry point.

mod cli;
mod commands;
mod error;
mod ide;
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
    let wants_json = arguments
        .iter()
        .any(|argument| argument == "--json" || argument == "--json-stream");
    let wants_ide = arguments.iter().any(|argument| argument == "ide");
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
            if wants_ide {
                let _ = crate::commands::ide::write_argument_error(&error.to_string());
            } else if wants_json {
                Reporter::new(true, false, false).argument_error(&error.to_string());
            } else {
                let _ = error.print();
            }
            return ExitCode::from(2);
        }
    };
    if cli.json_stream
        && !matches!(
            &cli.command,
            crate::cli::Command::Ide(_)
                | crate::cli::Command::Devices(_)
                | crate::cli::Command::Logs(_)
                | crate::cli::Command::Jobs(crate::cli::JobsArgs {
                    command: crate::cli::JobsCommand::Logs(_),
                })
        )
    {
        Reporter::new(true, false, false).argument_error(
            "--json-stream is supported only by `ide` operations, `devices`, `logs`, and `jobs logs`; use --json for this command",
        );
        return ExitCode::from(2);
    }
    let wants_json = cli.json || cli.json_stream;
    let is_json_stream = cli.json_stream;
    let is_ide = matches!(&cli.command, crate::cli::Command::Ide(_));
    let reporter = Reporter::new(cli.json, cli.quiet, cli.verbose);
    if let Err(source) = rustferry_core::process_control::install_interrupt_handler() {
        let error = crate::error::CliError::InterruptHandler { source };
        if is_ide {
            let _ =
                crate::ide::protocol::write_compact(&crate::ide::service::error_response(&error));
        } else {
            reporter.error(&error);
        }
        return ExitCode::from(5);
    }
    let result = commands::run(cli.command, cli.dry_run, cli.json_stream, &reporter);
    if rustferry_core::process_control::interrupt_requested() {
        if wants_json && !is_ide && !is_json_stream {
            reporter.error(&crate::error::CliError::CommandInterrupted {
                tool: "active child process".to_owned(),
                stage: "command execution",
            });
        }
        return ExitCode::from(130);
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.is_already_reported() => ExitCode::from(error.exit_code()),
        Err(error) => {
            reporter.error(&error);
            ExitCode::from(error.exit_code())
        }
    }
}
