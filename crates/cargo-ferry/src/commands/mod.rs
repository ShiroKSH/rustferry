mod capability;
mod check;
mod clean;
mod completion;
mod config;
mod doctor;
mod info;
mod new;
mod platform_build;
mod remote;

use crate::cli::Command;
use crate::error::CliError;
use crate::output::Reporter;

pub fn run(command: Command, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match command {
        Command::New(arguments) => new::run(arguments, dry_run, reporter),
        Command::Add(arguments) => capability::run(&arguments, true, dry_run, reporter),
        Command::Remove(arguments) => capability::run(&arguments, false, dry_run, reporter),
        Command::Check(arguments) => check::run(&arguments, dry_run, reporter),
        Command::Doctor(arguments) => doctor::run(&arguments, dry_run, reporter),
        Command::Remote(arguments) => remote::run(arguments, dry_run, reporter),
        Command::Build(arguments) => platform_build::run(arguments, dry_run, reporter),
        Command::Clean(arguments) => clean::run(&arguments, dry_run, reporter),
        Command::Config(arguments) => config::run(arguments, dry_run, reporter),
        Command::Capabilities(arguments) => info::capabilities(&arguments, reporter),
        Command::Examples => {
            info::examples(reporter);
            Ok(())
        }
        Command::Docs(arguments) => info::docs(arguments, reporter),
        Command::Completions(arguments) => {
            completion::run(&arguments, dry_run, reporter);
            Ok(())
        }
    }
}
