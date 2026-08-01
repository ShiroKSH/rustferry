mod assets;
mod capability;
mod check;
mod clean;
mod completion;
mod config;
mod deployment;
mod devices;
mod doctor;
pub(crate) mod ide;
mod info;
mod new;
pub(crate) mod platform_build;
mod signing;

use crate::cli::Command;
use crate::error::CliError;
use crate::output::Reporter;

pub fn run(
    command: Command,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    match command {
        Command::New(arguments) => new::run(arguments, dry_run, reporter),
        Command::Add(arguments) => capability::run(&arguments, true, dry_run, reporter),
        Command::Remove(arguments) => capability::run(&arguments, false, dry_run, reporter),
        Command::Check(arguments) => check::run(&arguments, dry_run, reporter),
        Command::Doctor(arguments) => doctor::run(&arguments, dry_run, reporter),
        Command::Build(arguments) => platform_build::run(arguments, dry_run, reporter),
        Command::Devices(arguments) => devices::run(arguments, dry_run, json_stream, reporter),
        Command::Install(arguments) => deployment::install(arguments, dry_run, reporter),
        Command::Run(arguments) => deployment::run(arguments, dry_run, reporter),
        Command::Logs(arguments) => deployment::logs(arguments, dry_run, json_stream, reporter),
        Command::Signing(arguments) => signing::run(arguments, reporter),
        Command::Assets(arguments) => assets::run(arguments, dry_run, reporter),
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
        Command::Ide(arguments) => ide::run(arguments, dry_run, reporter),
    }
}
