use camino::Utf8PathBuf;

use crate::cli::{SigningArgs, SigningCommand};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

pub fn run(arguments: SigningArgs, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        SigningCommand::Teams(arguments) => {
            let current_directory = match arguments.project_dir {
                Some(path) => find_project_root(Some(&path))?,
                None => Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| {
                    CliError::Io {
                        action: "read current directory",
                        path: Utf8PathBuf::from("."),
                        source,
                    }
                })?)
                .map_err(CliError::NonUtf8Path)?,
            };
            let teams = cargo_ferry::deployment::SigningService::new(
                cargo_ferry::deployment::SystemExecutor,
            )
            .teams(&current_directory)?;
            reporter.success(
                "signing teams",
                &teams,
                || {
                    if teams.is_empty() {
                        return "No usable Apple Development identities found.\n\nInstall an Apple Development certificate in Keychain, then rerun `cargo ferry signing teams`.".to_owned();
                    }
                    teams
                        .iter()
                        .map(|team| {
                            format!(
                                "{}\t{}\t{}",
                                team.team_id, team.identity, team.certificate_fingerprint
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                &[],
            );
            Ok(())
        }
    }
}
