use std::ffi::OsString;

use camino::Utf8PathBuf;
use rustferry_codegen::{
    PlatformSelection, ProjectGenerator, ProjectRequest, RuntimeDependency, TemplateKind,
};
use serde::Serialize;

use crate::cli::{NewArgs, PlatformChoice, TemplateChoice};
use crate::commands::check::check_project;
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{find_in_path, run_captured};

#[derive(Debug, Serialize)]
struct NewResult {
    project: String,
    crate_name: String,
    application_identifier: String,
    template: String,
    files: Vec<String>,
    git: String,
    cargo_check: String,
}

#[allow(clippy::too_many_lines)]
pub fn run(arguments: NewArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let parent = match arguments.parent {
        Some(parent) => parent,
        None => {
            Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| CliError::Io {
                action: "read current directory",
                path: Utf8PathBuf::from("."),
                source,
            })?)
            .map_err(CliError::NonUtf8Path)?
        }
    };
    let template = template_kind(arguments.template);
    let request = ProjectRequest {
        name: arguments.name,
        identifier: arguments.id,
        template,
        platforms: platform_selection(arguments.platform),
        runtime_dependency: runtime_dependency()?,
    };
    let generator = ProjectGenerator::new(parent, request);

    if dry_run {
        let plan = generator.plan()?;
        let result = NewResult {
            project: plan.destination.to_string(),
            crate_name: plan.names.crate_name.clone(),
            application_identifier: plan.names.application_identifier.clone(),
            template: template.as_str().to_owned(),
            files: plan.files.iter().map(ToString::to_string).collect(),
            git: if arguments.no_git {
                "skipped"
            } else {
                "planned"
            }
            .to_owned(),
            cargo_check: if arguments.no_check {
                "skipped"
            } else {
                "planned"
            }
            .to_owned(),
        };
        reporter.success(
            "new",
            &result,
            || {
                format!(
                    "Project generation plan\n\nDestination:\n  {}\n\nFiles:\n  {}",
                    plan.destination,
                    plan.files
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n  ")
                )
            },
            &[],
        );
        return Ok(());
    }

    let generated = generator.generate()?;
    let git_status = if arguments.no_git {
        "skipped"
    } else {
        initialize_git(&generated.destination, reporter)?;
        "initialized"
    };
    let check_status = if arguments.no_check {
        "skipped"
    } else {
        check_project(&generated.destination, false, reporter)?;
        "passed"
    };
    let mut files = generated
        .files
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if generated.destination.join("Cargo.lock").is_file() {
        files.push("Cargo.lock".to_owned());
    }
    let result = NewResult {
        project: generated.destination.to_string(),
        crate_name: generated.names.crate_name,
        application_identifier: generated.names.application_identifier,
        template: template.as_str().to_owned(),
        files,
        git: git_status.to_owned(),
        cargo_check: check_status.to_owned(),
    };
    reporter.success(
        "new",
        &result,
        || {
            format!(
                "✓ Created RustFerry application `{}`\n\nProject:\n  {}\n\nEdit first:\n  src/app.rs\n\nRun checks:\n  cd {}\n  cargo ferry check\n\nBuild Android:\n  cargo ferry build android\n\nBuild iOS Simulator:\n  cargo ferry build ios --simulator\n\nAdd a capability:\n  cargo ferry add notifications\n  cargo ferry add widget\n\nDocumentation:\n  cargo ferry docs",
                result.crate_name, result.project, generated.names.directory_name
            )
        },
        &[],
    );
    Ok(())
}

fn initialize_git(root: &camino::Utf8Path, reporter: &Reporter) -> Result<(), CliError> {
    let git = find_in_path("git").ok_or_else(|| CliError::ToolMissing {
        tool: "git".to_owned(),
        searched: vec!["PATH".to_owned()],
        help: "Install Git or generate the project again with `--no-git`.".to_owned(),
    })?;
    let output = run_captured(
        &git,
        &[OsString::from("init"), OsString::from("--quiet")],
        root,
        "project repository initialization",
        reporter,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(CliError::CommandFailed {
            tool: "git".to_owned(),
            stage: "project repository initialization",
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            log: None,
            help: format!("The project remains at {root}. Run `git init` there or use `--no-git`."),
        })
    }
}

fn runtime_dependency() -> Result<RuntimeDependency, CliError> {
    let Some(value) = std::env::var_os("CARGO_FERRY_RUNTIME_PATH") else {
        return Ok(RuntimeDependency::Version(
            env!("CARGO_PKG_VERSION").to_owned(),
        ));
    };
    let path =
        Utf8PathBuf::from_path_buf(value.into()).map_err(|_| CliError::InvalidRuntimePath {
            message: "the value must be valid UTF-8".to_owned(),
        })?;
    if !path.is_absolute() {
        return Err(CliError::InvalidRuntimePath {
            message: "the value must be an absolute path".to_owned(),
        });
    }
    let canonical =
        std::fs::canonicalize(&path).map_err(|source| CliError::InvalidRuntimePath {
            message: format!("the path could not be canonicalized: {source}"),
        })?;
    let canonical =
        Utf8PathBuf::from_path_buf(canonical).map_err(|_| CliError::InvalidRuntimePath {
            message: "the canonical path must be valid UTF-8".to_owned(),
        })?;
    if !canonical.is_dir() {
        return Err(CliError::InvalidRuntimePath {
            message: "the path must name a directory".to_owned(),
        });
    }
    if !canonical.join("Cargo.toml").is_file() {
        return Err(CliError::InvalidRuntimePath {
            message: "the directory must contain Cargo.toml".to_owned(),
        });
    }
    Ok(RuntimeDependency::Path(canonical))
}

const fn template_kind(choice: TemplateChoice) -> TemplateKind {
    match choice {
        TemplateChoice::Starter => TemplateKind::Starter,
        TemplateChoice::Minimal => TemplateKind::Minimal,
        TemplateChoice::Counter => TemplateKind::Counter,
        TemplateChoice::Network => TemplateKind::Network,
        TemplateChoice::Notifications => TemplateKind::Notifications,
        TemplateChoice::Widget => TemplateKind::Widget,
        TemplateChoice::LiveActivity => TemplateKind::LiveActivity,
        TemplateChoice::KitchenSink => TemplateKind::KitchenSink,
    }
}

const fn platform_selection(choice: PlatformChoice) -> PlatformSelection {
    match choice {
        PlatformChoice::Android => PlatformSelection::Android,
        PlatformChoice::Ios => PlatformSelection::Ios,
        PlatformChoice::Both => PlatformSelection::Both,
    }
}
