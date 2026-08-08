use std::ffi::OsString;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_codegen::{
    PlatformSelection, ProjectGenerator, ProjectRequest, RuntimeDependency, TemplateKind,
};
use serde::Serialize;

use crate::cli::{NewArgs, PlatformChoice, RuntimeSourceChoice, TemplateChoice};
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
    let runtime_dependency = runtime_dependency(
        arguments.runtime_source,
        arguments.runtime_version,
        arguments.runtime_path,
    )?;
    let request = ProjectRequest {
        name: arguments.name,
        display_name: arguments.display_name,
        identifier: arguments.id,
        template,
        platforms: platform_selection(arguments.platform),
        runtime_dependency,
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

fn runtime_dependency(
    source: Option<RuntimeSourceChoice>,
    version: Option<String>,
    path: Option<Utf8PathBuf>,
) -> Result<RuntimeDependency, CliError> {
    match source {
        Some(RuntimeSourceChoice::Registry) => {
            if path.is_some() {
                return Err(CliError::InvalidRuntimeDependency {
                    message: "--runtime-path is valid only with `--runtime-source path`".to_owned(),
                });
            }
            let version = version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
            semver::Version::parse(&version).map_err(|source| {
                CliError::InvalidRuntimeDependency {
                    message: format!("registry version `{version}` is not semantic: {source}"),
                }
            })?;
            Ok(RuntimeDependency::Registry(version))
        }
        Some(RuntimeSourceChoice::Workspace) => {
            if version.is_some() || path.is_some() {
                return Err(CliError::InvalidRuntimeDependency {
                    message:
                        "workspace runtime resolution does not accept --runtime-version or --runtime-path"
                            .to_owned(),
                });
            }
            Ok(RuntimeDependency::Workspace)
        }
        Some(RuntimeSourceChoice::Path) => {
            if version.is_some() {
                return Err(CliError::InvalidRuntimeDependency {
                    message: "--runtime-version is valid only with `--runtime-source registry`"
                        .to_owned(),
                });
            }
            let path = path.ok_or_else(|| CliError::InvalidRuntimeDependency {
                message: "--runtime-source path requires --runtime-path".to_owned(),
            })?;
            canonical_runtime_path(&path)
        }
        None => {
            if version.is_some() || path.is_some() {
                return Err(CliError::InvalidRuntimeDependency {
                    message: "runtime version/path options require an explicit --runtime-source"
                        .to_owned(),
                });
            }
            let Some(value) = std::env::var_os("CARGO_FERRY_RUNTIME_PATH") else {
                return Ok(RuntimeDependency::Registry(
                    env!("CARGO_PKG_VERSION").to_owned(),
                ));
            };
            let path = Utf8PathBuf::from_path_buf(value.into()).map_err(|_| {
                CliError::InvalidRuntimePath {
                    message: "the value must be valid UTF-8".to_owned(),
                }
            })?;
            canonical_runtime_path(&path)
        }
    }
}

fn canonical_runtime_path(path: &Utf8Path) -> Result<RuntimeDependency, CliError> {
    if !path.is_absolute() {
        return Err(CliError::InvalidRuntimePath {
            message: "the value must be an absolute path".to_owned(),
        });
    }
    let canonical = std::fs::canonicalize(path).map_err(|source| CliError::InvalidRuntimePath {
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
