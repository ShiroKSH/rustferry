use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;

use crate::cli::{
    AndroidBuildArgs, AndroidDeploymentArgs, AndroidLogArgs, BuildArgs, BuildPlatform,
    DeploymentPlatform, InstallArgs, IosBuildArgs, IosDeploymentArgs, IosLogArgs, LogLevelChoice,
    LogPlatform, LogsArgs, RunArgs,
};
use crate::error::CliError;
use crate::ide::protocol::{EventBody, EventEmitter, protocol_error, redact_text};
use crate::output::Reporter;
use crate::project::find_project_root;

use super::platform_build::{self, BuildOutput};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeploymentTarget {
    Android,
    IosSimulator,
    IosDevice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeploymentAction {
    Install,
    Run {
        terminate_existing: bool,
        collect_logs: bool,
    },
}

impl DeploymentAction {
    const fn label(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Run { .. } => "run",
        }
    }
}

impl DeploymentTarget {
    const fn label(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::IosSimulator => "ios-simulator",
            Self::IosDevice => "ios-device",
        }
    }
}

#[derive(Debug)]
struct DeploymentSpec {
    target: DeploymentTarget,
    requested_device: Option<String>,
    android: cargo_ferry::deployment::AndroidInstallOptions,
    boot_on_demand: bool,
    team: Option<String>,
    allow_provisioning_updates: bool,
    provisioning_profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeploymentPlan {
    platform: &'static str,
    requested_device: String,
    expected_artifact: String,
    action: &'static str,
    provisioning_updates: bool,
}

#[derive(Debug, Serialize)]
struct DeploymentReport {
    platform: &'static str,
    artifact: Utf8PathBuf,
    device_id: String,
    install: cargo_ferry::deployment::InstallOutcome,
    launch: Option<cargo_ferry::deployment::LaunchOutcome>,
    logs: Vec<cargo_ferry::deployment::LogEntry>,
}

#[derive(Debug, Serialize)]
struct LogPlan {
    platform: &'static str,
    requested_device: String,
    application_id: String,
    since_seconds: u64,
    max_entries: usize,
    max_bytes: usize,
}

#[derive(Debug, Serialize)]
struct LogReport {
    platform: &'static str,
    device_id: String,
    application_id: String,
    entries: Vec<cargo_ferry::deployment::LogEntry>,
}

pub fn install(arguments: InstallArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let InstallArgs {
        platform,
        release,
        project_dir,
    } = arguments;
    deploy(
        platform,
        release,
        project_dir.as_deref(),
        DeploymentAction::Install,
        dry_run,
        reporter,
    )
}

pub fn run(arguments: RunArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let RunArgs {
        platform,
        release,
        terminate_existing,
        logs,
        project_dir,
    } = arguments;
    deploy(
        platform,
        release,
        project_dir.as_deref(),
        DeploymentAction::Run {
            terminate_existing,
            collect_logs: logs,
        },
        dry_run,
        reporter,
    )
}

#[allow(clippy::too_many_lines)]
fn deploy(
    platform: DeploymentPlatform,
    release: bool,
    project_dir: Option<&Utf8Path>,
    action: DeploymentAction,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let root = find_project_root(project_dir)?;
    let spec = deployment_spec(platform)?;
    let build = platform_build::execute(build_arguments(&root, &spec, release), dry_run, reporter)?;
    let action_label = action.label();
    if dry_run {
        let plan = DeploymentPlan {
            platform: spec.target.label(),
            requested_device: spec
                .requested_device
                .clone()
                .unwrap_or_else(|| "auto".to_owned()),
            expected_artifact: build.expected_artifact,
            action: action_label,
            provisioning_updates: spec.allow_provisioning_updates,
        };
        reporter.success(
            action_label,
            &plan,
            || {
                format!(
                    "Deployment plan\n\nAction:\n  {}\n\nPlatform:\n  {}\n\nDevice:\n  {}\n\nExpected artifact:\n  {}",
                    plan.action,
                    plan.platform,
                    plan.requested_device,
                    plan.expected_artifact,
                )
            },
            &[],
        );
        return Ok(());
    }

    let artifact = validated_build_output(build, spec.target)?;
    let (device, warnings) = selected_device(
        &root,
        spec.target,
        spec.requested_device.as_deref(),
        true,
        "install application",
    )?;
    let mut install_request =
        cargo_ferry::deployment::InstallRequest::new(device.clone(), artifact.clone());
    install_request.android = spec.android;
    install_request.ios.boot_on_demand = spec.boot_on_demand;
    let install = cargo_ferry::deployment::Installer::new(
        cargo_ferry::deployment::SystemExecutor,
        root.clone(),
    )
    .install(&install_request)?;

    let launch_outcome = if let DeploymentAction::Run {
        terminate_existing, ..
    } = action
    {
        let mut request =
            cargo_ferry::deployment::LaunchRequest::new(device.clone(), artifact.clone());
        request.boot_on_demand = spec.boot_on_demand;
        request.terminate_existing = terminate_existing;
        Some(
            cargo_ferry::deployment::Launcher::new(
                cargo_ferry::deployment::SystemExecutor,
                root.clone(),
            )
            .launch(&request)?,
        )
    } else {
        None
    };

    let logs = if matches!(
        action,
        DeploymentAction::Run {
            collect_logs: true,
            ..
        }
    ) {
        let targets = platform_build::read_cargo_targets(&root)?;
        let request = cargo_ferry::deployment::LogRequest::new(
            device.clone(),
            artifact.application_id().to_owned(),
            targets.binary,
        );
        cargo_ferry::deployment::LogService::new(
            cargo_ferry::deployment::SystemExecutor,
            root.clone(),
        )
        .collect_snapshot(&request)?
    } else {
        Vec::new()
    };
    let warning_messages = warning_messages(&warnings);
    let report = DeploymentReport {
        platform: spec.target.label(),
        artifact: artifact.path().to_owned(),
        device_id: device.id,
        install,
        launch: launch_outcome,
        logs,
    };
    reporter.success(
        action_label,
        &report,
        || {
            let launched = report
                .launch
                .as_ref()
                .map_or("", |_| " and launched");
            format!(
                "✓ Installed{launched} {} application\n\nDevice:\n  {}\n\nArtifact:\n  {}\n\nLog entries:\n  {}",
                report.platform,
                report.device_id,
                report.artifact,
                report.logs.len(),
            )
        },
        &warning_messages,
    );
    Ok(())
}

pub fn logs(
    arguments: LogsArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    if json_stream {
        return stream_logs(arguments, dry_run);
    }
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let (target, requested_device) = log_target(arguments.platform);
    let config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let targets = platform_build::read_cargo_targets(&root)?;
    if dry_run {
        let plan = LogPlan {
            platform: target.label(),
            requested_device: requested_device
                .clone()
                .unwrap_or_else(|| "auto".to_owned()),
            application_id: config.app.identifier,
            since_seconds: arguments.since_seconds,
            max_entries: arguments.max_entries,
            max_bytes: arguments.max_bytes,
        };
        reporter.success(
            "logs",
            &plan,
            || {
                format!(
                    "Log collection plan\n\nPlatform:\n  {}\n\nDevice:\n  {}\n\nApplication:\n  {}\n\nBounds:\n  {} entries / {} bytes / {} seconds",
                    plan.platform,
                    plan.requested_device,
                    plan.application_id,
                    plan.max_entries,
                    plan.max_bytes,
                    plan.since_seconds,
                )
            },
            &[],
        );
        return Ok(());
    }
    let (device, warnings) = selected_device(
        &root,
        target,
        requested_device.as_deref(),
        false,
        "collect application logs",
    )?;
    let mut request = cargo_ferry::deployment::LogRequest::new(
        device.clone(),
        config.app.identifier.clone(),
        targets.binary,
    );
    request.since = Duration::from_secs(arguments.since_seconds);
    request.max_entries = arguments.max_entries;
    request.max_bytes = arguments.max_bytes;
    request.minimum_level = log_level(arguments.level);
    let entries =
        cargo_ferry::deployment::LogService::new(cargo_ferry::deployment::SystemExecutor, root)
            .collect_snapshot(&request)?;
    let report = LogReport {
        platform: target.label(),
        device_id: device.id,
        application_id: config.app.identifier,
        entries,
    };
    reporter.success(
        "logs",
        &report,
        || {
            if report.entries.is_empty() {
                return format!(
                    "No matching log entries for {} on {}.",
                    report.application_id, report.device_id
                );
            }
            report
                .entries
                .iter()
                .map(|entry| {
                    format!(
                        "{}\t{:?}\t{}\t{}",
                        entry.timestamp, entry.level, entry.target, entry.message
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        },
        &warning_messages(&warnings),
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn stream_logs(arguments: LogsArgs, dry_run: bool) -> Result<(), CliError> {
    let emitter = EventEmitter::new(None, None).map_err(|error| CliError::Unsupported {
        message: format!("could not initialize the log-stream operation: {error}"),
        help: "Retry the command; generated operation identifiers are protocol-safe.".to_owned(),
    })?;
    let requested_workspace = arguments
        .project_dir
        .as_ref()
        .map(ToString::to_string)
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|path| Utf8PathBuf::from_path_buf(path).ok())
                .map(|path| path.to_string())
        });
    emit_log_stream(
        &emitter,
        EventBody::OperationStarted {
            command: "logs".to_owned(),
            workspace: requested_workspace,
        },
    )?;
    if dry_run {
        return finish_log_stream_error(
            &emitter,
            None,
            CliError::Unsupported {
                message: "live log streaming cannot run in dry-run mode".to_owned(),
                help: "Omit --dry-run, or omit --json-stream to inspect the finite log plan."
                    .to_owned(),
            },
        );
    }

    let root = match find_project_root(arguments.project_dir.as_deref()) {
        Ok(root) => root,
        Err(error) => return finish_log_stream_error(&emitter, None, error),
    };
    let (target, requested_device) = log_target(arguments.platform);
    let config = match rustferry_core::FerryConfig::load(&root.join("ferry.toml")) {
        Ok(config) => config,
        Err(error) => return finish_log_stream_error(&emitter, None, error),
    };
    let targets = match platform_build::read_cargo_targets(&root) {
        Ok(targets) => targets,
        Err(error) => return finish_log_stream_error(&emitter, None, error),
    };

    emit_log_stream(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Resolving the application-log device".to_owned()),
        },
    )?;
    let (device, warnings) = match selected_device(
        &root,
        target,
        requested_device.as_deref(),
        false,
        "stream application logs",
    ) {
        Ok(selected) => selected,
        Err(error) => {
            return finish_log_stream_error(&emitter, Some("device_discovery"), error);
        }
    };
    for warning in warnings {
        emit_log_stream(
            &emitter,
            EventBody::Warning {
                code: warning.code,
                message: format!("{}: {}", warning.source, warning.message),
                help: None,
            },
        )?;
    }
    emit_log_stream(
        &emitter,
        EventBody::Device {
            device: super::ide::protocol_device(device.clone()),
        },
    )?;
    emit_log_stream(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    let mut request =
        cargo_ferry::deployment::LogRequest::new(device, config.app.identifier, targets.binary);
    request.since = Duration::from_secs(arguments.since_seconds);
    request.max_entries = arguments.max_entries;
    request.max_bytes = arguments.max_bytes;
    request.minimum_level = log_level(arguments.level);
    emit_log_stream(
        &emitter,
        EventBody::PhaseStarted {
            phase: "logs".to_owned(),
            message: Some("Streaming bounded, application-filtered logs".to_owned()),
        },
    )?;
    let service =
        cargo_ferry::deployment::LogService::new(cargo_ferry::deployment::SystemExecutor, root);
    let outcome = match service.stream(&request, |entry| {
        emitter
            .emit(EventBody::Log {
                source_timestamp: (!entry.timestamp.is_empty())
                    .then(|| redact_text(&entry.timestamp)),
                level: streamed_log_level(entry.level).to_owned(),
                target: redact_text(&entry.target),
                message: redact_text(&entry.message),
            })
            .map_err(|source| cargo_ferry::deployment::DeploymentError::Io {
                action: "write streamed CLI log event",
                path: Utf8PathBuf::from("<stdout>"),
                source,
            })
    }) {
        Ok(outcome) if !rustferry_core::process_control::interrupt_requested() => outcome,
        Ok(_) => {
            return finish_log_stream_error(
                &emitter,
                Some("logs"),
                CliError::CommandInterrupted {
                    tool: "platform log stream".to_owned(),
                    stage: "stream application logs",
                },
            );
        }
        Err(error) => {
            return finish_log_stream_error(&emitter, Some("logs"), error);
        }
    };
    emit_log_stream(
        &emitter,
        EventBody::Progress {
            phase: "logs".to_owned(),
            message: "Application-log stream ended after the platform tool exited".to_owned(),
            current: Some(outcome.entries),
            total: Some(outcome.entries),
        },
    )?;
    emit_log_stream(
        &emitter,
        EventBody::PhaseFinished {
            phase: "logs".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    emit_log_stream(
        &emitter,
        EventBody::OperationFinished {
            success: true,
            duration_ms: emitter.elapsed_ms(),
            error: None,
        },
    )
}

fn finish_log_stream_error(
    emitter: &EventEmitter,
    phase: Option<&str>,
    error: impl Into<CliError>,
) -> Result<(), CliError> {
    let error = error.into();
    if let Some(phase) = phase {
        emit_log_stream(
            emitter,
            EventBody::PhaseFinished {
                phase: phase.to_owned(),
                success: false,
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    }
    let cancelled = matches!(
        &error,
        CliError::CommandInterrupted { .. }
            | CliError::Deployment(cargo_ferry::deployment::DeploymentError::Cancelled { .. })
    ) || rustferry_core::process_control::interrupt_requested();
    let exit_code = if cancelled { 130 } else { error.exit_code() };
    if cancelled {
        emit_log_stream(
            emitter,
            EventBody::OperationCancelled {
                reason: "requested".to_owned(),
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    } else {
        emit_log_stream(
            emitter,
            EventBody::OperationFinished {
                success: false,
                duration_ms: emitter.elapsed_ms(),
                error: Some(protocol_error(&error)),
            },
        )?;
    }
    Err(CliError::AlreadyReported { exit_code })
}

fn emit_log_stream(emitter: &EventEmitter, body: EventBody) -> Result<(), CliError> {
    emitter.emit(body).map_err(|source| CliError::Io {
        action: "write log-stream protocol output",
        path: Utf8PathBuf::from("<stdout>"),
        source,
    })
}

const fn streamed_log_level(level: cargo_ferry::deployment::LogLevel) -> &'static str {
    match level {
        cargo_ferry::deployment::LogLevel::Debug => "debug",
        cargo_ferry::deployment::LogLevel::Info => "info",
        cargo_ferry::deployment::LogLevel::Warning => "warning",
        cargo_ferry::deployment::LogLevel::Error => "error",
        cargo_ferry::deployment::LogLevel::Fatal => "fatal",
        cargo_ferry::deployment::LogLevel::Unknown => "unknown",
    }
}

fn deployment_spec(platform: DeploymentPlatform) -> Result<DeploymentSpec, CliError> {
    match platform {
        DeploymentPlatform::Android(arguments) => Ok(android_spec(arguments)),
        DeploymentPlatform::Ios(arguments) => ios_spec(arguments),
    }
}

fn android_spec(arguments: AndroidDeploymentArgs) -> DeploymentSpec {
    DeploymentSpec {
        target: DeploymentTarget::Android,
        requested_device: auto_selector(arguments.device),
        android: cargo_ferry::deployment::AndroidInstallOptions {
            reinstall: arguments.reinstall,
            allow_downgrade: arguments.allow_downgrade,
            grant_permissions: arguments.grant_permissions,
            clear_data: arguments.clear_data,
        },
        boot_on_demand: false,
        team: None,
        allow_provisioning_updates: false,
        provisioning_profile: None,
    }
}

fn ios_spec(arguments: IosDeploymentArgs) -> Result<DeploymentSpec, CliError> {
    let (target, requested_device) = if let Some(selector) = arguments.simulator {
        (
            DeploymentTarget::IosSimulator,
            auto_selector(Some(selector)),
        )
    } else if let Some(selector) = arguments.device {
        (DeploymentTarget::IosDevice, auto_selector(Some(selector)))
    } else {
        return Err(CliError::Unsupported {
            message: "an iOS deployment target was not selected".to_owned(),
            help: "Pass `--simulator [UDID]` or `--device ID`.".to_owned(),
        });
    };
    if target == DeploymentTarget::IosDevice && arguments.team.is_none() {
        return Err(CliError::Unsupported {
            message: "physical iOS deployment requires an explicit Apple Development Team"
                .to_owned(),
            help: "Run `cargo ferry signing teams`, then pass `--device ID --team TEAM_ID`."
                .to_owned(),
        });
    }
    Ok(DeploymentSpec {
        target,
        requested_device,
        android: cargo_ferry::deployment::AndroidInstallOptions::default(),
        boot_on_demand: arguments.boot_on_demand,
        team: arguments.team,
        allow_provisioning_updates: arguments.allow_provisioning_updates,
        provisioning_profile: arguments.provisioning_profile,
    })
}

fn build_arguments(root: &Utf8Path, spec: &DeploymentSpec, release: bool) -> BuildArgs {
    let platform = match spec.target {
        DeploymentTarget::Android => BuildPlatform::Android(AndroidBuildArgs {
            keystore: None,
            key_alias: None,
        }),
        DeploymentTarget::IosSimulator => BuildPlatform::Ios(IosBuildArgs {
            simulator: true,
            device: false,
            team: None,
            allow_provisioning_updates: false,
            provisioning_profile: None,
        }),
        DeploymentTarget::IosDevice => BuildPlatform::Ios(IosBuildArgs {
            simulator: false,
            device: true,
            team: spec.team.clone(),
            allow_provisioning_updates: spec.allow_provisioning_updates,
            provisioning_profile: spec.provisioning_profile.clone(),
        }),
    };
    BuildArgs {
        platform,
        release,
        remote: None,
        config_dir: None,
        unsigned: false,
        artifact: None,
        include_dsym: false,
        project_dir: Some(root.to_owned()),
    }
}

fn validated_build_output(
    output: BuildOutput,
    target: DeploymentTarget,
) -> Result<cargo_ferry::deployment::ValidatedArtifact, CliError> {
    if !output.validated {
        return Err(CliError::Unsupported {
            message: "the build did not complete independent artifact validation".to_owned(),
            help: "Inspect the platform build logs; unvalidated output is never deployed."
                .to_owned(),
        });
    }
    let artifact = output
        .deployment_artifact
        .ok_or_else(|| CliError::Unsupported {
            message: "the validated build returned no typed deployment artifact".to_owned(),
            help:
                "Rebuild the artifact; serialized validation metadata is not deployment authority."
                    .to_owned(),
        })?;
    let expected_kind = match target {
        DeploymentTarget::Android => cargo_ferry::deployment::ArtifactKind::AndroidApk,
        DeploymentTarget::IosSimulator => cargo_ferry::deployment::ArtifactKind::IosSimulatorApp,
        DeploymentTarget::IosDevice => cargo_ferry::deployment::ArtifactKind::IosPhysicalApp,
    };
    if artifact.kind() != expected_kind {
        return Err(CliError::Unsupported {
            message: format!(
                "validated artifact platform mismatch: expected {}, found {}",
                expected_kind.label(),
                artifact.kind().label()
            ),
            help: "Rerun the build for the requested deployment platform.".to_owned(),
        });
    }
    Ok(artifact)
}

fn selected_device(
    root: &Utf8Path,
    target: DeploymentTarget,
    requested: Option<&str>,
    require_install: bool,
    operation: &'static str,
) -> Result<
    (
        cargo_ferry::deployment::Device,
        Vec<cargo_ferry::deployment::DiscoveryWarning>,
    ),
    CliError,
> {
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        root.to_owned(),
    )
    .discover(match target {
        DeploymentTarget::Android => cargo_ferry::deployment::DeviceFilter::Android,
        DeploymentTarget::IosSimulator | DeploymentTarget::IosDevice => {
            cargo_ferry::deployment::DeviceFilter::Ios
        }
    });
    let mut compatible = snapshot
        .devices
        .iter()
        .filter(|device| target_matches(target, device.kind))
        .filter(|device| {
            if require_install {
                device.capabilities.install
            } else {
                device.capabilities.logs
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    compatible.sort_by(|left, right| left.id.cmp(&right.id));
    let selected = if let Some(id) = requested {
        let candidate = snapshot
            .devices
            .iter()
            .find(|device| device.id == id)
            .ok_or_else(
                || cargo_ferry::deployment::DeploymentError::DeviceNotFound { id: id.to_owned() },
            )?;
        if !target_matches(target, candidate.kind) {
            return Err(
                cargo_ferry::deployment::DeploymentError::DeviceKindMismatch {
                    id: id.to_owned(),
                    expected: expected_kind(target),
                    actual: candidate.kind,
                }
                .into(),
            );
        }
        if require_install {
            cargo_ferry::deployment::select_device(
                &snapshot.devices,
                candidate.kind,
                Some(id),
                operation,
            )?
        } else if !candidate.capabilities.logs {
            return Err(
                cargo_ferry::deployment::DeploymentError::DeviceUnavailable {
                    id: id.to_owned(),
                    state: candidate.state,
                    operation,
                    help: "Choose a connected device that advertises application log support."
                        .to_owned(),
                }
                .into(),
            );
        } else {
            candidate.clone()
        }
    } else {
        match compatible.as_slice() {
            [device] => device.clone(),
            [] => {
                return Err(
                    cargo_ferry::deployment::DeploymentError::DeviceUnavailable {
                        id: "<none>".to_owned(),
                        state: cargo_ferry::deployment::DeviceState::Unavailable,
                        operation,
                        help: format!(
                            "Connect or boot one usable {} device, then retry.",
                            target.label()
                        ),
                    }
                    .into(),
                );
            }
            devices => {
                return Err(
                    cargo_ferry::deployment::DeploymentError::DeviceSelectionRequired {
                        device_ids: devices.iter().map(|device| device.id.clone()).collect(),
                    }
                    .into(),
                );
            }
        }
    };
    Ok((selected, snapshot.warnings))
}

fn log_target(platform: LogPlatform) -> (DeploymentTarget, Option<String>) {
    match platform {
        LogPlatform::Android(AndroidLogArgs { device }) => {
            (DeploymentTarget::Android, auto_selector(device))
        }
        LogPlatform::Ios(IosLogArgs {
            simulator: Some(selector),
            ..
        }) => (
            DeploymentTarget::IosSimulator,
            auto_selector(Some(selector)),
        ),
        LogPlatform::Ios(IosLogArgs {
            device: Some(selector),
            ..
        }) => (DeploymentTarget::IosDevice, auto_selector(Some(selector))),
        LogPlatform::Ios(_) => unreachable!("clap requires an iOS log target"),
    }
}

const fn target_matches(
    target: DeploymentTarget,
    kind: cargo_ferry::deployment::DeviceKind,
) -> bool {
    match target {
        DeploymentTarget::Android => matches!(
            kind,
            cargo_ferry::deployment::DeviceKind::AndroidPhysical
                | cargo_ferry::deployment::DeviceKind::AndroidEmulator
        ),
        DeploymentTarget::IosSimulator => {
            matches!(kind, cargo_ferry::deployment::DeviceKind::IosSimulator)
        }
        DeploymentTarget::IosDevice => {
            matches!(kind, cargo_ferry::deployment::DeviceKind::IosPhysical)
        }
    }
}

const fn expected_kind(target: DeploymentTarget) -> cargo_ferry::deployment::DeviceKind {
    match target {
        DeploymentTarget::Android => cargo_ferry::deployment::DeviceKind::AndroidPhysical,
        DeploymentTarget::IosSimulator => cargo_ferry::deployment::DeviceKind::IosSimulator,
        DeploymentTarget::IosDevice => cargo_ferry::deployment::DeviceKind::IosPhysical,
    }
}

fn auto_selector(selector: Option<String>) -> Option<String> {
    selector.filter(|selector| !selector.eq_ignore_ascii_case("auto"))
}

const fn log_level(level: LogLevelChoice) -> cargo_ferry::deployment::LogLevel {
    match level {
        LogLevelChoice::Debug => cargo_ferry::deployment::LogLevel::Debug,
        LogLevelChoice::Info => cargo_ferry::deployment::LogLevel::Info,
        LogLevelChoice::Warning => cargo_ferry::deployment::LogLevel::Warning,
        LogLevelChoice::Error => cargo_ferry::deployment::LogLevel::Error,
        LogLevelChoice::Fatal => cargo_ferry::deployment::LogLevel::Fatal,
    }
}

fn warning_messages(warnings: &[cargo_ferry::deployment::DiscoveryWarning]) -> Vec<String> {
    warnings
        .iter()
        .map(|warning| format!("{}: {}", warning.source, warning.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_validation_metadata_cannot_authorize_deployment() {
        let output = BuildOutput {
            project: "/tmp/example".to_owned(),
            platform: "android",
            profile: "debug",
            artifact: Some("/tmp/example.apk".to_owned()),
            deployment_artifact: None,
            expected_artifact: "/tmp/example.apk".to_owned(),
            validated: true,
            validation: Some(serde_json::json!({
                "artifact_digest": {
                    "sha256": "00",
                    "entries": 1,
                    "bytes": 1
                },
                "package_name": "com.example.forged"
            })),
            plan: None,
            log_directory: None,
            cache_hits: Vec::new(),
            cache_misses: Vec::new(),
            device_required: false,
            dry_run: false,
        };

        let error = validated_build_output(output, DeploymentTarget::Android)
            .expect_err("JSON evidence must not become deployment authority");
        assert!(error.to_string().contains("no typed deployment artifact"));
    }
}
