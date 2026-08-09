//! Machine-only IDE command handlers.

use std::collections::BTreeMap;
use std::io::Read as _;

use crate::cli::{
    AndroidBuildArgs, BuildArgs, BuildPlatform, DoctorArgs, IdeArgs, IdeBuildArgs, IdeCheckArgs,
    IdeCommand, IdeDeploymentArgs, IdeDevicePlatform, IdeDevicesArgs, IdePlatform, IdeProfile,
    IosBuildArgs,
};
use crate::error::CliError;
use crate::ide::protocol::{
    Artifact, Device, DeviceCapabilities, DeviceDiscoveryWarning, DeviceKind, DevicePlatform,
    DeviceSnapshotResponse, DeviceState, DevicectlCapabilities, Diagnostic, DiagnosticSeverity,
    DoctorResponse, EventBody, EventEmitter, PROTOCOL_VERSION, Position, ProtocolError,
    ProtocolErrorResponse, SourceRange, protocol_error, redact_text, schema_value, write_compact,
};
use crate::ide::service;
use crate::output::Reporter;
use crate::project::find_project_root;

pub fn run(arguments: IdeArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        IdeCommand::Handshake => unary(Ok(service::handshake())),
        IdeCommand::Project(arguments) => unary(service::project(&arguments.workspace)),
        IdeCommand::Validate(arguments) => unary(if arguments.manifest_stdin {
            read_manifest_stdin()
                .and_then(|source| service::validate_source(&arguments.workspace, &source))
        } else {
            service::validate(&arguments.workspace)
        }),
        IdeCommand::Doctor(arguments) => {
            let doctor = crate::commands::doctor::inspect(
                &DoctorArgs {
                    all: arguments.all,
                    fix: false,
                },
                dry_run,
                arguments.workspace.as_deref(),
            )
            .and_then(|report| {
                serde_json::to_value(report)
                    .map(|report| DoctorResponse {
                        protocol_version: PROTOCOL_VERSION,
                        report,
                    })
                    .map_err(|source| CliError::Io {
                        action: "serialize IDE doctor response",
                        path: camino::Utf8PathBuf::from("<stdout>"),
                        source: std::io::Error::other(source),
                    })
            });
            unary(doctor)
        }
        IdeCommand::Devices(arguments) if arguments.watch => watch_devices(arguments),
        IdeCommand::Devices(arguments) => unary(discover_devices(arguments.platform)),
        IdeCommand::SigningTeams(arguments) => unary(service::signing_teams(&arguments.workspace)),
        IdeCommand::Check(arguments) => check(arguments, dry_run, reporter),
        IdeCommand::Build(arguments) => build(arguments, dry_run, reporter),
        IdeCommand::Install(arguments) => install(&arguments, dry_run, reporter),
        IdeCommand::Run(arguments) => run_application(&arguments, dry_run, reporter),
        IdeCommand::Logs(arguments) => logs(&arguments, dry_run),
        IdeCommand::Schema => {
            let schema = schema_value().map_err(|source| CliError::Io {
                action: "generate IDE protocol schema",
                path: camino::Utf8PathBuf::from("schemas/ide-protocol-v1.schema.json"),
                source: std::io::Error::other(source),
            });
            unary(schema)
        }
    }
}

const IDE_MANIFEST_STDIN_LIMIT: usize = 1024 * 1024;

fn read_manifest_stdin() -> Result<String, CliError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((IDE_MANIFEST_STDIN_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read IDE manifest input",
            path: camino::Utf8PathBuf::from("<stdin>"),
            source,
        })?;
    if bytes.len() > IDE_MANIFEST_STDIN_LIMIT {
        return Err(CliError::IdeManifestInputTooLarge {
            limit_bytes: IDE_MANIFEST_STDIN_LIMIT,
        });
    }
    String::from_utf8(bytes).map_err(|_| CliError::IdeManifestInputInvalidUtf8)
}

fn discover_devices(platform: IdeDevicePlatform) -> Result<DeviceSnapshotResponse, CliError> {
    let current_directory = current_directory()?;
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        current_directory,
    )
    .discover(device_filter(platform));
    Ok(snapshot_response(snapshot))
}

fn watch_devices(arguments: IdeDevicesArgs) -> Result<(), CliError> {
    let emitter = match EventEmitter::new(arguments.operation_id, arguments.parent_operation_id) {
        Ok(emitter) => emitter,
        Err(error) => {
            write_compact(&ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            })
            .map_err(stdout_error)?;
            return Err(CliError::AlreadyReported { exit_code: 2 });
        }
    };
    let current_directory = current_directory()?;
    let service = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        current_directory,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "devices.watch".to_owned(),
            workspace: None,
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Discovering connected devices".to_owned()),
        },
    )?;
    let filter = device_filter(arguments.platform);
    let mut previous = service.discover(filter);
    emit_snapshot(&emitter, &previous)?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    let interval = std::time::Duration::from_millis(arguments.interval_ms.clamp(500, 60_000));
    loop {
        if sleep_until_refresh(interval) {
            emit(
                &emitter,
                EventBody::OperationCancelled {
                    reason: "requested".to_owned(),
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            return Err(CliError::AlreadyReported { exit_code: 130 });
        }
        let current = service.discover(filter);
        for delta in current.changes_since(&previous) {
            match delta.kind {
                cargo_ferry::deployment::DeviceDeltaKind::Added
                | cargo_ferry::deployment::DeviceDeltaKind::Changed => emit(
                    &emitter,
                    EventBody::Device {
                        device: protocol_device(delta.device),
                    },
                )?,
                cargo_ferry::deployment::DeviceDeltaKind::Removed => emit(
                    &emitter,
                    EventBody::DeviceRemoved {
                        device_id: delta.device.id,
                    },
                )?,
            }
        }
        if current.warnings != previous.warnings {
            emit_warnings(&emitter, &current.warnings)?;
        }
        previous = current;
    }
}

fn emit_snapshot(
    emitter: &EventEmitter,
    snapshot: &cargo_ferry::deployment::DeviceSnapshot,
) -> Result<(), CliError> {
    for device in snapshot.devices.iter().cloned() {
        emit(
            emitter,
            EventBody::Device {
                device: protocol_device(device),
            },
        )?;
    }
    emit_warnings(emitter, &snapshot.warnings)
}

fn emit_warnings(
    emitter: &EventEmitter,
    warnings: &[cargo_ferry::deployment::DiscoveryWarning],
) -> Result<(), CliError> {
    for warning in warnings {
        emit(
            emitter,
            EventBody::Warning {
                code: warning.code.clone(),
                message: format!("{}: {}", warning.source, warning.message),
                help: None,
            },
        )?;
    }
    Ok(())
}

fn sleep_until_refresh(interval: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < interval {
        if rustferry_core::process_control::interrupt_requested() {
            return true;
        }
        std::thread::sleep(
            interval
                .saturating_sub(started.elapsed())
                .min(std::time::Duration::from_millis(100)),
        );
    }
    rustferry_core::process_control::interrupt_requested()
}

const fn device_filter(platform: IdeDevicePlatform) -> cargo_ferry::deployment::DeviceFilter {
    match platform {
        IdeDevicePlatform::All => cargo_ferry::deployment::DeviceFilter::All,
        IdeDevicePlatform::Android => cargo_ferry::deployment::DeviceFilter::Android,
        IdeDevicePlatform::Ios => cargo_ferry::deployment::DeviceFilter::Ios,
    }
}

fn snapshot_response(snapshot: cargo_ferry::deployment::DeviceSnapshot) -> DeviceSnapshotResponse {
    DeviceSnapshotResponse {
        protocol_version: PROTOCOL_VERSION,
        devices: snapshot.devices.into_iter().map(protocol_device).collect(),
        warnings: snapshot
            .warnings
            .into_iter()
            .map(|warning| DeviceDiscoveryWarning {
                code: warning.code,
                source: warning.source,
                message: warning.message,
            })
            .collect(),
        devicectl: DevicectlCapabilities {
            available: snapshot.devicectl.available,
            json_output: snapshot.devicectl.json_output,
            install: snapshot.devicectl.install,
            launch: snapshot.devicectl.launch,
            logs: snapshot.devicectl.logs,
        },
    }
}

pub(crate) fn protocol_device(device: cargo_ferry::deployment::Device) -> Device {
    Device {
        id: device.id,
        name: device.name,
        platform: match device.platform {
            cargo_ferry::deployment::DevicePlatform::Android => DevicePlatform::Android,
            cargo_ferry::deployment::DevicePlatform::Ios => DevicePlatform::Ios,
        },
        kind: match device.kind {
            cargo_ferry::deployment::DeviceKind::AndroidPhysical => DeviceKind::AndroidPhysical,
            cargo_ferry::deployment::DeviceKind::AndroidEmulator => DeviceKind::AndroidEmulator,
            cargo_ferry::deployment::DeviceKind::IosSimulator => DeviceKind::IosSimulator,
            cargo_ferry::deployment::DeviceKind::IosPhysical => DeviceKind::IosPhysical,
        },
        state: match device.state {
            cargo_ferry::deployment::DeviceState::Online => DeviceState::Online,
            cargo_ferry::deployment::DeviceState::Booted => DeviceState::Booted,
            cargo_ferry::deployment::DeviceState::Shutdown => DeviceState::Shutdown,
            cargo_ferry::deployment::DeviceState::Offline => DeviceState::Offline,
            cargo_ferry::deployment::DeviceState::Unauthorized => DeviceState::Unauthorized,
            cargo_ferry::deployment::DeviceState::Unavailable => DeviceState::Unavailable,
            cargo_ferry::deployment::DeviceState::Disconnected => DeviceState::Disconnected,
            cargo_ferry::deployment::DeviceState::Unknown => DeviceState::Unknown,
        },
        os_version: device.os_version,
        architecture: device.architecture,
        transport: device.transport,
        paired: device.paired,
        trusted: device.trusted,
        capabilities: DeviceCapabilities {
            build: device.capabilities.build,
            install: device.capabilities.install,
            launch: device.capabilities.launch,
            logs: device.capabilities.logs,
        },
        details: device.details,
    }
}

fn current_directory() -> Result<camino::Utf8PathBuf, CliError> {
    camino::Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| CliError::Io {
        action: "read current directory for device discovery",
        path: camino::Utf8PathBuf::from("."),
        source,
    })?)
    .map_err(CliError::NonUtf8Path)
}

/// Write a bootstrap argument error before Clap can construct an IDE command.
pub fn write_argument_error(message: &str) -> std::io::Result<()> {
    write_compact(&ProtocolErrorResponse {
        protocol_version: PROTOCOL_VERSION,
        error: ProtocolError {
            code: "invalid_arguments".to_owned(),
            message: crate::ide::protocol::redact_text(message),
            help: Some("Run `cargo ferry ide --help` for valid arguments.".to_owned()),
            details: Vec::new(),
        },
    })
}

fn unary<T: serde::Serialize>(result: Result<T, CliError>) -> Result<(), CliError> {
    match result {
        Ok(value) => write_compact(&value).map_err(stdout_error),
        Err(error) => {
            let exit_code = error.exit_code();
            write_compact(&service::error_response(&error)).map_err(stdout_error)?;
            Err(CliError::AlreadyReported { exit_code })
        }
    }
}

fn check(arguments: IdeCheckArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let emitter = stream_emitter(arguments.operation_id, arguments.parent_operation_id)?;
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "check".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "rust_check".to_owned(),
            message: Some(
                if dry_run {
                    "Planning Rust source validation"
                } else {
                    "Checking Rust sources and collecting diagnostics"
                }
                .to_owned(),
            ),
        },
    )?;
    if !dry_run {
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: "cargo".to_owned(),
                arguments: vec![
                    "check".to_owned(),
                    "--all-targets".to_owned(),
                    "--message-format=json".to_owned(),
                ],
            },
        )?;
    }
    match crate::commands::check::check_project_structured(&root, dry_run, reporter) {
        Ok(outcome) => {
            for diagnostic in outcome.diagnostics {
                emit(&emitter, EventBody::Diagnostic { diagnostic })?;
            }
            emit(
                &emitter,
                EventBody::PhaseFinished {
                    phase: "rust_check".to_owned(),
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            emit(
                &emitter,
                EventBody::OperationFinished {
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                    error: None,
                },
            )?;
            Ok(())
        }
        Err(failure) => {
            let has_structured_diagnostics = !failure.diagnostics.is_empty();
            for diagnostic in failure.diagnostics {
                emit(&emitter, EventBody::Diagnostic { diagnostic })?;
            }
            let failure = (*failure.error).into();
            if has_structured_diagnostics {
                finish_failure_after_diagnostics(&emitter, Some("rust_check"), failure)
            } else {
                finish_failure(
                    &emitter,
                    root.join("ferry.toml").as_str(),
                    Some("rust_check"),
                    failure,
                )
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn build(arguments: IdeBuildArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let emitter = match EventEmitter::new(arguments.operation_id, arguments.parent_operation_id) {
        Ok(emitter) => emitter,
        Err(error) => {
            let response = ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            };
            write_compact(&response).map_err(stdout_error)?;
            return Err(CliError::AlreadyReported { exit_code: 2 });
        }
    };
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "build".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "build".to_owned(),
            message: Some("Building and validating mobile artifact".to_owned()),
        },
    )?;
    if !dry_run {
        emit(
            &emitter,
            EventBody::PhaseStarted {
                phase: "rust_check".to_owned(),
                message: Some("Checking Rust sources and collecting diagnostics".to_owned()),
            },
        )?;
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: "cargo".to_owned(),
                arguments: vec![
                    "check".to_owned(),
                    "--all-targets".to_owned(),
                    "--message-format=json".to_owned(),
                ],
            },
        )?;
        match crate::commands::check::check_project_structured(&root, false, reporter) {
            Ok(outcome) => {
                for diagnostic in outcome.diagnostics {
                    emit(&emitter, EventBody::Diagnostic { diagnostic })?;
                }
                emit(
                    &emitter,
                    EventBody::PhaseFinished {
                        phase: "rust_check".to_owned(),
                        success: true,
                        duration_ms: emitter.elapsed_ms(),
                    },
                )?;
            }
            Err(failure) => {
                let has_structured_diagnostics = !failure.diagnostics.is_empty();
                for diagnostic in failure.diagnostics {
                    emit(&emitter, EventBody::Diagnostic { diagnostic })?;
                }
                emit(
                    &emitter,
                    EventBody::PhaseFinished {
                        phase: "rust_check".to_owned(),
                        success: false,
                        duration_ms: emitter.elapsed_ms(),
                    },
                )?;
                let failure = (*failure.error).into();
                return if has_structured_diagnostics {
                    finish_failure_after_diagnostics(&emitter, Some("build"), failure)
                } else {
                    finish_failure(
                        &emitter,
                        root.join("ferry.toml").as_str(),
                        Some("build"),
                        failure,
                    )
                };
            }
        }
    }
    emit(
        &emitter,
        EventBody::Progress {
            phase: "build".to_owned(),
            message: "Preparing platform build".to_owned(),
            current: Some(0),
            total: Some(1),
        },
    )?;
    let (platform, build_platform) = match arguments.platform {
        IdePlatform::Android => (
            "android",
            BuildPlatform::Android(AndroidBuildArgs {
                keystore: None,
                key_alias: None,
            }),
        ),
        IdePlatform::IosSimulator => (
            "ios-simulator",
            BuildPlatform::Ios(IosBuildArgs {
                simulator: true,
                device: false,
                team: None,
                allow_provisioning_updates: false,
                provisioning_profile: None,
            }),
        ),
        IdePlatform::IosDevice => {
            let Some(team) = arguments.team.clone() else {
                return finish_build_error(
                    &emitter,
                    &root,
                    CliError::Unsupported {
                        message: "physical iOS IDE builds require an explicit Apple Development Team".to_owned(),
                        help: "Run `cargo ferry ide signing-teams --workspace PATH --json`, then pass `--team TEAM_ID`.".to_owned(),
                    },
                );
            };
            (
                "ios-device",
                BuildPlatform::Ios(IosBuildArgs {
                    simulator: false,
                    device: true,
                    team: Some(team),
                    allow_provisioning_updates: arguments.allow_provisioning_updates,
                    provisioning_profile: arguments.provisioning_profile.clone(),
                }),
            )
        }
    };
    let profile = match arguments.profile {
        IdeProfile::Debug => "debug",
        IdeProfile::Release => "release",
    };
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: "cargo-ferry".to_owned(),
            arguments: vec![
                "build".to_owned(),
                platform.to_owned(),
                format!("--profile={profile}"),
                "--project-dir".to_owned(),
                root.to_string(),
            ],
        },
    )?;
    let output = crate::commands::platform_build::execute(
        BuildArgs {
            platform: build_platform,
            release: matches!(arguments.profile, IdeProfile::Release),
            remote: None,
            config_dir: None,
            unsigned: false,
            artifact: None,
            include_dsym: false,
            project_dir: Some(root.clone()),
        },
        dry_run,
        reporter,
    );
    match output {
        Ok(output) => {
            emit(
                &emitter,
                EventBody::Progress {
                    phase: "build".to_owned(),
                    message: if dry_run {
                        "Build plan completed"
                    } else {
                        "Artifact validation completed"
                    }
                    .to_owned(),
                    current: Some(1),
                    total: Some(1),
                },
            )?;
            if let Some(path) = output.artifact {
                let config = match rustferry_core::FerryConfig::load(&root.join("ferry.toml")) {
                    Ok(config) => config,
                    Err(error) => return finish_build_error(&emitter, &root, error.into()),
                };
                let architectures = artifact_architectures(&config, arguments.platform);
                let mut validation = BTreeMap::new();
                validation.insert(
                    "artifact".to_owned(),
                    if output.validated {
                        "verified"
                    } else {
                        "unverified"
                    }
                    .to_owned(),
                );
                emit(
                    &emitter,
                    EventBody::Artifact {
                        artifact: Artifact {
                            platform: output.platform.to_owned(),
                            kind: if matches!(arguments.platform, IdePlatform::Android) {
                                "apk"
                            } else {
                                "app"
                            }
                            .to_owned(),
                            path,
                            package_identifier: config.app.identifier,
                            architectures,
                            profile: output.profile.to_owned(),
                            validation,
                        },
                    },
                )?;
            }
            emit(
                &emitter,
                EventBody::PhaseFinished {
                    phase: "build".to_owned(),
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            emit(
                &emitter,
                EventBody::OperationFinished {
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                    error: None,
                },
            )?;
            Ok(())
        }
        Err(_) if rustferry_core::process_control::interrupt_requested() => {
            emit(
                &emitter,
                EventBody::OperationCancelled {
                    reason: "requested".to_owned(),
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            Err(CliError::AlreadyReported { exit_code: 130 })
        }
        Err(error) => finish_build_error(&emitter, &root, error),
    }
}

fn install(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    deploy_application(arguments, dry_run, reporter, false)
}

fn run_application(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    deploy_application(arguments, dry_run, reporter, true)
}

#[allow(clippy::too_many_lines)]
fn deploy_application(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
    launch: bool,
) -> Result<(), CliError> {
    let emitter = stream_emitter(
        arguments.operation_id.clone(),
        arguments.parent_operation_id.clone(),
    )?;
    let command = if launch { "run" } else { "install" };
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: command.to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    let diagnostic_file = root.join("ferry.toml").to_string();
    if dry_run {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "dry_run_unsupported",
                "IDE deployment operations do not report simulated success",
                "Run `cargo ferry ide build` for a non-mutating build plan, or omit `--dry-run` to deploy.",
            ),
        );
    }
    if arguments.artifact.is_some() {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "artifact_validation_metadata_required",
                "an explicit artifact path has no persisted independent validation metadata",
                "Omit `--artifact` so cargo-ferry builds, validates, and structurally rechecks the artifact before deployment.",
            ),
        );
    }

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "build".to_owned(),
            message: Some("Building and validating deployment artifact".to_owned()),
        },
    )?;
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: "cargo-ferry".to_owned(),
            arguments: vec![
                "build".to_owned(),
                platform_label(arguments.platform).to_owned(),
                "--profile=debug".to_owned(),
                "--project-dir".to_owned(),
                root.to_string(),
            ],
        },
    )?;
    let built = match build_deployment_artifact(&root, arguments, reporter) {
        Ok(built) => built,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("build"), error);
        }
    };
    emit(
        &emitter,
        EventBody::Artifact {
            artifact: built.protocol.clone(),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "build".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Resolving the explicit deployment device".to_owned()),
        },
    )?;
    let selected = match selected_device(
        &root,
        arguments.platform,
        &arguments.device,
        "install application",
        true,
    ) {
        Ok(selected) => selected,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("device_discovery"), error);
        }
    };
    emit_warnings(&emitter, &selected.warnings)?;
    emit(
        &emitter,
        EventBody::Device {
            device: protocol_device(selected.device.clone()),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "install".to_owned(),
            message: Some("Installing validated artifact".to_owned()),
        },
    )?;
    let (tool, command_arguments) = install_command(
        arguments.platform,
        &selected.device.id,
        built.deployment.path(),
    );
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: tool.to_owned(),
            arguments: command_arguments,
        },
    )?;
    let install_request = cargo_ferry::deployment::InstallRequest::new(
        selected.device.clone(),
        built.deployment.clone(),
    );
    let installer = cargo_ferry::deployment::Installer::new(
        cargo_ferry::deployment::SystemExecutor,
        root.clone(),
    );
    if let Err(error) = installer.install(&install_request) {
        return finish_failure(&emitter, &diagnostic_file, Some("install"), error.into());
    }
    emit(
        &emitter,
        EventBody::Progress {
            phase: "install".to_owned(),
            message: "Application installation confirmed".to_owned(),
            current: Some(1),
            total: Some(1),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "install".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    if launch {
        emit(
            &emitter,
            EventBody::PhaseStarted {
                phase: "launch".to_owned(),
                message: Some("Launching installed application".to_owned()),
            },
        )?;
        let (tool, command_arguments) =
            launch_command(arguments.platform, &selected.device.id, &built.deployment);
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: tool.to_owned(),
                arguments: command_arguments,
            },
        )?;
        let launch_request =
            cargo_ferry::deployment::LaunchRequest::new(selected.device, built.deployment.clone());
        let launcher = cargo_ferry::deployment::Launcher::new(
            cargo_ferry::deployment::SystemExecutor,
            root.clone(),
        );
        let outcome = match launcher.launch(&launch_request) {
            Ok(outcome) => outcome,
            Err(error) => {
                return finish_failure(&emitter, &diagnostic_file, Some("launch"), error.into());
            }
        };
        emit(
            &emitter,
            EventBody::ApplicationStarted {
                platform: platform_label(arguments.platform).to_owned(),
                device_id: outcome.device_id,
                identifier: outcome.application_id,
                process_id: outcome.process_id,
            },
        )?;
        emit(
            &emitter,
            EventBody::PhaseFinished {
                phase: "launch".to_owned(),
                success: true,
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    }

    emit(
        &emitter,
        EventBody::OperationFinished {
            success: true,
            duration_ms: emitter.elapsed_ms(),
            error: None,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn logs(arguments: &IdeDeploymentArgs, dry_run: bool) -> Result<(), CliError> {
    let emitter = stream_emitter(
        arguments.operation_id.clone(),
        arguments.parent_operation_id.clone(),
    )?;
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "logs".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    let diagnostic_file = root.join("ferry.toml").to_string();
    if dry_run {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "dry_run_unsupported",
                "IDE log collection cannot be simulated",
                "Omit `--dry-run` to stream bounded, application-filtered logs until cancellation or tool exit.",
            ),
        );
    }
    if arguments.artifact.is_some() {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "artifact_not_supported_for_logs",
                "log filtering uses the validated project identity, not an unvalidated artifact path",
                "Omit `--artifact`; cargo-ferry reads the exact application identifier and process target from the project.",
            ),
        );
    }
    let config = match rustferry_core::FerryConfig::load(&root.join("ferry.toml")) {
        Ok(config) => config,
        Err(error) => {
            return finish_failure(
                &emitter,
                &diagnostic_file,
                None,
                OperationFailure::from(CliError::from(error)),
            );
        }
    };
    if !project_supports_platform(&config, arguments.platform) {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "platform_not_enabled",
                &format!(
                    "the project does not enable `{}`",
                    platform_label(arguments.platform)
                ),
                "Enable the platform in the top-level `platforms` array in ferry.toml.",
            ),
        );
    }
    let targets = match crate::commands::platform_build::read_cargo_targets(&root) {
        Ok(targets) => targets,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, None, error.into());
        }
    };

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Resolving the explicit logging device".to_owned()),
        },
    )?;
    let selected = match selected_device(
        &root,
        arguments.platform,
        &arguments.device,
        "collect application logs",
        false,
    ) {
        Ok(selected) => selected,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("device_discovery"), error);
        }
    };
    emit_warnings(&emitter, &selected.warnings)?;
    emit(
        &emitter,
        EventBody::Device {
            device: protocol_device(selected.device.clone()),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "logs".to_owned(),
            message: Some("Streaming bounded, application-filtered logs".to_owned()),
        },
    )?;
    let request = cargo_ferry::deployment::LogRequest::new(
        selected.device,
        config.app.identifier,
        targets.binary,
    );
    let service = cargo_ferry::deployment::LogService::new(
        cargo_ferry::deployment::SystemExecutor,
        root.clone(),
    );
    let outcome = match service.stream(&request, |entry| {
        emitter
            .emit(EventBody::Log {
                source_timestamp: (!entry.timestamp.is_empty())
                    .then(|| redact_text(&entry.timestamp)),
                level: log_level(entry.level).to_owned(),
                target: redact_text(&entry.target),
                message: redact_text(&entry.message),
            })
            .map_err(|source| cargo_ferry::deployment::DeploymentError::Io {
                action: "write streamed IDE log event",
                path: camino::Utf8PathBuf::from("<stdout>"),
                source,
            })
    }) {
        Ok(outcome) => outcome,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("logs"), error.into());
        }
    };
    emit(
        &emitter,
        EventBody::Progress {
            phase: "logs".to_owned(),
            message: "Application-log stream ended after the platform tool exited".to_owned(),
            current: Some(outcome.entries),
            total: Some(outcome.entries),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "logs".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    emit(
        &emitter,
        EventBody::OperationFinished {
            success: true,
            duration_ms: emitter.elapsed_ms(),
            error: None,
        },
    )
}

#[derive(Debug)]
struct BuiltDeploymentArtifact {
    deployment: cargo_ferry::deployment::ValidatedArtifact,
    protocol: Artifact,
}

fn build_deployment_artifact(
    root: &camino::Utf8Path,
    arguments: &IdeDeploymentArgs,
    reporter: &Reporter,
) -> Result<BuiltDeploymentArtifact, OperationFailure> {
    let build_platform = match arguments.platform {
        IdePlatform::Android => BuildPlatform::Android(AndroidBuildArgs {
            keystore: None,
            key_alias: None,
        }),
        IdePlatform::IosSimulator => BuildPlatform::Ios(IosBuildArgs {
            simulator: true,
            device: false,
            team: None,
            allow_provisioning_updates: false,
            provisioning_profile: None,
        }),
        IdePlatform::IosDevice => BuildPlatform::Ios(IosBuildArgs {
            simulator: false,
            device: true,
            team: Some(arguments.team.clone().ok_or_else(|| {
                OperationFailure::unsupported(
                    "physical_ios_team_required",
                    "physical iOS deployment requires an explicit Apple Development Team",
                    "Select a team in VS Code or pass `--team TEAM_ID`; credentials and private keys are never accepted.",
                )
            })?),
            allow_provisioning_updates: arguments.allow_provisioning_updates,
            provisioning_profile: arguments.provisioning_profile.clone(),
        }),
    };
    let output = crate::commands::platform_build::execute(
        BuildArgs {
            platform: build_platform,
            release: false,
            remote: None,
            config_dir: None,
            unsigned: false,
            artifact: None,
            include_dsym: false,
            project_dir: Some(root.to_owned()),
        },
        false,
        reporter,
    )
    .map_err(OperationFailure::from)?;
    validated_build_output(output, arguments.platform)
}

fn validated_build_output(
    output: crate::commands::platform_build::BuildOutput,
    platform: IdePlatform,
) -> Result<BuiltDeploymentArtifact, OperationFailure> {
    if !output.validated {
        return Err(OperationFailure::invalid_build_metadata(
            "the build did not report completed independent artifact validation",
        ));
    }
    let deployment = output.deployment_artifact.ok_or_else(|| {
        OperationFailure::invalid_build_metadata(
            "the validated build returned no typed deployment artifact",
        )
    })?;
    let validation = output.validation.ok_or_else(|| {
        OperationFailure::invalid_build_metadata(
            "the validated build returned no validation record",
        )
    })?;
    let (expected_kind, architectures, kind, team_id) = match platform {
        IdePlatform::Android => {
            let validation: rustferry_android::ApkValidation = serde_json::from_value(validation)
                .map_err(|error| {
                OperationFailure::invalid_build_metadata(&format!(
                    "Android validation metadata was malformed: {error}"
                ))
            })?;
            (
                cargo_ferry::deployment::ArtifactKind::AndroidApk,
                validation.native_abis,
                "apk",
                None,
            )
        }
        IdePlatform::IosSimulator => {
            let validation: rustferry_apple::IosArtifactValidation =
                serde_json::from_value(validation).map_err(|error| {
                    OperationFailure::invalid_build_metadata(&format!(
                        "iOS validation metadata was malformed: {error}"
                    ))
                })?;
            (
                cargo_ferry::deployment::ArtifactKind::IosSimulatorApp,
                validation.architectures,
                "app",
                None,
            )
        }
        IdePlatform::IosDevice => {
            let validation: cargo_ferry::deployment::PhysicalIosValidation =
                serde_json::from_value(validation).map_err(|error| {
                    OperationFailure::invalid_build_metadata(&format!(
                        "physical iOS validation metadata was malformed: {error}"
                    ))
                })?;
            (
                cargo_ferry::deployment::ArtifactKind::IosPhysicalApp,
                validation.architectures,
                "app",
                Some(validation.team_id),
            )
        }
    };
    if deployment.kind() != expected_kind {
        return Err(OperationFailure::invalid_build_metadata(&format!(
            "validated artifact platform mismatch: expected {}, found {}",
            expected_kind.label(),
            deployment.kind().label()
        )));
    }
    let mut validation_status = BTreeMap::new();
    validation_status.insert("artifact".to_owned(), "verified".to_owned());
    if let Some(team_id) = team_id {
        validation_status.insert("team_id".to_owned(), team_id);
    }
    let protocol = Artifact {
        platform: output.platform.to_owned(),
        kind: kind.to_owned(),
        path: deployment.path().to_string(),
        package_identifier: deployment.application_id().to_owned(),
        architectures,
        profile: output.profile.to_owned(),
        validation: validation_status,
    };
    Ok(BuiltDeploymentArtifact {
        deployment,
        protocol,
    })
}

#[derive(Debug)]
struct SelectedDevice {
    device: cargo_ferry::deployment::Device,
    warnings: Vec<cargo_ferry::deployment::DiscoveryWarning>,
}

fn selected_device(
    root: &camino::Utf8Path,
    platform: IdePlatform,
    requested_id: &str,
    operation: &'static str,
    requires_install: bool,
) -> Result<SelectedDevice, OperationFailure> {
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        root.to_owned(),
    )
    .discover(match platform {
        IdePlatform::Android => cargo_ferry::deployment::DeviceFilter::Android,
        IdePlatform::IosSimulator | IdePlatform::IosDevice => {
            cargo_ferry::deployment::DeviceFilter::Ios
        }
    });
    let candidate = snapshot
        .devices
        .iter()
        .find(|device| device.id == requested_id)
        .ok_or_else(
            || cargo_ferry::deployment::DeploymentError::DeviceNotFound {
                id: requested_id.to_owned(),
            },
        )?;
    let expected = match platform {
        IdePlatform::Android
            if matches!(
                candidate.kind,
                cargo_ferry::deployment::DeviceKind::AndroidPhysical
                    | cargo_ferry::deployment::DeviceKind::AndroidEmulator
            ) =>
        {
            candidate.kind
        }
        IdePlatform::IosSimulator
            if candidate.kind == cargo_ferry::deployment::DeviceKind::IosSimulator =>
        {
            cargo_ferry::deployment::DeviceKind::IosSimulator
        }
        IdePlatform::IosDevice
            if candidate.kind == cargo_ferry::deployment::DeviceKind::IosPhysical =>
        {
            cargo_ferry::deployment::DeviceKind::IosPhysical
        }
        IdePlatform::Android => cargo_ferry::deployment::DeviceKind::AndroidPhysical,
        IdePlatform::IosSimulator => cargo_ferry::deployment::DeviceKind::IosSimulator,
        IdePlatform::IosDevice => cargo_ferry::deployment::DeviceKind::IosPhysical,
    };
    if candidate.kind != expected {
        return Err(
            cargo_ferry::deployment::DeploymentError::DeviceKindMismatch {
                id: requested_id.to_owned(),
                expected,
                actual: candidate.kind,
            }
            .into(),
        );
    }
    let device = if requires_install {
        cargo_ferry::deployment::select_device(
            &snapshot.devices,
            expected,
            Some(requested_id),
            operation,
        )?
    } else {
        candidate.clone()
    };
    Ok(SelectedDevice {
        device,
        warnings: snapshot.warnings,
    })
}

fn install_command(
    platform: IdePlatform,
    device_id: &str,
    artifact: &camino::Utf8Path,
) -> (&'static str, Vec<String>) {
    match platform {
        IdePlatform::Android => (
            "adb",
            vec![
                "-s".to_owned(),
                device_id.to_owned(),
                "install".to_owned(),
                artifact.to_string(),
            ],
        ),
        IdePlatform::IosSimulator => (
            "xcrun",
            vec![
                "simctl".to_owned(),
                "install".to_owned(),
                device_id.to_owned(),
                artifact.to_string(),
            ],
        ),
        IdePlatform::IosDevice => (
            "xcrun",
            vec![
                "devicectl".to_owned(),
                "device".to_owned(),
                "install".to_owned(),
                "app".to_owned(),
                "--device".to_owned(),
                device_id.to_owned(),
                artifact.to_string(),
            ],
        ),
    }
}

fn launch_command(
    platform: IdePlatform,
    device_id: &str,
    artifact: &cargo_ferry::deployment::ValidatedArtifact,
) -> (&'static str, Vec<String>) {
    match platform {
        IdePlatform::Android => (
            "adb",
            vec![
                "-s".to_owned(),
                device_id.to_owned(),
                "shell".to_owned(),
                "am".to_owned(),
                "start".to_owned(),
                "-W".to_owned(),
                "-n".to_owned(),
                format!("{}/{}", artifact.application_id(), artifact.launch_target()),
            ],
        ),
        IdePlatform::IosSimulator => (
            "xcrun",
            vec![
                "simctl".to_owned(),
                "launch".to_owned(),
                device_id.to_owned(),
                artifact.application_id().to_owned(),
            ],
        ),
        IdePlatform::IosDevice => (
            "xcrun",
            vec![
                "devicectl".to_owned(),
                "device".to_owned(),
                "process".to_owned(),
                "launch".to_owned(),
                "--device".to_owned(),
                device_id.to_owned(),
                artifact.application_id().to_owned(),
            ],
        ),
    }
}

const fn platform_label(platform: IdePlatform) -> &'static str {
    match platform {
        IdePlatform::Android => "android",
        IdePlatform::IosSimulator => "ios-simulator",
        IdePlatform::IosDevice => "ios-device",
    }
}

fn project_supports_platform(config: &rustferry_core::FerryConfig, platform: IdePlatform) -> bool {
    let target = match platform {
        IdePlatform::Android => rustferry_core::TargetPlatform::Android,
        IdePlatform::IosSimulator | IdePlatform::IosDevice => rustferry_core::TargetPlatform::Ios,
    };
    config.platforms.contains(&target)
}

const fn log_level(level: cargo_ferry::deployment::LogLevel) -> &'static str {
    match level {
        cargo_ferry::deployment::LogLevel::Debug => "debug",
        cargo_ferry::deployment::LogLevel::Info => "info",
        cargo_ferry::deployment::LogLevel::Warning => "warning",
        cargo_ferry::deployment::LogLevel::Error => "error",
        cargo_ferry::deployment::LogLevel::Fatal => "fatal",
        cargo_ferry::deployment::LogLevel::Unknown => "unknown",
    }
}

#[derive(Debug)]
struct OperationFailure {
    error: ProtocolError,
    exit_code: u8,
    cancelled: bool,
}

impl OperationFailure {
    fn unsupported(code: &str, message: &str, help: &str) -> Self {
        Self {
            error: ProtocolError {
                code: code.to_owned(),
                message: redact_text(message),
                help: Some(redact_text(help)),
                details: Vec::new(),
            },
            exit_code: 3,
            cancelled: false,
        }
    }

    fn invalid_build_metadata(message: &str) -> Self {
        Self {
            error: ProtocolError {
                code: "invalid_build_validation_metadata".to_owned(),
                message: redact_text(message),
                help: Some(
                    "Rebuild the artifact; cargo-ferry never deploys missing or malformed validation evidence."
                        .to_owned(),
                ),
                details: Vec::new(),
            },
            exit_code: 4,
            cancelled: false,
        }
    }
}

impl From<CliError> for OperationFailure {
    fn from(error: CliError) -> Self {
        let cancelled = matches!(&error, CliError::CommandInterrupted { .. })
            || rustferry_core::process_control::interrupt_requested();
        Self {
            error: protocol_error(&error),
            exit_code: if cancelled { 130 } else { error.exit_code() },
            cancelled,
        }
    }
}

impl From<cargo_ferry::deployment::DeploymentError> for OperationFailure {
    fn from(error: cargo_ferry::deployment::DeploymentError) -> Self {
        use cargo_ferry::deployment::DeploymentError;

        let code = error.code().to_owned();
        let message = redact_text(&error.to_string());
        let help = match &error {
            DeploymentError::ToolMissing { help, .. }
            | DeploymentError::CommandFailed { help, .. }
            | DeploymentError::DeviceUnavailable { help, .. }
            | DeploymentError::Unsupported { help, .. } => Some(redact_text(help)),
            DeploymentError::CommandTimedOut { .. } => {
                Some("Verify the selected device remains connected, then retry.".to_owned())
            }
            DeploymentError::Cancelled { .. } => {
                Some("The active deployment process tree was stopped.".to_owned())
            }
            DeploymentError::DeviceNotFound { .. } => {
                Some("Refresh the device inventory and pass one exact stable device ID.".to_owned())
            }
            DeploymentError::DeviceSelectionRequired { .. } => {
                Some("Pass one exact stable device ID from `cargo ferry ide devices`.".to_owned())
            }
            DeploymentError::DeviceKindMismatch { .. }
            | DeploymentError::PlatformMismatch { .. } => {
                Some("Choose a device whose kind matches the requested platform.".to_owned())
            }
            DeploymentError::InvalidArtifact { .. } => {
                Some("Rebuild and revalidate the artifact before deployment.".to_owned())
            }
            DeploymentError::InvalidSigning { .. } => Some(
                "Create a fresh Apple development-signed build with matching provisioning metadata."
                    .to_owned(),
            ),
            DeploymentError::Io { .. } | DeploymentError::InvalidToolOutput { .. } => None,
        };
        let details = match &error {
            DeploymentError::CommandFailed {
                status: Some(status),
                ..
            } => {
                vec![format!("exit_status={status}")]
            }
            _ => Vec::new(),
        };
        let cancelled = matches!(&error, DeploymentError::Cancelled { .. })
            || rustferry_core::process_control::interrupt_requested();
        let exit_code = if cancelled {
            130
        } else {
            match error {
                DeploymentError::Io { .. } => 5,
                DeploymentError::ToolMissing { .. }
                | DeploymentError::CommandTimedOut { .. }
                | DeploymentError::CommandFailed { .. }
                | DeploymentError::InvalidToolOutput { .. } => 4,
                DeploymentError::Cancelled { .. } => 130,
                DeploymentError::DeviceNotFound { .. }
                | DeploymentError::DeviceSelectionRequired { .. }
                | DeploymentError::DeviceUnavailable { .. }
                | DeploymentError::DeviceKindMismatch { .. }
                | DeploymentError::InvalidArtifact { .. }
                | DeploymentError::PlatformMismatch { .. }
                | DeploymentError::Unsupported { .. }
                | DeploymentError::InvalidSigning { .. } => 3,
            }
        };
        Self {
            error: ProtocolError {
                code,
                message,
                help,
                details,
            },
            exit_code,
            cancelled,
        }
    }
}

fn finish_failure(
    emitter: &EventEmitter,
    file: &str,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    finish_failure_impl(emitter, Some(file), phase, failure)
}

fn finish_failure_after_diagnostics(
    emitter: &EventEmitter,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    finish_failure_impl(emitter, None, phase, failure)
}

fn finish_failure_impl(
    emitter: &EventEmitter,
    diagnostic_file: Option<&str>,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    if let Some(phase) = phase {
        emit(
            emitter,
            EventBody::PhaseFinished {
                phase: phase.to_owned(),
                success: false,
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    }
    if failure.cancelled {
        emit(
            emitter,
            EventBody::OperationCancelled {
                reason: "requested".to_owned(),
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    } else {
        if let Some(file) = diagnostic_file {
            emit(
                emitter,
                EventBody::Diagnostic {
                    diagnostic: Diagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: format!("ferry.{}", failure.error.code),
                        message: failure.error.message.clone(),
                        file: file.to_owned(),
                        range: zero_range(),
                        help: failure.error.help.clone(),
                        documentation: None,
                        fixes: Vec::new(),
                    },
                },
            )?;
        }
        emit(
            emitter,
            EventBody::OperationFinished {
                success: false,
                duration_ms: emitter.elapsed_ms(),
                error: Some(failure.error),
            },
        )?;
    }
    Err(CliError::AlreadyReported {
        exit_code: failure.exit_code,
    })
}

fn stream_emitter(
    operation_id: Option<String>,
    parent_operation_id: Option<String>,
) -> Result<EventEmitter, CliError> {
    match EventEmitter::new(operation_id, parent_operation_id) {
        Ok(emitter) => Ok(emitter),
        Err(error) => {
            write_compact(&ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            })
            .map_err(stdout_error)?;
            Err(CliError::AlreadyReported { exit_code: 2 })
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn finish_error(emitter: &EventEmitter, workspace: &str, error: CliError) -> Result<(), CliError> {
    let protocol_error = protocol_error(&error);
    emit(
        emitter,
        EventBody::Diagnostic {
            diagnostic: Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: format!("ferry.{}", protocol_error.code),
                message: protocol_error.message.clone(),
                file: workspace.to_owned(),
                range: zero_range(),
                help: protocol_error.help.clone(),
                documentation: None,
                fixes: Vec::new(),
            },
        },
    )?;
    emit(
        emitter,
        EventBody::OperationFinished {
            success: false,
            duration_ms: emitter.elapsed_ms(),
            error: Some(protocol_error),
        },
    )?;
    Err(CliError::AlreadyReported {
        exit_code: error.exit_code(),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn finish_build_error(
    emitter: &EventEmitter,
    root: &camino::Utf8Path,
    error: CliError,
) -> Result<(), CliError> {
    let protocol_error = protocol_error(&error);
    emit(
        emitter,
        EventBody::Diagnostic {
            diagnostic: Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: format!("ferry.{}", protocol_error.code),
                message: protocol_error.message.clone(),
                file: root.join("ferry.toml").to_string(),
                range: zero_range(),
                help: protocol_error.help.clone(),
                documentation: None,
                fixes: Vec::new(),
            },
        },
    )?;
    emit(
        emitter,
        EventBody::PhaseFinished {
            phase: "build".to_owned(),
            success: false,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    emit(
        emitter,
        EventBody::OperationFinished {
            success: false,
            duration_ms: emitter.elapsed_ms(),
            error: Some(protocol_error),
        },
    )?;
    Err(CliError::AlreadyReported {
        exit_code: error.exit_code(),
    })
}

fn artifact_architectures(
    config: &rustferry_core::FerryConfig,
    platform: IdePlatform,
) -> Vec<String> {
    match platform {
        IdePlatform::Android => config
            .android
            .abis
            .iter()
            .filter_map(|abi| serde_json::to_value(abi).ok())
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        IdePlatform::IosSimulator => vec![std::env::consts::ARCH.to_owned()],
        IdePlatform::IosDevice => vec!["arm64".to_owned()],
    }
}

fn zero_range() -> SourceRange {
    SourceRange {
        start: Position {
            line: 0,
            character: 0,
        },
        end: Position {
            line: 0,
            character: 0,
        },
    }
}

fn emit(emitter: &EventEmitter, body: EventBody) -> Result<(), CliError> {
    emitter.emit(body).map_err(stdout_error)
}

fn stdout_error(source: std::io::Error) -> CliError {
    CliError::Io {
        action: "write IDE protocol output",
        path: camino::Utf8PathBuf::from("<stdout>"),
        source,
    }
}

fn absolute_display_path(path: &camino::Utf8Path) -> String {
    if let Ok(canonical) = path.canonicalize_utf8() {
        return canonical.to_string();
    }
    if path.is_absolute() {
        return path.to_string();
    }
    std::env::current_dir()
        .ok()
        .and_then(|directory| camino::Utf8PathBuf::from_path_buf(directory).ok())
        .map_or_else(
            || path.to_string(),
            |directory| directory.join(path).to_string(),
        )
}
