use std::fs;

use camino::Utf8Path;
use rustferry_android::{
    AndroidBuildOutcome, AndroidBuildProfile, AndroidBuildRequest, AndroidSigningConfig,
    SigningPasswordSource,
};
use rustferry_apple::{
    AppleBuildProfile, AppleDiscoveryOptions, IosDeviceToolchain, IosSimulatorBuildRequest,
    discover_apple,
};
use rustferry_core::TargetPlatform;
use serde::Serialize;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use cargo_ferry::deployment::{
    PhysicalBuildRequest, SigningService, SystemExecutor, ToolCommand, ValidatedArtifact,
    plan_physical_build,
};

use crate::cli::{
    AndroidBuildArgs, BuildArgs, BuildPlatform, BuildRemoteTarget, IosBuildArgs,
    RemoteProviderChoice,
};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

use super::{remote, ssh_remote};

#[derive(Debug, Serialize)]
pub(crate) struct BuildOutput {
    pub(crate) project: String,
    pub(crate) platform: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) artifact: Option<String>,
    #[serde(skip)]
    pub(crate) deployment_artifact: Option<ValidatedArtifact>,
    pub(crate) expected_artifact: String,
    pub(crate) validated: bool,
    pub(crate) validation: Option<Value>,
    pub(crate) plan: Option<Value>,
    pub(crate) log_directory: Option<String>,
    pub(crate) cache_hits: Vec<String>,
    pub(crate) cache_misses: Vec<String>,
    pub(crate) device_required: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug)]
pub(crate) struct CargoTargets {
    pub(crate) package: String,
    pub(crate) library: String,
    pub(crate) binary: String,
}

impl CargoTargets {
    pub(super) fn binary(&self) -> &str {
        &self.binary
    }
}

pub fn run(arguments: BuildArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    validate_artifact_options(&arguments)?;
    let route = build_route(&arguments);
    if route == BuildRoute::Local {
        validate_local_artifact_options(&arguments)?;
    }
    if route == BuildRoute::Remote {
        return run_remote(arguments, dry_run, reporter);
    }
    let output = execute(arguments, dry_run, reporter)?;
    report_build(&output, reporter);
    Ok(())
}

fn validate_local_artifact_options(arguments: &BuildArgs) -> Result<(), CliError> {
    if arguments.artifact.is_none() && !arguments.include_dsym {
        return Ok(());
    }
    if matches!(&arguments.platform, BuildPlatform::Ios(ios) if ios.device) {
        return Err(CliError::Unsupported {
            message: "local physical-iPhone builds do not support artifact selection yet"
                .to_owned(),
            help:
                "Remove `--artifact` and `--include-dsym`, or explicitly select `--remote github`."
                    .to_owned(),
        });
    }
    Ok(())
}

fn validate_artifact_options(arguments: &BuildArgs) -> Result<(), CliError> {
    if arguments.artifact.is_none() && !arguments.include_dsym {
        return Ok(());
    }
    match &arguments.platform {
        BuildPlatform::Android(_) => Err(CliError::Unsupported {
            message: "physical-iPhone artifact options do not apply to Android builds".to_owned(),
            help: "Remove `--artifact` and `--include-dsym` from the Android build command."
                .to_owned(),
        }),
        BuildPlatform::Ios(ios) if ios.simulator => Err(CliError::Unsupported {
            message: "physical-iPhone artifact options do not apply to iOS Simulator builds"
                .to_owned(),
            help: "Remove `--artifact` and `--include-dsym`, or select `--device`.".to_owned(),
        }),
        BuildPlatform::Iphone(_) | BuildPlatform::Ios(_) => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildRoute {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientHost {
    MacOs,
    NonMacOs,
}

impl ClientHost {
    const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::NonMacOs
        }
    }
}

fn build_route(arguments: &BuildArgs) -> BuildRoute {
    build_route_for_host(arguments, ClientHost::current())
}

fn build_route_for_host(arguments: &BuildArgs, host: ClientHost) -> BuildRoute {
    match &arguments.platform {
        BuildPlatform::Iphone(_) => BuildRoute::Remote,
        BuildPlatform::Ios(ios)
            if ios.device
                && (arguments.remote.is_some()
                    || arguments.unsigned
                    || host == ClientHost::NonMacOs) =>
        {
            BuildRoute::Remote
        }
        BuildPlatform::Android(_) | BuildPlatform::Ios(_) => BuildRoute::Local,
    }
}

fn run_remote(arguments: BuildArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let remote_target = arguments
        .remote
        .clone()
        .unwrap_or(BuildRemoteTarget::Github);
    if remote_target == BuildRemoteTarget::Github && arguments.config_dir.is_some() {
        return Err(CliError::Unsupported {
            message: "`--config-dir` applies only to named SSH build remotes".to_owned(),
            help: "Remove `--config-dir` for GitHub, or pass `--remote REMOTE_NAME`.".to_owned(),
        });
    }
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let targets = read_cargo_targets(&root)?;
    require_platform(&config, TargetPlatform::Ios, "ios")?;

    let team = match arguments.platform {
        BuildPlatform::Iphone(iphone) => iphone.team,
        BuildPlatform::Ios(ios) => {
            if ios.allow_provisioning_updates || ios.provisioning_profile.is_some() {
                return Err(CliError::Unsupported {
                    message: "local Xcode provisioning options cannot be used for a remote iPhone build"
                        .to_owned(),
                    help: "Remove `--allow-provisioning-updates` and `--provisioning-profile`; local physical-iPhone builds are available only on macOS."
                        .to_owned(),
                });
            }
            ios.team
        }
        BuildPlatform::Android(_) => unreachable!("only iPhone builds use the remote route"),
    };
    let artifact = arguments.artifact;
    let include_dsym = arguments.include_dsym;

    match remote_target {
        BuildRemoteTarget::Github => remote::build_iphone(
            &root,
            &config,
            &targets.package,
            &targets.binary,
            RemoteProviderChoice::Github,
            team.as_deref(),
            arguments.release,
            arguments.unsigned,
            artifact,
            include_dsym,
            dry_run,
            reporter,
        ),
        BuildRemoteTarget::SshMac(name) => {
            ssh_remote::validate_snapshot_build_mode(
                team.as_deref(),
                arguments.unsigned,
                artifact,
                include_dsym,
            )?;
            let endpoint = ssh_remote::load_endpoint(&name, arguments.config_dir.as_deref())?;
            ssh_remote::build_iphone(
                &root,
                &config,
                &targets.package,
                &targets.binary,
                &endpoint,
                team.as_deref(),
                arguments.release,
                arguments.unsigned,
                artifact,
                include_dsym,
                dry_run,
                reporter,
            )
        }
    }
}

pub(crate) fn execute(
    arguments: BuildArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<BuildOutput, CliError> {
    validate_artifact_options(&arguments)?;
    validate_local_artifact_options(&arguments)?;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let targets = read_cargo_targets(&root)?;
    match arguments.platform {
        BuildPlatform::Android(android) => {
            if arguments.remote.is_some() || arguments.config_dir.is_some() || arguments.unsigned {
                return Err(CliError::Unsupported {
                    message: "remote, config-directory, and unsigned options apply only to physical-iPhone builds"
                        .to_owned(),
                    help: "Remove `--remote`, `--config-dir`, and `--unsigned` from the Android build command."
                        .to_owned(),
                });
            }
            build_android(
                &root,
                config,
                &targets,
                android,
                arguments.release,
                dry_run,
                reporter,
            )
        }
        BuildPlatform::Iphone(_) => Err(CliError::Unsupported {
            message: "physical-iPhone builds use the remote build route".to_owned(),
            help: "Run this build through the top-level `cargo ferry build` command.".to_owned(),
        }),
        BuildPlatform::Ios(ios) => {
            if arguments.remote.is_some() || arguments.config_dir.is_some() || arguments.unsigned {
                return Err(CliError::Unsupported {
                    message: "remote, config-directory, and unsigned options apply only to physical-iPhone builds"
                        .to_owned(),
                    help: "Use `cargo ferry build ios --simulator` without `--remote`, `--config-dir`, or `--unsigned`, or select `--device`."
                        .to_owned(),
                });
            }
            build_ios(
                &root,
                config,
                &targets,
                &ios,
                arguments.release,
                dry_run,
                reporter,
            )
        }
    }
}

fn build_android(
    root: &Utf8Path,
    config: rustferry_core::FerryConfig,
    targets: &CargoTargets,
    arguments: AndroidBuildArgs,
    release: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<BuildOutput, CliError> {
    require_platform(&config, TargetPlatform::Android, "android")?;
    let mut request = AndroidBuildRequest::new(
        root,
        config,
        targets.package.clone(),
        targets.library.clone(),
    );
    request.profile = if release {
        AndroidBuildProfile::Release
    } else {
        AndroidBuildProfile::Debug
    };
    if let (Some(keystore), Some(key_alias)) = (arguments.keystore, arguments.key_alias) {
        request.signing = AndroidSigningConfig::Keystore {
            keystore,
            key_alias,
            store_password: SigningPasswordSource::Environment(
                "CARGO_FERRY_KEYSTORE_PASSWORD".to_owned(),
            ),
            key_password: std::env::var_os("CARGO_FERRY_KEY_PASSWORD")
                .is_some()
                .then(|| SigningPasswordSource::Environment("CARGO_FERRY_KEY_PASSWORD".to_owned())),
        };
    }

    request.dry_run = true;
    let plan = match rustferry_android::build_android(&request)? {
        AndroidBuildOutcome::DryRun(plan) => plan,
        AndroidBuildOutcome::Built(_) => unreachable!("dry-run request returned a built APK"),
    };
    for step in &plan.steps {
        if let Some(command) = &step.command {
            reporter.verbose(format!("{}: {}", step.stage, command.join(" ")));
        }
    }
    let expected_artifact = plan.paths.final_apk.to_string();
    if dry_run {
        let output = BuildOutput {
            project: root.to_string(),
            platform: "android",
            profile: profile_name(release),
            artifact: None,
            deployment_artifact: None,
            expected_artifact,
            validated: false,
            validation: None,
            plan: Some(serde_json::to_value(&plan.steps).unwrap_or(Value::Null)),
            log_directory: Some(plan.paths.logs.to_string()),
            cache_hits: Vec::new(),
            cache_misses: Vec::new(),
            device_required: false,
            dry_run: true,
        };
        return Ok(output);
    }

    request.dry_run = false;
    let artifact = match rustferry_android::build_android(&request)? {
        AndroidBuildOutcome::Built(artifact) => artifact,
        AndroidBuildOutcome::DryRun(_) => unreachable!("build request returned a dry-run plan"),
    };
    let deployment_artifact = ValidatedArtifact::from_android_build(&artifact)?;
    let cacheable_stages = ["aapt2-compile", "aapt2-link", "d8"];
    let cache_misses = cacheable_stages
        .iter()
        .filter(|stage| !artifact.cache_hits().iter().any(|hit| hit == **stage))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    for stage in cacheable_stages {
        let result = if artifact.cache_hits().iter().any(|hit| hit == stage) {
            "hit"
        } else {
            "miss"
        };
        reporter.verbose(format!("Android cache {stage}: {result}"));
    }
    let output = BuildOutput {
        project: root.to_string(),
        platform: "android",
        profile: profile_name(release),
        artifact: Some(artifact.apk().to_string()),
        deployment_artifact: Some(deployment_artifact),
        expected_artifact,
        validated: true,
        validation: Some(serde_json::to_value(artifact.validation()).unwrap_or(Value::Null)),
        plan: None,
        log_directory: Some(artifact.log_dir().to_string()),
        cache_hits: artifact.cache_hits().to_vec(),
        cache_misses,
        device_required: false,
        dry_run: false,
    };
    Ok(output)
}

fn ios_request(
    root: &Utf8Path,
    config: rustferry_core::FerryConfig,
    targets: &CargoTargets,
    release: bool,
) -> IosSimulatorBuildRequest {
    let mut request = IosSimulatorBuildRequest::new(root, config, targets.binary.clone());
    request.package_name = Some(targets.package.clone());
    request.profile = if release {
        AppleBuildProfile::Release
    } else {
        AppleBuildProfile::Debug
    };
    request
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_ios(
    root: &Utf8Path,
    config: rustferry_core::FerryConfig,
    targets: &CargoTargets,
    arguments: &IosBuildArgs,
    release: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<BuildOutput, CliError> {
    require_platform(&config, TargetPlatform::Ios, "ios")?;
    if arguments.device {
        return build_ios_device(root, config, targets, arguments, release, dry_run, reporter);
    }
    if !arguments.simulator {
        return Err(CliError::Unsupported {
            message: "an iOS build mode was not selected".to_owned(),
            help: "Pass `--simulator`; use `--device --team TEAM` for a local signed build, or `--device --remote github` for a remote build."
                .to_owned(),
        });
    }

    let mut request = ios_request(root, config, targets, release);
    request.dry_run = true;
    let planned = rustferry_apple::build_ios_simulator(&request)?;
    let planned_plan = planned.plan();
    for command in &planned_plan.commands {
        reporter.verbose(format!(
            "{}: {}",
            command.stage,
            command.redacted_argv().join(" ")
        ));
    }
    let expected_artifact = planned_plan.artifact_path.to_string();
    let log_directory = root
        .join("target/ferry/ios/logs")
        .join(profile_name(release))
        .to_string();
    if dry_run {
        let commands = planned
            .plan()
            .commands
            .iter()
            .map(|command| {
                json!({
                    "stage": command.stage,
                    "argv": command.redacted_argv(),
                    "environment": command.redacted_environment(),
                })
            })
            .collect::<Vec<_>>();
        let output = BuildOutput {
            project: root.to_string(),
            platform: "ios-simulator",
            profile: profile_name(release),
            artifact: None,
            deployment_artifact: None,
            expected_artifact,
            validated: false,
            validation: None,
            plan: Some(json!({
                "rust_target": &planned_plan.rust_target,
                "commands": commands,
                "generated_files": &planned_plan.generated_files,
            })),
            log_directory: Some(log_directory),
            cache_hits: Vec::new(),
            cache_misses: Vec::new(),
            device_required: false,
            dry_run: true,
        };
        return Ok(output);
    }

    request.dry_run = false;
    let built = rustferry_apple::build_ios_simulator(&request)?;
    let deployment_artifact = ValidatedArtifact::from_ios_simulator_build(&built)?;
    let artifact = built.artifact().ok_or_else(|| CliError::Unsupported {
        message: "the iOS builder completed without an artifact".to_owned(),
        help: "Inspect the iOS build logs and rerun `cargo ferry doctor`.".to_owned(),
    })?;
    let validation = built.validation().ok_or_else(|| CliError::Unsupported {
        message: "the iOS builder completed without artifact validation".to_owned(),
        help:
            "Inspect the iOS validation logs; unvalidated bundles are never reported as successful."
                .to_owned(),
    })?;
    let output = BuildOutput {
        project: root.to_string(),
        platform: "ios-simulator",
        profile: profile_name(release),
        artifact: Some(artifact.to_string()),
        deployment_artifact: Some(deployment_artifact),
        expected_artifact,
        validated: true,
        validation: Some(serde_json::to_value(validation).unwrap_or(Value::Null)),
        plan: None,
        log_directory: Some(log_directory),
        cache_hits: Vec::new(),
        cache_misses: Vec::new(),
        device_required: false,
        dry_run: false,
    };
    Ok(output)
}

fn build_ios_device(
    root: &Utf8Path,
    config: rustferry_core::FerryConfig,
    targets: &CargoTargets,
    arguments: &IosBuildArgs,
    release: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<BuildOutput, CliError> {
    let team = arguments
        .team
        .as_deref()
        .ok_or_else(|| CliError::Unsupported {
            message: "physical iOS builds require an explicit Apple Development Team".to_owned(),
            help: "Run `cargo ferry signing teams`, then pass `--device --team TEAM_ID`."
                .to_owned(),
        })?;
    let mut request = PhysicalBuildRequest::new(root, config, targets.binary.clone(), team);
    request.package_name = Some(targets.package.clone());
    request.release = release;
    request.allow_provisioning_updates = arguments.allow_provisioning_updates;
    request
        .provisioning_profile
        .clone_from(&arguments.provisioning_profile);

    if dry_run {
        let xcrun = intended_xcrun_path();
        let developer_dir = intended_developer_dir();
        let plan = plan_physical_build(&request, &intended_cargo_path(), &xcrun, &developer_dir)?;
        reporter.verbose(format!(
            "physical-ios-rust: {}",
            display_tool_command(&plan.cargo_command).join(" ")
        ));
        reporter.verbose(format!(
            "physical-ios-xcode: {}",
            display_tool_command(&plan.xcodebuild_command).join(" ")
        ));
        return Ok(BuildOutput {
            project: root.to_string(),
            platform: "ios-device",
            profile: profile_name(release),
            artifact: None,
            deployment_artifact: None,
            expected_artifact: plan.artifact_path.to_string(),
            validated: false,
            validation: None,
            plan: Some(json!({
                "schema_version": plan.schema_version,
                "rust_target": plan.rust_target,
                "generated_root": plan.generated_root,
                "artifact": plan.artifact_path,
                "allow_provisioning_updates": plan.allow_provisioning_updates,
                "commands": [
                    display_tool_command(&plan.cargo_command),
                    display_tool_command(&plan.xcodebuild_command),
                ],
            })),
            log_directory: None,
            cache_hits: Vec::new(),
            cache_misses: Vec::new(),
            device_required: false,
            dry_run: true,
        });
    }

    let toolchain = discover_physical_toolchain(root)?;
    let service = SigningService::for_physical_build(SystemExecutor, &toolchain)?;
    let plan = service.plan(&request)?;
    reporter.verbose(format!(
        "physical-ios-rust: {}",
        display_tool_command(&plan.cargo_command).join(" ")
    ));
    reporter.verbose(format!(
        "physical-ios-xcode: {}",
        display_tool_command(&plan.xcodebuild_command).join(" ")
    ));
    let expected_artifact = plan.artifact_path.to_string();
    let built = service.build(&request)?;
    let artifact_path = built.artifact.path().to_string();
    let validation = serde_json::to_value(&built.validation).unwrap_or(Value::Null);
    Ok(BuildOutput {
        project: root.to_string(),
        platform: "ios-device",
        profile: profile_name(release),
        artifact: Some(artifact_path),
        deployment_artifact: Some(built.artifact),
        expected_artifact,
        validated: true,
        validation: Some(validation),
        plan: None,
        log_directory: None,
        cache_hits: Vec::new(),
        cache_misses: Vec::new(),
        device_required: false,
        dry_run: false,
    })
}

fn discover_physical_toolchain(root: &Utf8Path) -> Result<IosDeviceToolchain, CliError> {
    let mut search_paths = vec![
        camino::Utf8PathBuf::from("/usr/bin"),
        camino::Utf8PathBuf::from("/bin"),
    ];
    let executable_directory = std::env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(std::path::Path::to_owned))
        .and_then(|parent| camino::Utf8PathBuf::from_path_buf(parent).ok());
    for path in [
        "/opt/homebrew/opt/rustup/bin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ] {
        let path = camino::Utf8PathBuf::from(path);
        if !search_paths.contains(&path) {
            search_paths.push(path);
        }
    }
    if let Some(parent) = executable_directory
        && !search_paths.contains(&parent)
    {
        search_paths.push(parent);
    }
    let discovery = discover_apple(&AppleDiscoveryOptions {
        developer_dir: developer_dir_override()?,
        executable_search_paths: search_paths,
        current_dir: root.to_owned(),
        host_os: std::env::consts::OS.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
    })?;
    discovery.select_device_toolchain().map_err(Into::into)
}

fn developer_dir_override() -> Result<Option<camino::Utf8PathBuf>, CliError> {
    canonical_developer_dir_override(
        std::env::var_os("DEVELOPER_DIR").map(std::path::PathBuf::from),
    )
}

fn canonical_developer_dir_override(
    path: Option<std::path::PathBuf>,
) -> Result<Option<camino::Utf8PathBuf>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let developer_dir = camino::Utf8PathBuf::from_path_buf(path).map_err(CliError::NonUtf8Path)?;
    let canonical = developer_dir
        .canonicalize_utf8()
        .map_err(|source| CliError::Io {
            action: "resolve DEVELOPER_DIR",
            path: developer_dir,
            source,
        })?;
    if !canonical.is_dir() {
        return Err(rustferry_apple::AppleError::InvalidRequest(
            "DEVELOPER_DIR must identify an existing directory".to_owned(),
        )
        .into());
    }
    Ok(Some(canonical))
}

fn intended_cargo_path() -> camino::Utf8PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_owned))
        .and_then(|parent| camino::Utf8PathBuf::from_path_buf(parent).ok())
        .map_or_else(
            || {
                if cfg!(windows) {
                    camino::Utf8PathBuf::from("C:/Program Files/Rust/bin/cargo.exe")
                } else {
                    camino::Utf8PathBuf::from("/usr/local/bin/cargo")
                }
            },
            |parent| parent.join(if cfg!(windows) { "cargo.exe" } else { "cargo" }),
        )
}

fn intended_xcrun_path() -> camino::Utf8PathBuf {
    if cfg!(windows) {
        camino::Utf8PathBuf::from("C:/usr/bin/xcrun.exe")
    } else {
        camino::Utf8PathBuf::from("/usr/bin/xcrun")
    }
}

fn intended_developer_dir() -> camino::Utf8PathBuf {
    if cfg!(windows) {
        camino::Utf8PathBuf::from("C:/Applications/Xcode.app/Contents/Developer")
    } else {
        camino::Utf8PathBuf::from("/Applications/Xcode.app/Contents/Developer")
    }
}

fn display_tool_command(command: &ToolCommand) -> Vec<String> {
    std::iter::once(command.program.to_string())
        .chain(
            command
                .arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned()),
        )
        .collect()
}

fn report_build(output: &BuildOutput, reporter: &Reporter) {
    reporter.success(
        "build",
        &output,
        || {
            if output.dry_run {
                format!(
                    "Build plan\n\nPlatform:\n  {}\n\nExpected artifact:\n  {}\n\nA connected device is not required.",
                    output.platform, output.expected_artifact
                )
            } else {
                format!(
                    "✓ Built and validated {} artifact\n\nArtifact:\n  {}\n\nLogs:\n  {}\n\nA connected device was not required.",
                    output.platform,
                    output.artifact.as_deref().unwrap_or("<missing>"),
                    output.log_directory.as_deref().unwrap_or("<none>")
                )
            }
        },
        &[],
    );
}

pub(crate) fn read_cargo_targets(root: &Utf8Path) -> Result<CargoTargets, CliError> {
    let path = root.join("Cargo.toml");
    let source = fs::read_to_string(&path).map_err(|source| CliError::Io {
        action: "read Cargo manifest",
        path: path.clone(),
        source,
    })?;
    let document = source
        .parse::<DocumentMut>()
        .map_err(|error| CliError::ProjectManifest {
            path: path.clone(),
            message: error.to_string(),
        })?;
    let package = document["package"]["name"]
        .as_str()
        .ok_or_else(|| CliError::ProjectManifest {
            path: path.clone(),
            message: "`package.name` is required".to_owned(),
        })?
        .to_owned();
    let library = document
        .get("lib")
        .and_then(|item| item.get("name"))
        .and_then(toml_edit::Item::as_str)
        .map_or_else(|| package.replace('-', "_"), ToOwned::to_owned);
    let binaries = document
        .get("bin")
        .and_then(toml_edit::Item::as_array_of_tables)
        .map(|tables| {
            tables
                .iter()
                .filter_map(|table| table.get("name").and_then(toml_edit::Item::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let binary = match binaries.as_slice() {
        [] => package.clone(),
        [only] => only.clone(),
        many => many
            .iter()
            .find(|name| *name == &package)
            .cloned()
            .ok_or_else(|| CliError::ProjectManifest {
                path: path.clone(),
                message: "multiple binary targets exist and none matches `package.name`; cargo-ferry cannot choose one safely".to_owned(),
            })?,
    };
    Ok(CargoTargets {
        package,
        library,
        binary,
    })
}

fn require_platform(
    config: &rustferry_core::FerryConfig,
    platform: TargetPlatform,
    name: &'static str,
) -> Result<(), CliError> {
    if config.platforms.contains(&platform) {
        Ok(())
    } else {
        Err(CliError::Unsupported {
            message: format!("the project does not enable the `{name}` platform"),
            help: format!("Add `{name}` to the top-level `platforms` array in ferry.toml."),
        })
    }
}

const fn profile_name(release: bool) -> &'static str {
    if release { "release" } else { "debug" }
}

#[cfg(test)]
mod tests {
    use crate::cli::{
        AndroidBuildArgs, BuildArgs, BuildArtifactSelection, BuildPlatform, BuildRemoteTarget,
        IosBuildArgs, IphoneBuildArgs,
    };

    use super::{
        BuildRoute, ClientHost, build_route_for_host, canonical_developer_dir_override,
        intended_developer_dir, intended_xcrun_path, validate_artifact_options,
        validate_local_artifact_options,
    };

    fn ios_arguments(device: bool, remote: Option<BuildRemoteTarget>, unsigned: bool) -> BuildArgs {
        BuildArgs {
            platform: BuildPlatform::Ios(IosBuildArgs {
                simulator: !device,
                device,
                team: device.then(|| "TEAM123456".to_owned()),
                allow_provisioning_updates: false,
                provisioning_profile: None,
            }),
            release: false,
            remote,
            config_dir: None,
            unsigned,
            artifact: None,
            include_dsym: false,
            project_dir: None,
        }
    }

    #[test]
    fn ios_device_auto_selects_remote_only_away_from_macos() {
        assert_eq!(
            build_route_for_host(&ios_arguments(true, None, false), ClientHost::MacOs),
            BuildRoute::Local
        );
        assert_eq!(
            build_route_for_host(&ios_arguments(true, None, false), ClientHost::NonMacOs),
            BuildRoute::Remote
        );
    }

    #[test]
    fn physical_dry_run_tool_paths_are_absolute_on_the_target_host() {
        assert!(intended_xcrun_path().is_absolute());
        assert!(intended_developer_dir().is_absolute());
    }

    #[test]
    fn explicit_developer_directory_is_canonicalized_before_discovery() {
        let directory = tempfile::tempdir().expect("developer directory");
        let expected = camino::Utf8PathBuf::from_path_buf(
            directory
                .path()
                .canonicalize()
                .expect("canonical directory"),
        )
        .expect("UTF-8 directory");

        let selected = canonical_developer_dir_override(Some(directory.path().to_owned()))
            .expect("valid override")
            .expect("present override");

        assert_eq!(selected, expected);
    }

    #[test]
    fn remote_or_unsigned_ios_device_build_uses_remote_route() {
        for host in [ClientHost::MacOs, ClientHost::NonMacOs] {
            assert_eq!(
                build_route_for_host(
                    &ios_arguments(true, Some(BuildRemoteTarget::Github), false),
                    host,
                ),
                BuildRoute::Remote
            );
            assert_eq!(
                build_route_for_host(&ios_arguments(true, None, true), host),
                BuildRoute::Remote
            );
        }
    }

    #[test]
    fn named_ssh_ios_device_build_uses_remote_route_on_every_host() {
        let name = rustferry_ssh::SshRemoteName::new("office-mac").expect("remote name");
        for host in [ClientHost::MacOs, ClientHost::NonMacOs] {
            assert_eq!(
                build_route_for_host(
                    &ios_arguments(true, Some(BuildRemoteTarget::SshMac(name.clone())), false,),
                    host,
                ),
                BuildRoute::Remote
            );
        }
    }

    #[test]
    fn simulator_options_never_select_the_remote_route() {
        for host in [ClientHost::MacOs, ClientHost::NonMacOs] {
            assert_eq!(
                build_route_for_host(
                    &ios_arguments(false, Some(BuildRemoteTarget::Github), false),
                    host,
                ),
                BuildRoute::Local
            );
        }
    }

    #[test]
    fn artifact_options_are_physical_iphone_only() {
        let mut simulator = ios_arguments(false, None, false);
        simulator.artifact = Some(BuildArtifactSelection::App);
        assert!(validate_artifact_options(&simulator).is_err());

        let android = BuildArgs {
            platform: BuildPlatform::Android(AndroidBuildArgs {
                keystore: None,
                key_alias: None,
            }),
            release: false,
            remote: None,
            config_dir: None,
            unsigned: false,
            artifact: None,
            include_dsym: true,
            project_dir: None,
        };
        assert!(validate_artifact_options(&android).is_err());

        let mut device = ios_arguments(true, None, false);
        device.artifact = Some(BuildArtifactSelection::Archive);
        assert!(validate_artifact_options(&device).is_ok());
        assert_eq!(
            build_route_for_host(&device, ClientHost::MacOs),
            BuildRoute::Local
        );
        assert!(validate_local_artifact_options(&device).is_err());

        device.remote = Some(BuildRemoteTarget::Github);
        assert_eq!(
            build_route_for_host(&device, ClientHost::MacOs),
            BuildRoute::Remote
        );
    }

    #[test]
    fn iphone_alias_always_selects_the_remote_route() {
        let arguments = BuildArgs {
            platform: BuildPlatform::Iphone(IphoneBuildArgs { team: None }),
            release: false,
            remote: None,
            config_dir: None,
            unsigned: false,
            artifact: None,
            include_dsym: false,
            project_dir: None,
        };
        for host in [ClientHost::MacOs, ClientHost::NonMacOs] {
            assert_eq!(build_route_for_host(&arguments, host), BuildRoute::Remote);
        }
    }
}
