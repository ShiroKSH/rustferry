use std::fs;

use camino::Utf8Path;
use rustferry_android::{
    AndroidBuildOutcome, AndroidBuildProfile, AndroidBuildRequest, AndroidSigningConfig,
    SigningPasswordSource,
};
use rustferry_apple::{AppleBuildProfile, IosSimulatorBuildRequest};
use rustferry_core::TargetPlatform;
use serde::Serialize;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::cli::{AndroidBuildArgs, BuildArgs, BuildPlatform, IosBuildArgs, RemoteProviderChoice};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

use super::remote;

#[derive(Debug, Serialize)]
struct BuildOutput {
    project: String,
    platform: &'static str,
    profile: &'static str,
    artifact: Option<String>,
    expected_artifact: String,
    validated: bool,
    validation: Option<Value>,
    plan: Option<Value>,
    log_directory: Option<String>,
    cache_hits: Vec<String>,
    cache_misses: Vec<String>,
    device_required: bool,
    dry_run: bool,
}

#[derive(Debug)]
pub(super) struct CargoTargets {
    package: String,
    library: String,
    binary: String,
}

impl CargoTargets {
    pub(super) fn binary(&self) -> &str {
        &self.binary
    }
}

pub fn run(arguments: BuildArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let targets = read_cargo_targets(&root)?;
    match arguments.platform {
        BuildPlatform::Android(android) => {
            if arguments.remote.is_some() || arguments.unsigned {
                return Err(CliError::Unsupported {
                    message: "remote and unsigned options apply only to physical-iPhone builds"
                        .to_owned(),
                    help: "Remove `--remote` and `--unsigned` from the Android build command."
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
        BuildPlatform::Iphone(iphone) => {
            require_platform(&config, TargetPlatform::Ios, "ios")?;
            remote::build_iphone(
                &root,
                &config,
                &targets.package,
                &targets.binary,
                arguments.remote.unwrap_or(RemoteProviderChoice::Github),
                iphone.team.as_deref(),
                arguments.release,
                arguments.unsigned,
                dry_run,
                reporter,
            )
        }
        BuildPlatform::Ios(ios) => build_ios(
            &root,
            config,
            &targets,
            &ios,
            arguments.remote,
            arguments.release,
            arguments.unsigned,
            dry_run,
            reporter,
        ),
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
) -> Result<(), CliError> {
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
        report_build(&output, reporter);
        return Ok(());
    }

    request.dry_run = false;
    let artifact = match rustferry_android::build_android(&request)? {
        AndroidBuildOutcome::Built(artifact) => artifact,
        AndroidBuildOutcome::DryRun(_) => unreachable!("build request returned a dry-run plan"),
    };
    let cacheable_stages = ["aapt2-compile", "aapt2-link", "d8"];
    let cache_misses = cacheable_stages
        .iter()
        .filter(|stage| !artifact.cache_hits.iter().any(|hit| hit == **stage))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    for stage in cacheable_stages {
        let result = if artifact.cache_hits.iter().any(|hit| hit == stage) {
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
        artifact: Some(artifact.apk.to_string()),
        expected_artifact,
        validated: true,
        validation: Some(serde_json::to_value(&artifact.validation).unwrap_or(Value::Null)),
        plan: None,
        log_directory: Some(artifact.log_dir.to_string()),
        cache_hits: artifact.cache_hits,
        cache_misses,
        device_required: false,
        dry_run: false,
    };
    report_build(&output, reporter);
    Ok(())
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
    remote_provider: Option<RemoteProviderChoice>,
    release: bool,
    unsigned: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    require_platform(&config, TargetPlatform::Ios, "ios")?;
    if arguments.device {
        return remote::build_iphone(
            root,
            &config,
            &targets.package,
            &targets.binary,
            remote_provider.unwrap_or(RemoteProviderChoice::Github),
            arguments.team.as_deref(),
            release,
            unsigned,
            dry_run,
            reporter,
        );
    }
    if !arguments.simulator {
        return Err(CliError::Unsupported {
            message: "an iOS build mode was not selected".to_owned(),
            help:
                "Pass `--simulator`, or use `--device --remote github` for a physical-iPhone build."
                    .to_owned(),
        });
    }
    if remote_provider.is_some() || unsigned {
        return Err(CliError::Unsupported {
            message: "remote and unsigned options apply only to physical-iPhone builds".to_owned(),
            help: "Use `cargo ferry build ios --simulator` without `--remote` or `--unsigned`, or select `--device`.".to_owned(),
        });
    }

    let mut request = ios_request(root, config, targets, release);
    request.dry_run = true;
    let planned = rustferry_apple::build_ios_simulator(&request)?;
    for command in &planned.plan.commands {
        reporter.verbose(format!(
            "{}: {}",
            command.stage,
            command.redacted_argv().join(" ")
        ));
    }
    let expected_artifact = planned.plan.artifact_path.to_string();
    let log_directory = root
        .join("target/ferry/ios/logs")
        .join(profile_name(release))
        .to_string();
    if dry_run {
        let commands = planned
            .plan
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
            expected_artifact,
            validated: false,
            validation: None,
            plan: Some(json!({
                "rust_target": planned.plan.rust_target,
                "commands": commands,
                "generated_files": planned.plan.generated_files,
            })),
            log_directory: Some(log_directory),
            cache_hits: Vec::new(),
            cache_misses: Vec::new(),
            device_required: false,
            dry_run: true,
        };
        report_build(&output, reporter);
        return Ok(());
    }

    request.dry_run = false;
    let built = rustferry_apple::build_ios_simulator(&request)?;
    let artifact = built.artifact.ok_or_else(|| CliError::Unsupported {
        message: "the iOS builder completed without an artifact".to_owned(),
        help: "Inspect the iOS build logs and rerun `cargo ferry doctor`.".to_owned(),
    })?;
    let validation = built.validation.ok_or_else(|| CliError::Unsupported {
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
    report_build(&output, reporter);
    Ok(())
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

pub(super) fn read_cargo_targets(root: &Utf8Path) -> Result<CargoTargets, CliError> {
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
