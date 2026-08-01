use std::fs;

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rustferry_core::{FerryConfig, ProjectAssets, brand};
use rustferry_remote::{
    IosDeviceProductExpectation, UnsignedNestedBundleExpectation, UnsignedNestedBundleKind,
    UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection, inspect_unsigned_xcarchive,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AppleBuildProfile, AppleError, CommandSpec, IOS_DEVICE_TARGET, IosDeviceToolchain,
    IosProjectPlatform, IosProjectSpec, PlannedCopy, error::io_error,
    generate_ios_project_for_platform, run_command, write_ios_project,
};

const IOS_DEVICE_SDK: &str = "iphoneos";
const IOS_GENERIC_DESTINATION: &str = "generic/platform=iOS";

/// Inputs for an unsigned physical-iPhone compilation and Xcode archive.
#[derive(Clone, Debug, PartialEq)]
pub struct IosDeviceArchiveRequest {
    /// Rust project containing `Cargo.toml` and `ferry.toml`.
    pub project_dir: Utf8PathBuf,
    /// Validated application configuration.
    pub config: FerryConfig,
    /// Cargo binary target and final `CFBundleExecutable` name.
    pub binary_name: String,
    /// Optional Cargo package selector for workspace projects.
    pub package_name: Option<String>,
    /// Cargo/Xcode profile.
    pub profile: AppleBuildProfile,
    /// Explicit Cargo features enabled for the target build.
    pub cargo_features: Vec<String>,
    /// Plan only; perform no writes or subprocess execution.
    pub dry_run: bool,
}

impl IosDeviceArchiveRequest {
    /// Construct a release-mode unsigned physical-device archive request.
    pub fn new(
        project_dir: impl Into<Utf8PathBuf>,
        config: FerryConfig,
        binary_name: impl Into<String>,
    ) -> Self {
        Self {
            project_dir: project_dir.into(),
            config,
            binary_name: binary_name.into(),
            package_name: None,
            profile: AppleBuildProfile::Release,
            cargo_features: Vec::new(),
            dry_run: false,
        }
    }
}

/// Installation status of a physical-device build product.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IosDeviceArtifactDisposition {
    /// Compiled device code in an unsigned archive; not installable until separately signed.
    UnsignedCompileOnly,
}

/// Commands and invariants used to reject Simulator Mach-O output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosDeviceMachOValidationPlan {
    /// Archived application executable to inspect.
    pub executable_path: Utf8PathBuf,
    /// Required thin Mach-O architecture.
    pub expected_architecture: String,
    /// Required `LC_BUILD_VERSION` platform reported by `vtool`.
    pub expected_platform: String,
    /// Required minimum iOS version reported by `vtool`.
    pub expected_minimum_os: String,
    /// Required iPhoneOS SDK version reported by `vtool`.
    pub expected_sdk: String,
    /// Tokenized architecture and platform inspection commands.
    pub commands: Vec<CommandSpec>,
}

/// Complete serializable plan for an unsigned physical-device Xcode archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosDeviceArchivePlan {
    /// Stable plan schema version.
    pub schema_version: u32,
    /// Rust compilation target.
    pub rust_target: String,
    /// Xcode SDK identifier.
    pub sdk: String,
    /// Xcode generic destination.
    pub destination: String,
    /// Build profile.
    pub profile: AppleBuildProfile,
    /// Explicitly non-installable output classification.
    pub disposition: IosDeviceArtifactDisposition,
    /// Internal generated Xcode root.
    pub generated_root: Utf8PathBuf,
    /// Isolated Cargo target directory.
    pub cargo_target_dir: Utf8PathBuf,
    /// Xcode `DerivedData` directory.
    pub xcode_derived_data: Utf8PathBuf,
    /// Xcode destination preflight, Rust compilation, and Xcode archive commands, in order.
    pub commands: Vec<CommandSpec>,
    /// Deterministic generated file paths.
    pub generated_files: Vec<Utf8PathBuf>,
    /// Stable identity of icon and splash bytes embedded as app resources.
    pub asset_fingerprint: String,
    /// Rust executable staging copy.
    pub rust_binary_copy: PlannedCopy,
    /// Expected unsigned `.xcarchive` output.
    pub archive_path: Utf8PathBuf,
    /// Expected unsigned `.app` inside the archive.
    pub app_path: Utf8PathBuf,
    /// Post-archive device Mach-O validation hook.
    pub macho_validation: IosDeviceMachOValidationPlan,
    /// Cross-platform structural invariants for the unsigned archive and every nested code object.
    pub archive_expectation: UnsignedXcarchiveExpectation,
}

/// Evidence that an archived executable is arm64 physical-iOS code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosDeviceMachOValidation {
    /// Validated executable path.
    pub executable_path: Utf8PathBuf,
    /// Architecture reported by `lipo`.
    pub architecture: String,
    /// Build platform reported by `vtool`.
    pub platform: String,
    /// Minimum iOS version reported by `vtool`.
    pub minimum_os: String,
    /// iPhoneOS SDK version reported by `vtool`.
    pub sdk: String,
}

/// Result of an unsigned physical-device archive operation.
#[derive(Debug)]
pub struct IosDeviceArchiveOutcome {
    /// Exact plan used by the operation.
    pub plan: IosDeviceArchivePlan,
    /// Produced archive path, absent for dry-run.
    pub archive: Option<Utf8PathBuf>,
    /// Produced application path, absent for dry-run.
    pub app: Option<Utf8PathBuf>,
    /// Physical-device Mach-O evidence, absent for dry-run.
    pub macho_validation: Option<IosDeviceMachOValidation>,
    /// Full cross-platform archive/app/nested-code evidence, absent for dry-run.
    pub archive_inspection: Option<UnsignedXcarchiveInspection>,
}

/// Produce a deterministic, side-effect-free unsigned device archive plan.
///
/// # Errors
///
/// Returns [`AppleError`] when request/config values are invalid or assets
/// cannot be loaded safely.
pub fn plan_ios_device_unsigned(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
) -> Result<IosDeviceArchivePlan, AppleError> {
    validate_request(request)?;
    let assets = ProjectAssets::load(&request.project_dir)?;
    plan_with_assets(request, toolchain, &assets)
}

/// Derive the complete client-owned product identity for a physical-iPhone request.
///
/// This helper is host-independent and does not inspect Xcode. The remote worker later compares
/// the generated archive with these pre-submission values.
///
/// # Errors
///
/// Returns [`AppleError`] when the binary name, configuration, or extension graph is invalid.
pub fn derive_ios_device_product_expectation(
    config: &FerryConfig,
    binary_name: &str,
) -> Result<IosDeviceProductExpectation, AppleError> {
    validate_binary_name(binary_name)?;
    let _ = generate_ios_project_for_platform(
        &IosProjectSpec::new(config.clone(), binary_name.to_owned()),
        IosProjectPlatform::DeviceUnsigned,
    )?;
    let mut nested_bundles = vec![UnsignedNestedBundleExpectation {
        relative_path: "Frameworks/FerryRuntimeBridge.framework".to_owned(),
        bundle_identifier: "org.rustferry.runtime-bridge".to_owned(),
        executable: "FerryRuntimeBridge".to_owned(),
        kind: UnsignedNestedBundleKind::Framework,
    }];
    if config.extensions.live_activity.enabled {
        nested_bundles.push(UnsignedNestedBundleExpectation {
            relative_path: "Frameworks/FerryActivityModel.framework".to_owned(),
            bundle_identifier: "org.rustferry.activity-model".to_owned(),
            executable: "FerryActivityModel".to_owned(),
            kind: UnsignedNestedBundleKind::Framework,
        });
        nested_bundles.push(UnsignedNestedBundleExpectation {
            relative_path: "PlugIns/FerryLiveActivityExtension.appex".to_owned(),
            bundle_identifier: format!("{}.liveactivity", config.app.identifier),
            executable: "FerryLiveActivityExtension".to_owned(),
            kind: UnsignedNestedBundleKind::AppExtension,
        });
    }
    if config.extensions.widget.enabled {
        nested_bundles.push(UnsignedNestedBundleExpectation {
            relative_path: "PlugIns/FerryWidgetExtension.appex".to_owned(),
            bundle_identifier: format!("{}.widget", config.app.identifier),
            executable: "FerryWidgetExtension".to_owned(),
            kind: UnsignedNestedBundleKind::AppExtension,
        });
    }
    nested_bundles.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let version = &config.app.version;
    Ok(IosDeviceProductExpectation {
        app_directory_name: format!("{binary_name}.app"),
        executable: binary_name.to_owned(),
        app_version: config.app.display_version.clone(),
        build_number: format!("{}.{}.{}", version.major, version.minor, version.patch),
        nested_bundles,
    })
}

fn plan_with_assets(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    assets: &ProjectAssets,
) -> Result<IosDeviceArchivePlan, AppleError> {
    if parse_apple_version(&toolchain.device_sdk.version).is_none()
        || toolchain.device_sdk.build_version.trim().is_empty()
    {
        return Err(AppleError::InvalidRequest(format!(
            "selected iPhoneOS SDK evidence is incomplete or invalid: version `{}`, build `{}`",
            toolchain.device_sdk.version, toolchain.device_sdk.build_version
        )));
    }
    let generated = generate_ios_project_for_platform(
        &IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
            .with_assets(assets.clone()),
        IosProjectPlatform::DeviceUnsigned,
    )?;
    let device_root = request
        .project_dir
        .join("target")
        .join(brand::TARGET_DIRECTORY)
        .join("ios")
        .join("device");
    let generated_root = device_root.join("generated");
    let cargo_target_dir = device_root.join("cargo");
    let profile_directory = profile_directory(request.profile);
    let xcode_derived_data = device_root.join("xcode").join(profile_directory);
    let archive_path = device_root
        .join("archives")
        .join(profile_directory)
        .join(format!("{}.xcarchive", request.binary_name));
    let app_path = archive_path
        .join("Products")
        .join("Applications")
        .join(format!("{}.app", request.binary_name));
    let cargo_binary = cargo_target_dir
        .join(IOS_DEVICE_TARGET)
        .join(profile_directory)
        .join(&request.binary_name);
    let staged_binary = generated_root.join(&request.binary_name);

    let archived_executable = app_path.join(&request.binary_name);
    let destination_preflight = xcode_destination_command(request, toolchain, &generated_root);
    let cargo = cargo_build_command(request, toolchain, &cargo_target_dir);
    let xcodebuild = xcode_archive_command(
        request,
        toolchain,
        &generated_root,
        &xcode_derived_data,
        &archive_path,
    );
    let macho_validation = macho_validation_plan(request, toolchain, archived_executable);
    let archive_expectation = archive_expectation(request, toolchain, &generated)?;

    Ok(IosDeviceArchivePlan {
        schema_version: 1,
        rust_target: IOS_DEVICE_TARGET.to_owned(),
        sdk: IOS_DEVICE_SDK.to_owned(),
        destination: IOS_GENERIC_DESTINATION.to_owned(),
        profile: request.profile,
        disposition: IosDeviceArtifactDisposition::UnsignedCompileOnly,
        generated_root,
        cargo_target_dir,
        xcode_derived_data,
        commands: vec![destination_preflight, cargo, xcodebuild],
        generated_files: generated
            .files
            .keys()
            .map(|relative| device_root.join("generated").join(relative))
            .collect(),
        asset_fingerprint: assets.fingerprint().to_owned(),
        rust_binary_copy: PlannedCopy {
            source: cargo_binary,
            destination: staged_binary,
        },
        archive_path,
        app_path,
        macho_validation,
        archive_expectation,
    })
}

fn archive_expectation(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    generated: &crate::GeneratedAppleProject,
) -> Result<UnsignedXcarchiveExpectation, AppleError> {
    let product = derive_ios_device_product_expectation(&request.config, &request.binary_name)?;

    let mut required_resources = std::collections::BTreeMap::new();
    for relative in ["FerryResources.json", "FerryIcon.png", "FerrySplash.png"] {
        let bytes = generated
            .files
            .get(Utf8Path::new(relative))
            .ok_or_else(|| {
                AppleError::InvalidRequest(format!(
                    "generated physical-iOS project omitted required resource `{relative}`"
                ))
            })?;
        required_resources.insert(relative.to_owned(), format!("{:x}", Sha256::digest(bytes)));
    }
    Ok(UnsignedXcarchiveExpectation {
        app_directory_name: product.app_directory_name,
        bundle_identifier: request.config.app.identifier.clone(),
        executable: product.executable,
        app_version: product.app_version,
        build_number: product.build_number,
        minimum_os: request.config.ios.min_version.clone(),
        sdk_version: toolchain.device_sdk.version.clone(),
        sdk_build_version: toolchain.device_sdk.build_version.clone(),
        nested_bundles: product.nested_bundles,
        required_resources,
    })
}

fn cargo_build_command(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    cargo_target_dir: &Utf8Path,
) -> CommandSpec {
    let mut command = CommandSpec::new(
        "cross-compile Rust executable for physical iOS device",
        &toolchain.cargo,
        &request.project_dir,
    );
    command.args = vec![
        "build".to_owned(),
        "--locked".to_owned(),
        "--target".to_owned(),
        IOS_DEVICE_TARGET.to_owned(),
        "--bin".to_owned(),
        request.binary_name.clone(),
    ];
    if let Some(package) = &request.package_name {
        command.args.push("--package".to_owned());
        command.args.push(package.clone());
    }
    if request.profile == AppleBuildProfile::Release {
        command.args.push("--release".to_owned());
    }
    if !request.cargo_features.is_empty() {
        command.args.push("--features".to_owned());
        command.args.push(request.cargo_features.join(","));
    }
    command
        .environment
        .insert("CARGO_TARGET_DIR".to_owned(), cargo_target_dir.to_string());
    command.environment.insert(
        "IPHONEOS_DEPLOYMENT_TARGET".to_owned(),
        request.config.ios.min_version.clone(),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command
        .environment
        .insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    command
}

fn xcode_destination_command(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    generated_root: &Utf8Path,
) -> CommandSpec {
    let mut command = CommandSpec::new(
        "preflight physical-iOS Xcode destination",
        &toolchain.xcodebuild,
        &request.project_dir,
    );
    command.args = vec![
        "-project".to_owned(),
        generated_root.join("FerryHost.xcodeproj").to_string(),
        "-scheme".to_owned(),
        "FerryApp".to_owned(),
        "-configuration".to_owned(),
        xcode_configuration(request.profile).to_owned(),
        "-sdk".to_owned(),
        IOS_DEVICE_SDK.to_owned(),
        "-showdestinations".to_owned(),
    ];
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command
        .environment
        .insert("LC_ALL".to_owned(), "C".to_owned());
    command
}

fn xcode_archive_command(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    generated_root: &Utf8Path,
    xcode_derived_data: &Utf8Path,
    archive_path: &Utf8Path,
) -> CommandSpec {
    let mut command = CommandSpec::new(
        "assemble unsigned physical-iOS Xcode archive",
        &toolchain.xcodebuild,
        &request.project_dir,
    );
    command.args = vec![
        "-project".to_owned(),
        generated_root.join("FerryHost.xcodeproj").to_string(),
        "-scheme".to_owned(),
        "FerryApp".to_owned(),
        "-configuration".to_owned(),
        xcode_configuration(request.profile).to_owned(),
        "-sdk".to_owned(),
        IOS_DEVICE_SDK.to_owned(),
        "-destination".to_owned(),
        IOS_GENERIC_DESTINATION.to_owned(),
        "-derivedDataPath".to_owned(),
        xcode_derived_data.to_string(),
        "-archivePath".to_owned(),
        archive_path.to_string(),
        "AD_HOC_CODE_SIGNING_ALLOWED=NO".to_owned(),
        "CODE_SIGN_IDENTITY=".to_owned(),
        "CODE_SIGNING_ALLOWED=NO".to_owned(),
        "CODE_SIGNING_REQUIRED=NO".to_owned(),
        "DEVELOPMENT_TEAM=".to_owned(),
        "PROVISIONING_PROFILE_SPECIFIER=".to_owned(),
        "ARCHS=arm64".to_owned(),
        "ONLY_ACTIVE_ARCH=NO".to_owned(),
        "archive".to_owned(),
    ];
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command
        .environment
        .insert("NSUnbufferedIO".to_owned(), "YES".to_owned());
    command
}

fn macho_validation_plan(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
    executable_path: Utf8PathBuf,
) -> IosDeviceMachOValidationPlan {
    IosDeviceMachOValidationPlan {
        expected_architecture: "arm64".to_owned(),
        expected_platform: "IOS".to_owned(),
        expected_minimum_os: request.config.ios.min_version.clone(),
        expected_sdk: toolchain.device_sdk.version.clone(),
        commands: vec![
            inspection_command(
                "validate physical-iOS Mach-O architecture",
                toolchain,
                &request.project_dir,
                vec![
                    "lipo".to_owned(),
                    "-archs".to_owned(),
                    executable_path.to_string(),
                ],
            ),
            inspection_command(
                "validate physical-iOS Mach-O platform",
                toolchain,
                &request.project_dir,
                vec![
                    "vtool".to_owned(),
                    "-show-build".to_owned(),
                    executable_path.to_string(),
                ],
            ),
        ],
        executable_path,
    }
}

/// Cross-compile, archive without signing, and prove the main Mach-O targets physical iOS.
///
/// The returned `.xcarchive` and `.app` are compile evidence only. They are not
/// installable until a later signing phase applies an Apple development identity
/// and matching provisioning profile.
///
/// # Errors
///
/// Returns [`AppleError`] for invalid inputs, unsafe internal paths, command
/// failures, missing archive products, or Simulator/device Mach-O confusion.
pub fn build_ios_device_unsigned(
    request: &IosDeviceArchiveRequest,
    toolchain: &IosDeviceToolchain,
) -> Result<IosDeviceArchiveOutcome, AppleError> {
    validate_request(request)?;
    let assets = ProjectAssets::load(&request.project_dir)?;
    let plan = plan_with_assets(request, toolchain, &assets)?;
    if request.dry_run {
        return Ok(IosDeviceArchiveOutcome {
            plan,
            archive: None,
            app: None,
            macho_validation: None,
            archive_inspection: None,
        });
    }

    let logs = request
        .project_dir
        .join("target")
        .join(brand::TARGET_DIRECTORY)
        .join("ios")
        .join("device")
        .join("logs")
        .join(profile_directory(request.profile));
    execute_unsigned_archive(request, &assets, &plan, &logs)?;
    let (archive_inspection, macho_validation) =
        inspect_unsigned_archive_output(request, &plan, &logs)?;

    Ok(IosDeviceArchiveOutcome {
        archive: Some(plan.archive_path.clone()),
        app: Some(plan.app_path.clone()),
        macho_validation: Some(macho_validation),
        archive_inspection: Some(archive_inspection),
        plan,
    })
}

fn execute_unsigned_archive(
    request: &IosDeviceArchiveRequest,
    assets: &ProjectAssets,
    plan: &IosDeviceArchivePlan,
    logs: &Utf8Path,
) -> Result<(), AppleError> {
    for directory in [
        &plan.cargo_target_dir,
        logs,
        plan.archive_path.parent().unwrap_or(&plan.archive_path),
    ] {
        prepare_directory(&request.project_dir, directory)?;
    }

    reset_directory(&request.project_dir, &plan.generated_root)?;
    write_trusted_generated_project(request, assets, &plan.generated_root)?;
    let destination = run_command(
        &plan.commands[0],
        Some(&logs.join("00-xcode-destination-preflight.log")),
    )?;
    validate_device_destination(&destination.stdout, &plan.commands[0].program)?;

    run_command(&plan.commands[1], Some(&logs.join("01-cargo-build.log")))?;
    validate_regular_file(
        &plan.rust_binary_copy.source,
        "Cargo-produced physical-iOS executable",
    )?;
    for directory in [
        logs,
        plan.archive_path.parent().unwrap_or(&plan.archive_path),
    ] {
        prepare_directory(&request.project_dir, directory)?;
    }
    reset_directory(&request.project_dir, &plan.xcode_derived_data)?;

    // Cargo build scripts are project-controlled. Recreate trusted Xcode input
    // only after Cargo exits so they cannot persistently alter the generated host.
    reset_directory(&request.project_dir, &plan.generated_root)?;
    write_trusted_generated_project(request, assets, &plan.generated_root)?;
    fs::copy(
        &plan.rust_binary_copy.source,
        &plan.rust_binary_copy.destination,
    )
    .map_err(|source| {
        io_error(
            "stage physical-iOS Rust executable for Xcode",
            &plan.rust_binary_copy.destination,
            source,
        )
    })?;
    make_executable(&plan.rust_binary_copy.destination)?;

    remove_stale_archive(&request.project_dir, &plan.archive_path)?;
    run_command(
        &plan.commands[2],
        Some(&logs.join("02-xcodebuild-archive.log")),
    )?;
    Ok(())
}

fn write_trusted_generated_project(
    request: &IosDeviceArchiveRequest,
    assets: &ProjectAssets,
    generated_root: &Utf8Path,
) -> Result<(), AppleError> {
    let generated = generate_ios_project_for_platform(
        &IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
            .with_assets(assets.clone()),
        IosProjectPlatform::DeviceUnsigned,
    )?;
    write_ios_project(&generated, generated_root)
}

fn inspect_unsigned_archive_output(
    request: &IosDeviceArchiveRequest,
    plan: &IosDeviceArchivePlan,
    logs: &Utf8Path,
) -> Result<(UnsignedXcarchiveInspection, IosDeviceMachOValidation), AppleError> {
    reject_symlink_components(&request.project_dir, &plan.archive_path)?;
    reject_symlink_components(&request.project_dir, &plan.macho_validation.executable_path)?;
    validate_real_directory(&plan.archive_path, "unsigned Xcode archive")?;
    validate_regular_file(&plan.archive_path.join("Info.plist"), "archive Info.plist")?;
    validate_real_directory(&plan.app_path, "unsigned archived application")?;
    validate_regular_file(
        &plan.macho_validation.executable_path,
        "archived application executable",
    )?;
    let archive_inspection =
        inspect_unsigned_xcarchive(&plan.archive_path, &plan.archive_expectation).map_err(
            |error| AppleError::InvalidArtifact {
                path: plan.archive_path.clone(),
                reason: error.to_string(),
            },
        )?;

    let architecture_output = run_command(
        &plan.macho_validation.commands[0],
        Some(&logs.join("03-lipo-architecture.log")),
    )?;
    let architecture = validate_architecture(
        &architecture_output.stdout,
        &plan.macho_validation.expected_architecture,
        &plan.macho_validation.executable_path,
    )?;
    let platform_output = run_command(
        &plan.macho_validation.commands[1],
        Some(&logs.join("04-vtool-platform.log")),
    )?;
    let (platform, minimum_os, sdk) = validate_platform(
        &platform_output.stdout,
        &plan.macho_validation.expected_platform,
        &plan.macho_validation.expected_minimum_os,
        &plan.macho_validation.expected_sdk,
        &plan.macho_validation.executable_path,
    )?;
    Ok((
        archive_inspection,
        IosDeviceMachOValidation {
            executable_path: plan.macho_validation.executable_path.clone(),
            architecture,
            platform,
            minimum_os,
            sdk,
        },
    ))
}

fn inspection_command(
    stage: &str,
    toolchain: &IosDeviceToolchain,
    project_dir: &Utf8Path,
    args: Vec<String>,
) -> CommandSpec {
    let mut command = CommandSpec::new(stage, &toolchain.xcrun, project_dir);
    command.args = args;
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command
}

fn validate_request(request: &IosDeviceArchiveRequest) -> Result<(), AppleError> {
    validate_binary_name(&request.binary_name)?;
    if !request.project_dir.is_dir() {
        return Err(AppleError::InvalidRequest(format!(
            "project directory does not exist: {}",
            request.project_dir
        )));
    }
    if !request.project_dir.join("Cargo.toml").is_file() {
        return Err(AppleError::InvalidRequest(format!(
            "Cargo.toml was not found in project directory {}",
            request.project_dir
        )));
    }
    if let Some(package) = &request.package_name {
        validate_cargo_selector("package", package)?;
    }
    for feature in &request.cargo_features {
        validate_cargo_selector("feature", feature)?;
    }
    let _ = generate_ios_project_for_platform(
        &IosProjectSpec::new(request.config.clone(), request.binary_name.clone()),
        IosProjectPlatform::DeviceUnsigned,
    )?;
    Ok(())
}

fn validate_binary_name(name: &str) -> Result<(), AppleError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppleError::InvalidRequest(format!(
            "binary name `{name}` must contain only ASCII letters, digits, `-`, or `_`"
        )));
    }
    Ok(())
}

fn validate_cargo_selector(kind: &str, value: &str) -> Result<(), AppleError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppleError::InvalidRequest(format!(
            "Cargo {kind} `{value}` must contain only ASCII letters, digits, `-`, or `_`"
        )));
    }
    Ok(())
}

const fn profile_directory(profile: AppleBuildProfile) -> &'static str {
    match profile {
        AppleBuildProfile::Debug => "debug",
        AppleBuildProfile::Release => "release",
    }
}

const fn xcode_configuration(profile: AppleBuildProfile) -> &'static str {
    match profile {
        AppleBuildProfile::Debug => "Debug",
        AppleBuildProfile::Release => "Release",
    }
}

fn validate_architecture(
    output: &[u8],
    expected: &str,
    executable: &Utf8Path,
) -> Result<String, AppleError> {
    let output = std::str::from_utf8(output).map_err(|_| AppleError::InvalidArtifact {
        path: executable.to_owned(),
        reason: "`lipo -archs` emitted non-UTF-8 output".to_owned(),
    })?;
    let architectures = output.split_whitespace().collect::<Vec<_>>();
    if architectures != [expected] {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!(
                "archived Mach-O architectures are {architectures:?}, expected only `{expected}`"
            ),
        });
    }
    Ok(expected.to_owned())
}

fn validate_platform(
    output: &[u8],
    expected_platform: &str,
    expected_minimum_os: &str,
    expected_sdk: &str,
    executable: &Utf8Path,
) -> Result<(String, String, String), AppleError> {
    let output = std::str::from_utf8(output).map_err(|_| AppleError::InvalidArtifact {
        path: executable.to_owned(),
        reason: "`vtool -show-build` emitted non-UTF-8 output".to_owned(),
    })?;
    let platforms = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("platform "))
        .collect::<Vec<_>>();
    let minimum_versions = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("minos "))
        .collect::<Vec<_>>();
    let sdk_versions = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("sdk "))
        .collect::<Vec<_>>();
    if platforms != [expected_platform] {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!(
                "archived Mach-O build platforms are {platforms:?}, expected only `{expected_platform}`; Simulator output is not a physical-device artifact"
            ),
        });
    }
    let [minimum_os] = minimum_versions.as_slice() else {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!(
                "archived Mach-O minimum-OS evidence is {minimum_versions:?}, expected exactly one numeric value"
            ),
        });
    };
    let [sdk] = sdk_versions.as_slice() else {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!(
                "archived Mach-O SDK evidence is {sdk_versions:?}, expected exactly one numeric value"
            ),
        });
    };
    if parse_apple_version(minimum_os) != parse_apple_version(expected_minimum_os) {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!(
                "archived Mach-O minimum OS is `{minimum_os}`, expected `{expected_minimum_os}`"
            ),
        });
    }
    if parse_apple_version(sdk) != parse_apple_version(expected_sdk) {
        return Err(AppleError::InvalidArtifact {
            path: executable.to_owned(),
            reason: format!("archived Mach-O SDK is `{sdk}`, expected `{expected_sdk}`"),
        });
    }
    Ok((
        expected_platform.to_owned(),
        (*minimum_os).to_owned(),
        (*sdk).to_owned(),
    ))
}

fn validate_device_destination(output: &[u8], xcodebuild: &Utf8Path) -> Result<(), AppleError> {
    let output = std::str::from_utf8(output).map_err(|_| AppleError::InvalidArtifact {
        path: xcodebuild.to_owned(),
        reason: "`xcodebuild -showdestinations` emitted non-UTF-8 output".to_owned(),
    })?;
    let available = output
        .split_once("Available destinations for")
        .map(|(_, suffix)| suffix)
        .and_then(|suffix| suffix.split("Ineligible destinations for").next())
        .unwrap_or_default();
    let eligible = available.lines().any(|line| {
        let line = line.trim();
        line.starts_with('{')
            && line.ends_with('}')
            && line.contains("platform:iOS")
            && (line.contains("name:Any iOS Device") || line.contains("generic:1"))
            && !line.contains("error:")
    });
    if !eligible {
        return Err(AppleError::InvalidRequest(
            "Xcode reports no eligible generic physical-iOS destination. Install the matching iOS platform in Xcode Settings > Components; an SDK directory alone is insufficient."
                .to_owned(),
        ));
    }
    Ok(())
}

fn parse_apple_version(value: &str) -> Option<[u32; 3]> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    let mut version = [0_u32; 3];
    for (index, component) in components.iter().enumerate() {
        version[index] = component.parse().ok()?;
    }
    Some(version)
}

fn prepare_directory(project_dir: &Utf8Path, directory: &Utf8Path) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_descendant(&ferry_root, directory)?;
    reject_symlink_components(project_dir, directory)?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AppleError::UnsafeGeneratedPath {
                path: directory.to_owned(),
                reason: "internal device build output must be a real directory".to_owned(),
            });
        }
        Ok(_) => return Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect physical-iOS output directory",
                directory,
                source,
            ));
        }
    }
    fs::create_dir_all(directory)
        .map_err(|source| io_error("create physical-iOS output directory", directory, source))
}

fn reset_directory(project_dir: &Utf8Path, directory: &Utf8Path) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_descendant(&ferry_root, directory)?;
    reject_symlink_components(project_dir, directory)?;
    if directory.exists() {
        validate_real_directory(directory, "generated physical-iOS project")?;
        fs::remove_dir_all(directory).map_err(|source| {
            io_error("replace generated physical-iOS project", directory, source)
        })?;
    }
    fs::create_dir_all(directory)
        .map_err(|source| io_error("create generated physical-iOS project", directory, source))
}

fn remove_stale_archive(project_dir: &Utf8Path, archive: &Utf8Path) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_descendant(&ferry_root, archive)?;
    reject_symlink_components(project_dir, archive.parent().unwrap_or(archive))?;
    match fs::symlink_metadata(archive) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AppleError::UnsafeGeneratedPath {
                path: archive.to_owned(),
                reason: "stale physical-iOS archive must be a real directory".to_owned(),
            });
        }
        Ok(_) => {
            fs::remove_dir_all(archive)
                .map_err(|source| io_error("remove stale physical-iOS archive", archive, source))?;
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect stale physical-iOS archive",
                archive,
                source,
            ));
        }
    }
    Ok(())
}

fn ensure_descendant(root: &Utf8Path, path: &Utf8Path) -> Result<(), AppleError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: format!("path is outside internal root `{root}`"),
        })?;
    if relative.as_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Utf8Component::Normal(_)))
    {
        return Err(AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: "path must be a non-empty normalized descendant".to_owned(),
        });
    }
    Ok(())
}

fn reject_symlink_components(root: &Utf8Path, path: &Utf8Path) -> Result<(), AppleError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: format!("path is outside project root `{root}`"),
        })?;
    let mut current = root.to_owned();
    for component in relative.components() {
        let Utf8Component::Normal(component) = component else {
            return Err(AppleError::UnsafeGeneratedPath {
                path: path.to_owned(),
                reason: "path contains a traversal component".to_owned(),
            });
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AppleError::UnsafeGeneratedPath {
                    path: current,
                    reason: "internal device build output cannot traverse a symbolic link"
                        .to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(io_error(
                    "inspect physical-iOS internal path",
                    &current,
                    source,
                ));
            }
        }
    }
    Ok(())
}

fn validate_real_directory(path: &Utf8Path, kind: &str) -> Result<(), AppleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect physical-iOS archive directory", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppleError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("{kind} is not a real directory"),
        });
    }
    Ok(())
}

fn validate_regular_file(path: &Utf8Path, kind: &str) -> Result<(), AppleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect physical-iOS artifact file", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppleError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("{kind} is not a regular file"),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Utf8Path) -> Result<(), AppleError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| io_error("inspect staged physical-iOS executable", path, source))?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions).map_err(|source| {
        io_error(
            "mark staged physical-iOS executable executable",
            path,
            source,
        )
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Utf8Path) -> Result<(), AppleError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_parser_rejects_extra_slices() {
        let executable = Utf8Path::new("Weather.app/weather");
        assert_eq!(
            validate_architecture(b"arm64\n", "arm64", executable).unwrap(),
            "arm64"
        );
        assert!(
            validate_architecture(
                b"Architectures in the fat file: weather are: arm64 x86_64\n",
                "arm64",
                executable
            )
            .is_err()
        );
    }

    #[test]
    fn platform_parser_rejects_simulator_and_unproven_binaries() {
        let executable = Utf8Path::new("Weather.app/weather");
        assert_eq!(
            validate_platform(
                b"Load command 1\n      platform IOS\n        minos 16.0\n          sdk 26.0\n",
                "IOS",
                "16.0",
                "26.0",
                executable
            )
            .unwrap(),
            ("IOS".to_owned(), "16.0".to_owned(), "26.0".to_owned())
        );
        assert!(
            validate_platform(
                b"Load command 1\n      platform IOSSIMULATOR\n        minos 16.0\n          sdk 26.0\n",
                "IOS",
                "16.0",
                "26.0",
                executable
            )
            .is_err()
        );
        assert!(
            validate_platform(
                b"LC_VERSION_MIN_IPHONEOS\n",
                "IOS",
                "16.0",
                "26.0",
                executable
            )
            .is_err()
        );
        assert!(
            validate_platform(
                b"Load command 1\n      platform IOS\n        minos 15.0\n          sdk 26.0\n",
                "IOS",
                "16.0",
                "26.0",
                executable
            )
            .is_err()
        );
    }

    #[test]
    fn destination_parser_requires_eligible_generic_iphoneos() {
        let xcodebuild = Utf8Path::new("/Applications/Xcode.app/xcodebuild");
        let eligible = b"Available destinations for the \"FerryApp\" scheme:\n\t{ platform:iOS, arch:arm64, id:dvtdevice-DVTiPhonePlaceholder-iphoneos:placeholder, name:Any iOS Device }\n";
        validate_device_destination(eligible, xcodebuild).unwrap();

        let missing_component = b"Available destinations for the \"FerryApp\" scheme:\n\nIneligible destinations for the \"FerryApp\" scheme:\n\t{ platform:iOS, id:dvtdevice-DVTiPhonePlaceholder-iphoneos:placeholder, name:Any iOS Device, error:iOS 26.5 is not installed. }\n";
        assert!(validate_device_destination(missing_component, xcodebuild).is_err());
        assert!(validate_device_destination(b"", xcodebuild).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stale_archive_rejects_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let project = Utf8Path::from_path(temporary.path()).unwrap();
        let archive = project.join("target/ferry/ios/device/archives/release/app.xcarchive");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        symlink(project.join("missing-outside"), &archive).unwrap();

        assert!(matches!(
            remove_stale_archive(project, &archive),
            Err(AppleError::UnsafeGeneratedPath { .. })
        ));
    }
}
