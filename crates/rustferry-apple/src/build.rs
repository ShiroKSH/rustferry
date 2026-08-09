use std::{fmt, fs};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_codegen::generate_platform_assets;
use rustferry_core::{FerryConfig, ProjectAssets, brand};
use serde::{Deserialize, Serialize};

use crate::{
    AppleDiscoveryOptions, AppleError, AppleToolchain, CommandSpec, IOS_SIMULATOR_TARGET,
    IosArtifactExpectation, IosArtifactValidation, IosAssetPackaging, IosExtensionExpectation,
    IosProjectSpec, discover_apple,
    error::io_error,
    generate_ios_project,
    project::{generate_ios_project_from_asset_set, validate_binary_name},
    run_command, validate_ios_app, write_ios_project,
};

/// Cargo/Xcode build profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppleBuildProfile {
    /// Unoptimized development artifact.
    #[default]
    Debug,
    /// Optimized distribution-style artifact without device signing.
    Release,
}

impl AppleBuildProfile {
    fn cargo_directory(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    fn xcode_configuration(self) -> &'static str {
        match self {
            Self::Debug => "Debug",
            Self::Release => "Release",
        }
    }
}

/// Apple extension family generated as a native Xcode target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExtensionKind {
    /// `WidgetKit` home-screen widget.
    WidgetKit,
    /// `ActivityKit` Live Activity and Dynamic Island presentation.
    ActivityKit,
}

impl fmt::Display for ExtensionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WidgetKit => formatter.write_str("WidgetKit extension"),
            Self::ActivityKit => formatter.write_str("ActivityKit extension"),
        }
    }
}

/// Inputs for a build-only iOS Simulator application.
#[derive(Clone, Debug, PartialEq)]
pub struct IosSimulatorBuildRequest {
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
    /// Plan only; perform no writes or subprocess execution after discovery.
    pub dry_run: bool,
}

impl IosSimulatorBuildRequest {
    /// Construct a debug simulator request using Cargo's selected package.
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
            profile: AppleBuildProfile::Debug,
            cargo_features: Vec::new(),
            dry_run: false,
        }
    }
}

/// One internal file copy represented explicitly in a dry-run plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlannedCopy {
    /// Existing Cargo-produced file.
    pub source: Utf8PathBuf,
    /// Destination consumed by the generated Xcode build phase.
    pub destination: Utf8PathBuf,
}

/// Complete, serializable simulator command and generated-file plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosBuildPlan {
    /// Stable plan schema version.
    pub schema_version: u32,
    /// Rust compilation target.
    pub rust_target: String,
    /// Build profile.
    pub profile: AppleBuildProfile,
    /// Internal generated Xcode root.
    pub generated_root: Utf8PathBuf,
    /// Isolated Cargo target directory.
    pub cargo_target_dir: Utf8PathBuf,
    /// Xcode `DerivedData` directory.
    pub xcode_derived_data: Utf8PathBuf,
    /// Redacted command specifications, executed in order.
    pub commands: Vec<CommandSpec>,
    /// Deterministic generated file paths.
    pub generated_files: Vec<Utf8PathBuf>,
    /// Stable identity of the icon and splash bytes embedded as app resources.
    pub asset_fingerprint: String,
    /// Asset representation selected from installed Simulator capabilities.
    pub asset_packaging: IosAssetPackaging,
    /// Rust executable staging copy.
    pub rust_binary_copy: PlannedCopy,
    /// Expected final `.app` bundle.
    pub artifact_path: Utf8PathBuf,
}

/// Build result. Dry-run results deliberately contain no artifact or validation claim.
#[derive(Debug)]
pub struct IosBuildOutcome {
    /// Exact plan used by the operation.
    plan: IosBuildPlan,
    /// Built application path, absent for dry-run.
    artifact: Option<Utf8PathBuf>,
    /// Independent metadata/binary validation, absent for dry-run.
    validation: Option<IosArtifactValidation>,
}

impl IosBuildOutcome {
    /// Exact plan used by the operation.
    #[must_use]
    pub const fn plan(&self) -> &IosBuildPlan {
        &self.plan
    }

    /// Built application path, absent for dry-run.
    #[must_use]
    pub fn artifact(&self) -> Option<&Utf8Path> {
        self.artifact.as_deref()
    }

    /// Independent metadata and binary validation, absent for dry-run.
    #[must_use]
    pub const fn validation(&self) -> Option<&IosArtifactValidation> {
        self.validation.as_ref()
    }
}

/// Produce a deterministic, side-effect-free command plan using an already selected toolchain.
///
/// # Errors
///
/// Returns [`AppleError`] when request/config values are invalid or cannot be
/// represented safely in Cargo, plist, or Xcode inputs.
#[allow(clippy::too_many_lines)]
pub fn plan_ios_simulator(
    request: &IosSimulatorBuildRequest,
    toolchain: &AppleToolchain,
) -> Result<IosBuildPlan, AppleError> {
    validate_request(request)?;
    let assets = ProjectAssets::load(&request.project_dir)?;
    plan_ios_simulator_with_assets(request, toolchain, &assets)
}

#[allow(clippy::too_many_lines)]
fn plan_ios_simulator_with_assets(
    request: &IosSimulatorBuildRequest,
    toolchain: &AppleToolchain,
    assets: &ProjectAssets,
) -> Result<IosBuildPlan, AppleError> {
    let asset_packaging = if toolchain.simulator_runtime_available {
        IosAssetPackaging::CompiledCatalog
    } else {
        IosAssetPackaging::SdkOnlyResources
    };
    let generated = generate_ios_project(
        &IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
            .with_assets(assets.clone())
            .with_asset_packaging(asset_packaging),
    )?;
    let ios_root = request
        .project_dir
        .join("target")
        .join(brand::TARGET_DIRECTORY)
        .join("ios");
    let generated_root = ios_root.join("generated");
    let cargo_target_dir = ios_root.join("cargo");
    let asset_cache_directory = match asset_packaging {
        IosAssetPackaging::CompiledCatalog => "compiled-catalog",
        IosAssetPackaging::SdkOnlyResources => "sdk-only-resources",
    };
    let xcode_derived_data = ios_root
        .join("xcode")
        .join(request.profile.cargo_directory())
        .join(asset_cache_directory);
    let artifact_directory = ios_root.join(request.profile.cargo_directory());
    let artifact_path = artifact_directory.join(format!("{}.app", request.binary_name));
    let cargo_binary = cargo_target_dir
        .join(IOS_SIMULATOR_TARGET)
        .join(request.profile.cargo_directory())
        .join(&request.binary_name);
    let staged_binary = generated_root.join(&request.binary_name);

    let mut cargo = CommandSpec::new(
        "cross-compile Rust executable for iOS Simulator",
        &toolchain.cargo,
        &request.project_dir,
    );
    cargo.args = vec![
        "build".to_owned(),
        "--target".to_owned(),
        IOS_SIMULATOR_TARGET.to_owned(),
        "--bin".to_owned(),
        request.binary_name.clone(),
    ];
    if let Some(package) = &request.package_name {
        cargo.args.push("--package".to_owned());
        cargo.args.push(package.clone());
    }
    if request.profile == AppleBuildProfile::Release {
        cargo.args.push("--release".to_owned());
    }
    if !request.cargo_features.is_empty() {
        cargo.args.push("--features".to_owned());
        cargo.args.push(request.cargo_features.join(","));
    }
    cargo
        .environment
        .insert("CARGO_TARGET_DIR".to_owned(), cargo_target_dir.to_string());
    cargo.environment.insert(
        "IPHONEOS_DEPLOYMENT_TARGET".to_owned(),
        request.config.ios.min_version.clone(),
    );
    cargo.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    cargo
        .environment
        .insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());

    let mut xcodebuild = CommandSpec::new(
        "assemble and ad-hoc sign iOS Simulator application",
        &toolchain.xcodebuild,
        &request.project_dir,
    );
    xcodebuild.args = vec![
        "-project".to_owned(),
        generated_root.join("FerryHost.xcodeproj").to_string(),
        "-target".to_owned(),
        "FerryApp".to_owned(),
        "-configuration".to_owned(),
        request.profile.xcode_configuration().to_owned(),
        "-sdk".to_owned(),
        "iphonesimulator".to_owned(),
        "AD_HOC_CODE_SIGNING_ALLOWED=YES".to_owned(),
        "CODE_SIGN_IDENTITY=-".to_owned(),
        "CODE_SIGNING_ALLOWED=YES".to_owned(),
        "CODE_SIGNING_REQUIRED=YES".to_owned(),
        "ARCHS=arm64".to_owned(),
        "ONLY_ACTIVE_ARCH=NO".to_owned(),
        format!("SYMROOT={xcode_derived_data}"),
        format!("OBJROOT={}", xcode_derived_data.join("Intermediates")),
        format!("CONFIGURATION_BUILD_DIR={artifact_directory}"),
        "build".to_owned(),
    ];
    xcodebuild.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    xcodebuild
        .environment
        .insert("NSUnbufferedIO".to_owned(), "YES".to_owned());

    let mut commands = vec![cargo, xcodebuild];
    if request.config.extensions.widget.enabled
        && request.config.extensions.widget.app_group.is_some()
    {
        commands.push(entitlement_resign_command(
            "re-sign WidgetKit extension with application-group entitlements",
            toolchain,
            &request.project_dir,
            &generated_root.join("WidgetExtension/Widget.entitlements"),
            &artifact_path.join("PlugIns/FerryWidgetExtension.appex"),
        ));
        commands.push(entitlement_resign_command(
            "re-sign iOS Simulator application with application-group entitlements",
            toolchain,
            &request.project_dir,
            &generated_root.join("App.entitlements"),
            &artifact_path,
        ));
    }

    let generated_files = generated
        .files
        .keys()
        .map(|relative| generated_root.join(relative))
        .collect();
    Ok(IosBuildPlan {
        schema_version: 2,
        rust_target: IOS_SIMULATOR_TARGET.to_owned(),
        profile: request.profile,
        generated_root,
        cargo_target_dir,
        xcode_derived_data,
        commands,
        generated_files,
        asset_fingerprint: assets.fingerprint().to_owned(),
        asset_packaging,
        rust_binary_copy: PlannedCopy {
            source: cargo_binary,
            destination: staged_binary,
        },
        artifact_path,
    })
}

/// Cross-compile the Rust executable, assemble a real `.app`, and validate it.
///
/// # Errors
///
/// Returns [`AppleError`] for invalid inputs, missing toolchain components,
/// command failures/timeouts, unsafe generated paths, I/O failures, or an
/// artifact that fails independent validation.
pub fn build_ios_simulator(
    request: &IosSimulatorBuildRequest,
) -> Result<IosBuildOutcome, AppleError> {
    validate_request(request)?;
    let discovery = discover_apple(&AppleDiscoveryOptions {
        current_dir: request.project_dir.clone(),
        ..AppleDiscoveryOptions::from_environment()
    })?;
    let toolchain = discovery.select_toolchain()?;
    let project_assets = ProjectAssets::load(&request.project_dir)?;
    let plan = plan_ios_simulator_with_assets(request, &toolchain, &project_assets)?;
    if request.dry_run {
        return Ok(IosBuildOutcome {
            plan,
            artifact: None,
            validation: None,
        });
    }
    let logs = request
        .project_dir
        .join("target")
        .join(brand::TARGET_DIRECTORY)
        .join("ios")
        .join("logs")
        .join(request.profile.cargo_directory());
    for directory in [
        &plan.cargo_target_dir,
        &plan.xcode_derived_data,
        &logs,
        plan.artifact_path.parent().unwrap_or(&plan.artifact_path),
    ] {
        prepare_output_directory(&request.project_dir, directory)?;
    }
    prepare_generated_root(&request.project_dir, &plan.generated_root)?;
    let project_spec = IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
        .with_assets(project_assets.clone())
        .with_asset_packaging(plan.asset_packaging);
    let generated = match plan.asset_packaging {
        IosAssetPackaging::CompiledCatalog => {
            let generated_assets = generate_platform_assets(&request.project_dir, None)?;
            generate_ios_project_from_asset_set(&project_spec, &generated_assets)?
        }
        IosAssetPackaging::SdkOnlyResources => generate_ios_project(&project_spec)?,
    };
    write_ios_project(&generated, &plan.generated_root)?;

    run_command(&plan.commands[0], Some(&logs.join("01-cargo-build.log")))?;
    if !plan.rust_binary_copy.source.is_file() {
        return Err(AppleError::InvalidArtifact {
            path: plan.rust_binary_copy.source.clone(),
            reason: format!(
                "Cargo succeeded but did not produce binary `{}` for target {IOS_SIMULATOR_TARGET}",
                request.binary_name
            ),
        });
    }
    fs::copy(
        &plan.rust_binary_copy.source,
        &plan.rust_binary_copy.destination,
    )
    .map_err(|source| {
        io_error(
            "stage Rust executable for Xcode",
            &plan.rust_binary_copy.destination,
            source,
        )
    })?;
    #[cfg(unix)]
    make_executable(&plan.rust_binary_copy.destination)?;

    remove_stale_artifact(&request.project_dir, &plan.artifact_path)?;
    run_command(&plan.commands[1], Some(&logs.join("02-xcodebuild.log")))?;
    for (index, command) in plan.commands.iter().enumerate().skip(2) {
        run_command(
            command,
            Some(&logs.join(format!("{:02}-post-xcode-sign.log", index + 1))),
        )?;
    }
    let validation = validate_ios_app(
        &IosArtifactExpectation {
            app_path: plan.artifact_path.clone(),
            bundle_identifier: request.config.app.identifier.clone(),
            executable_name: request.binary_name.clone(),
            rust_binary: Some(plan.rust_binary_copy.source.clone()),
            expected_architectures: vec!["arm64".to_owned()],
            extensions: extension_expectations(&request.config),
            deep_link_schemes: request.config.capabilities.deep_links.schemes.clone(),
            app_group: request
                .config
                .extensions
                .widget
                .enabled
                .then(|| request.config.extensions.widget.app_group.clone())
                .flatten(),
            log_dir: Some(logs.join("validation")),
            project_assets: Some(project_assets),
            asset_packaging: Some(plan.asset_packaging),
        },
        &toolchain,
    )?;
    Ok(IosBuildOutcome {
        artifact: Some(plan.artifact_path.clone()),
        plan,
        validation: Some(validation),
    })
}

fn entitlement_resign_command(
    stage: &str,
    toolchain: &AppleToolchain,
    project_dir: &Utf8Path,
    entitlements: &Utf8Path,
    bundle: &Utf8Path,
) -> CommandSpec {
    let mut command = CommandSpec::new(stage, &toolchain.xcrun, project_dir);
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec![
        "codesign".to_owned(),
        "--force".to_owned(),
        "--sign".to_owned(),
        "-".to_owned(),
        "--entitlements".to_owned(),
        entitlements.to_string(),
        "--timestamp=none".to_owned(),
        "--generate-entitlement-der".to_owned(),
        bundle.to_string(),
    ];
    command
}

fn validate_request(request: &IosSimulatorBuildRequest) -> Result<(), AppleError> {
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
    let _ = generate_ios_project(&IosProjectSpec::new(
        request.config.clone(),
        request.binary_name.clone(),
    ))?;
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

fn extension_expectations(config: &FerryConfig) -> Vec<IosExtensionExpectation> {
    let mut extensions = Vec::new();
    if config.extensions.widget.enabled {
        extensions.push(IosExtensionExpectation {
            kind: ExtensionKind::WidgetKit,
            bundle_name: "FerryWidgetExtension".to_owned(),
            bundle_identifier: format!("{}.widget", config.app.identifier),
            executable_name: "FerryWidgetExtension".to_owned(),
            app_group: config.extensions.widget.app_group.clone(),
        });
    }
    if config.extensions.live_activity.enabled {
        extensions.push(IosExtensionExpectation {
            kind: ExtensionKind::ActivityKit,
            bundle_name: "FerryLiveActivityExtension".to_owned(),
            bundle_identifier: format!("{}.liveactivity", config.app.identifier),
            executable_name: "FerryLiveActivityExtension".to_owned(),
            app_group: None,
        });
    }
    extensions
}

fn prepare_generated_root(
    project_dir: &Utf8Path,
    generated_root: &Utf8Path,
) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_exact_descendant(&ferry_root, generated_root)?;
    reject_symlink_components(project_dir, &ferry_root)?;
    if generated_root.exists() {
        let metadata = fs::symlink_metadata(generated_root)
            .map_err(|source| io_error("inspect generated iOS root", generated_root, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppleError::UnsafeGeneratedPath {
                path: generated_root.to_owned(),
                reason: "expected a real generated directory before replacement".to_owned(),
            });
        }
        fs::remove_dir_all(generated_root).map_err(|source| {
            io_error("replace generated iOS directory", generated_root, source)
        })?;
    }
    fs::create_dir_all(generated_root)
        .map_err(|source| io_error("create generated iOS directory", generated_root, source))
}

fn prepare_output_directory(
    project_dir: &Utf8Path,
    directory: &Utf8Path,
) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_exact_descendant(&ferry_root, directory)?;
    reject_symlink_components(project_dir, directory)?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AppleError::UnsafeGeneratedPath {
                path: directory.to_owned(),
                reason: "internal build output must be a real directory".to_owned(),
            });
        }
        Ok(_) => return Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspect iOS output directory", directory, source)),
    }
    fs::create_dir_all(directory)
        .map_err(|source| io_error("create iOS output directory", directory, source))?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|source| io_error("inspect created iOS output directory", directory, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppleError::UnsafeGeneratedPath {
            path: directory.to_owned(),
            reason: "created internal build output is not a real directory".to_owned(),
        });
    }
    Ok(())
}

fn remove_stale_artifact(project_dir: &Utf8Path, artifact: &Utf8Path) -> Result<(), AppleError> {
    let ferry_root = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    ensure_exact_descendant(&ferry_root, artifact)?;
    reject_symlink_components(project_dir, artifact.parent().unwrap_or(artifact))?;
    if artifact.exists() {
        let metadata = fs::symlink_metadata(artifact)
            .map_err(|source| io_error("inspect stale iOS artifact", artifact, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppleError::UnsafeGeneratedPath {
                path: artifact.to_owned(),
                reason: "stale artifact is not a real application directory".to_owned(),
            });
        }
        fs::remove_dir_all(artifact)
            .map_err(|source| io_error("remove stale iOS artifact", artifact, source))?;
    }
    Ok(())
}

fn ensure_exact_descendant(root: &Utf8Path, path: &Utf8Path) -> Result<(), AppleError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: format!("path is outside internal root `{root}`"),
        })?;
    if relative.as_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, camino::Utf8Component::Normal(_)))
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
        let camino::Utf8Component::Normal(component) = component else {
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
                    reason: "internal build output cannot traverse a symbolic link".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(io_error("inspect internal build path", &current, source)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Utf8Path) -> Result<(), AppleError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| io_error("inspect staged Rust executable", path, source))?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions)
        .map_err(|source| io_error("mark staged Rust binary executable", path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimulatorSdk, generate_ios_project};

    mod png_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/opaque_png.rs"
        ));
    }

    use png_fixture::OPAQUE_1024_PNG as PNG;

    fn fake_toolchain(root: &Utf8Path) -> AppleToolchain {
        AppleToolchain {
            developer_dir: root.join("Xcode.app/Contents/Developer"),
            xcode_version: "Xcode 26.0".into(),
            simulator_sdk: SimulatorSdk {
                path: root.join("iPhoneSimulator.sdk"),
                version: "26.0".into(),
                build_version: Some("23A1".into()),
            },
            simulator_runtime_available: true,
            cargo: root.join("bin/cargo"),
            rustup: root.join("bin/rustup"),
            xcodebuild: root.join("bin/xcodebuild"),
            xcrun: root.join("bin/xcrun"),
            plutil: root.join("bin/plutil"),
            host_arch: "aarch64".into(),
        }
    }

    fn request(root: &Utf8Path) -> IosSimulatorBuildRequest {
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='weather'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        IosSimulatorBuildRequest::new(
            root,
            FerryConfig::starter("Weather", "com.example.weather"),
            "weather",
        )
    }

    fn png_with_text_chunk(png: &[u8]) -> Vec<u8> {
        const TEXT_CHUNK: &[u8] = &[
            0, 0, 0, 3, b't', b'E', b'X', b't', b'x', 0, b'y', 0x45, 0xdb, 0xf3, 0x28,
        ];
        let iend_offset = png.len().checked_sub(12).expect("PNG IEND chunk");
        let mut changed = png[..iend_offset].to_vec();
        changed.extend_from_slice(TEXT_CHUNK);
        changed.extend_from_slice(&png[iend_offset..]);
        changed
    }

    #[test]
    fn dry_run_plan_uses_argument_arrays_and_internal_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let plan = plan_ios_simulator(&request(root), &fake_toolchain(root)).unwrap();
        assert_eq!(plan.commands.len(), 2);
        assert_eq!(plan.commands[0].args[0], "build");
        assert_eq!(plan.commands[0].args[2], IOS_SIMULATOR_TARGET);
        assert!(
            plan.commands[1]
                .args
                .contains(&"iphonesimulator".to_owned())
        );
        assert!(!plan.commands[1].args.contains(&"-destination".to_owned()));
        for setting in [
            "AD_HOC_CODE_SIGNING_ALLOWED=YES",
            "CODE_SIGN_IDENTITY=-",
            "CODE_SIGNING_ALLOWED=YES",
            "CODE_SIGNING_REQUIRED=YES",
        ] {
            assert!(
                plan.commands[1]
                    .args
                    .iter()
                    .any(|argument| argument == setting)
            );
        }
        assert!(!plan.commands[1].args.iter().any(|argument| matches!(
            argument.as_str(),
            "AD_HOC_CODE_SIGNING_ALLOWED=NO"
                | "CODE_SIGNING_ALLOWED=NO"
                | "CODE_SIGNING_REQUIRED=NO"
        )));
        assert!(plan.generated_root.starts_with(root.join("target/ferry")));
        assert!(!plan.generated_files.is_empty());
        assert_eq!(plan.asset_packaging, IosAssetPackaging::CompiledCatalog);
    }

    #[test]
    fn missing_simulator_runtime_selects_validated_sdk_only_assets() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let compiled_plan = plan_ios_simulator(&request(root), &fake_toolchain(root)).unwrap();
        let mut toolchain = fake_toolchain(root);
        toolchain.simulator_runtime_available = false;
        let plan = plan_ios_simulator(&request(root), &toolchain).unwrap();

        assert_eq!(plan.asset_packaging, IosAssetPackaging::SdkOnlyResources);
        assert_ne!(plan.xcode_derived_data, compiled_plan.xcode_derived_data);
        assert!(
            plan.generated_files
                .iter()
                .any(|path| path.file_name() == Some("FerryIcon.png"))
        );
        assert!(
            plan.generated_files
                .iter()
                .any(|path| path.file_name() == Some("FerrySplash.png"))
        );
        assert!(
            !plan
                .generated_files
                .iter()
                .any(|path| path.as_str().contains("Assets.xcassets"))
        );
    }

    #[test]
    fn plan_and_generation_share_one_asset_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let request = request(root);
        let assets = ProjectAssets::load(root).unwrap();
        let planned_fingerprint = assets.fingerprint().to_owned();
        let planned_catalog = rustferry_codegen::render_platform_assets_for(
            &assets,
            rustferry_codegen::GeneratedAssetPlatform::Ios,
        )
        .unwrap()
        .files;
        let plan =
            plan_ios_simulator_with_assets(&request, &fake_toolchain(root), &assets).unwrap();

        fs::write(
            root.join("assets/icon.png"),
            png_with_text_chunk(assets.icon()),
        )
        .unwrap();
        let changed_assets = ProjectAssets::load(root).unwrap();
        assert_ne!(changed_assets.fingerprint(), planned_fingerprint);

        let generated = generate_ios_project(
            &IosProjectSpec::new(request.config, request.binary_name).with_assets(assets),
        )
        .unwrap();
        assert_eq!(plan.asset_fingerprint, planned_fingerprint);
        let expected_icon = planned_catalog
            .into_iter()
            .find_map(|(path, bytes)| {
                (path == "ios/Assets.xcassets/AppIcon.appiconset/AppIcon-1024-1x.png")
                    .then_some(bytes)
            })
            .unwrap();
        assert_eq!(
            generated.files
                [Utf8Path::new("Assets.xcassets/AppIcon.appiconset/AppIcon-1024-1x.png")],
            expected_icon
        );
    }

    #[test]
    fn extension_plan_includes_native_targets_without_runtime_blockers() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let mut request = request(root);
        request.config.extensions.widget.enabled = true;
        request.config.extensions.widget.app_group = Some("group.com.example.weather".into());
        let plan = plan_ios_simulator(&request, &fake_toolchain(root)).unwrap();
        assert_eq!(plan.commands.len(), 4);
        let widget_sign = &plan.commands[2];
        let app_sign = &plan.commands[3];
        assert!(widget_sign.stage.contains("WidgetKit extension"));
        assert!(app_sign.stage.contains("Simulator application"));
        for command in [widget_sign, app_sign] {
            assert_eq!(command.program, root.join("bin/xcrun"));
            assert_eq!(command.args[0], "codesign");
            assert_eq!(command.args[1..4], ["--force", "--sign", "-"]);
            assert!(command.args.contains(&"--timestamp=none".to_owned()));
            assert!(
                command
                    .args
                    .contains(&"--generate-entitlement-der".to_owned())
            );
            assert!(!command.args.contains(&"--deep".to_owned()));
            assert_eq!(
                command.timeout_seconds,
                crate::DEFAULT_COMMAND_TIMEOUT.as_secs()
            );
            assert!(command.redacted_args.is_empty());
            assert!(command.redacted_environment.is_empty());
        }
        assert_eq!(
            widget_sign.args[5],
            plan.generated_root
                .join("WidgetExtension/Widget.entitlements")
                .to_string()
        );
        assert_eq!(
            widget_sign.args[8],
            plan.artifact_path
                .join("PlugIns/FerryWidgetExtension.appex")
                .to_string()
        );
        assert_eq!(
            app_sign.args[5],
            plan.generated_root.join("App.entitlements").to_string()
        );
        assert_eq!(app_sign.args[8], plan.artifact_path.to_string());
        assert!(
            plan.generated_files
                .iter()
                .any(|path| path.ends_with("WidgetExtension/Widget.swift"))
        );
        let generated =
            generate_ios_project(&IosProjectSpec::new(request.config, request.binary_name))
                .unwrap();
        assert!(
            generated
                .files
                .contains_key(Utf8Path::new("WidgetExtension/Widget.swift"))
        );
    }

    #[test]
    fn rejects_feature_argument_injection() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let mut request = request(root);
        request.cargo_features.push("safe --release".into());
        assert!(matches!(
            plan_ios_simulator(&request, &fake_toolchain(root)),
            Err(AppleError::InvalidRequest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn output_preparation_rejects_symlinked_cargo_directory() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir_all(root.join("target/ferry/ios")).unwrap();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("marker"), "preserve").unwrap();
        symlink(&outside, root.join("target/ferry/ios/cargo")).unwrap();

        let error = prepare_output_directory(root, &root.join("target/ferry/ios/cargo"))
            .expect_err("symlinked Cargo output must be rejected");
        assert!(matches!(error, AppleError::UnsafeGeneratedPath { .. }));
        assert_eq!(
            fs::read_to_string(outside.join("marker")).unwrap(),
            "preserve"
        );
    }
}
