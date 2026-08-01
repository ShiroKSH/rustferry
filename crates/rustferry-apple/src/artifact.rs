use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::ProjectAssets;
use serde::{Deserialize, Serialize};

use crate::{AppleError, AppleToolchain, CommandSpec, ExtensionKind, error::io_error, run_command};

const ACTIVITY_MODEL_BUNDLE_IDENTIFIER: &str = "org.rustferry.activity-model";
const ACTIVITY_MODEL_INSTALL_NAME: &str = "@rpath/FerryActivityModel.framework/FerryActivityModel";
const RUNTIME_BRIDGE_INSTALL_NAME: &str = "@rpath/FerryRuntimeBridge.framework/FerryRuntimeBridge";

/// Expected embedded app extension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosExtensionExpectation {
    /// Extension family.
    pub kind: ExtensionKind,
    /// Bundle directory name without `.appex`.
    pub bundle_name: String,
    /// Exact extension bundle identifier.
    pub bundle_identifier: String,
    /// Exact extension executable name.
    pub executable_name: String,
    /// Application group that must be embedded in the code signature.
    pub app_group: Option<String>,
}

/// Independent validation inputs for a built iOS application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IosArtifactExpectation {
    /// Built `.app` directory.
    pub app_path: Utf8PathBuf,
    /// Exact `CFBundleIdentifier`.
    pub bundle_identifier: String,
    /// Exact `CFBundleExecutable` and executable filename.
    pub executable_name: String,
    /// Cargo binary whose Mach-O identity must match the signed embedded executable.
    pub rust_binary: Option<Utf8PathBuf>,
    /// Exact Mach-O architectures expected from `lipo -archs`.
    pub expected_architectures: Vec<String>,
    /// Expected embedded extensions.
    pub extensions: Vec<IosExtensionExpectation>,
    /// Custom URL schemes expected to route through the generated application delegate.
    pub deep_link_schemes: Vec<String>,
    /// Application group that must be embedded in the application signature.
    pub app_group: Option<String>,
    /// Optional destination for redacted validation logs.
    pub log_dir: Option<Utf8PathBuf>,
    /// Exact project icon and splash bytes expected in the sealed bundle.
    pub project_assets: Option<ProjectAssets>,
}

/// Validated ad-hoc code-signature metadata.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosCodeSignatureValidation {
    /// Exact identifier sealed into the signature.
    pub identifier: String,
    /// Whether the signature uses the local ad-hoc identity.
    pub ad_hoc: bool,
    /// Whether strict signature verification passed.
    pub strict_verified: bool,
    /// Whether recursive strict verification passed for this bundle.
    pub deep_verified: bool,
    /// Whether the bundle's `Info.plist` is sealed.
    pub info_plist_sealed: bool,
    /// Whether the bundle resources are sealed.
    pub resources_sealed: bool,
    /// Application groups embedded in the signature entitlements.
    pub app_groups: Vec<String>,
}

/// Validated embedded extension metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosExtensionValidation {
    /// Extension family.
    pub kind: ExtensionKind,
    /// Validated `.appex` path.
    pub path: Utf8PathBuf,
    /// Validated bundle identifier.
    pub bundle_identifier: String,
    /// Validated executable path.
    pub executable: Utf8PathBuf,
    /// Validated Mach-O architectures.
    pub architectures: Vec<String>,
    /// Validated extension-point identifier.
    pub extension_point_identifier: String,
    /// Whether an `ActivityKit` extension links the extension-safe shared model framework.
    pub activity_model_linked: bool,
    /// Strictly verified extension code signature.
    pub code_signature: IosCodeSignatureValidation,
}

/// Validated generated native runtime framework metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosRuntimeBridgeValidation {
    /// Embedded framework bundle path.
    pub path: Utf8PathBuf,
    /// Framework executable path.
    pub executable: Utf8PathBuf,
    /// Exact framework bundle identifier.
    pub bundle_identifier: String,
    /// Validated Mach-O architectures.
    pub architectures: Vec<String>,
    /// Mach-O install name used by the app and extensions.
    pub install_name: String,
    /// Whether the compiled framework contains the pre-`UIApplicationMain` delegate hook.
    pub application_delegate_hook: bool,
    /// Required C ABI entrypoints exported for Rust's dynamic loader.
    pub exported_symbols: Vec<String>,
    /// Strictly verified framework code signature.
    pub code_signature: IosCodeSignatureValidation,
}

/// Evidence collected from a successfully validated `.app`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosArtifactValidation {
    /// Stable validation schema version.
    pub schema_version: u32,
    /// Validated application path.
    pub app_path: Utf8PathBuf,
    /// Validated bundle identifier.
    pub bundle_identifier: String,
    /// Validated executable path.
    pub executable: Utf8PathBuf,
    /// Validated Mach-O architectures.
    pub architectures: Vec<String>,
    /// Whether the signed executable retains Cargo's Mach-O build identity.
    pub rust_binary_embedded: bool,
    /// Required resources found in the app.
    pub resources: Vec<Utf8PathBuf>,
    /// Inspected embedded frameworks and dynamic libraries.
    pub embedded_frameworks: Vec<Utf8PathBuf>,
    /// Generated native runtime framework evidence.
    pub runtime_bridge: IosRuntimeBridgeValidation,
    /// Validated embedded extensions.
    pub extensions: Vec<IosExtensionValidation>,
    /// Validated custom URL schemes.
    pub deep_link_schemes: Vec<String>,
    /// Generated `UIApplication` delegate class when deep links are enabled.
    pub application_delegate: Option<String>,
    /// Strictly and recursively verified application code signature.
    pub code_signature: IosCodeSignatureValidation,
}

/// Validate plist metadata, executable identity/architecture, resources, libraries, and extensions.
///
/// # Errors
///
/// Returns [`AppleError`] when the bundle is missing, malformed, has unexpected
/// metadata, architecture, code signature, or Cargo build identity, or a validation
/// tool cannot run successfully.
#[allow(clippy::too_many_lines)]
pub fn validate_ios_app(
    expected: &IosArtifactExpectation,
    toolchain: &AppleToolchain,
) -> Result<IosArtifactValidation, AppleError> {
    validate_real_directory(&expected.app_path, "application bundle")?;
    let info_plist = expected.app_path.join("Info.plist");
    validate_regular_file(&info_plist, "application Info.plist")?;
    lint_plist(&info_plist, toolchain, expected.log_dir.as_deref(), 1)?;

    let bundle_identifier = plist_value(
        &info_plist,
        "CFBundleIdentifier",
        toolchain,
        expected.log_dir.as_deref(),
        2,
    )?;
    if bundle_identifier != expected.bundle_identifier {
        return invalid(
            &expected.app_path,
            format!(
                "CFBundleIdentifier is `{bundle_identifier}`, expected `{}`",
                expected.bundle_identifier
            ),
        );
    }
    let executable_name = plist_value(
        &info_plist,
        "CFBundleExecutable",
        toolchain,
        expected.log_dir.as_deref(),
        3,
    )?;
    if executable_name != expected.executable_name {
        return invalid(
            &expected.app_path,
            format!(
                "CFBundleExecutable is `{executable_name}`, expected `{}`",
                expected.executable_name
            ),
        );
    }
    let package_type = plist_value(
        &info_plist,
        "CFBundlePackageType",
        toolchain,
        expected.log_dir.as_deref(),
        4,
    )?;
    if package_type != "APPL" {
        return invalid(
            &expected.app_path,
            format!("CFBundlePackageType is `{package_type}`, expected `APPL`"),
        );
    }

    if !expected.deep_link_schemes.is_empty() {
        for (index, scheme) in expected.deep_link_schemes.iter().enumerate() {
            let actual = plist_value(
                &info_plist,
                &format!("CFBundleURLTypes.0.CFBundleURLSchemes.{index}"),
                toolchain,
                expected.log_dir.as_deref(),
                6 + index,
            )?;
            if actual != *scheme {
                return invalid(
                    &info_plist,
                    format!("custom URL scheme {index} is `{actual}`, expected `{scheme}`"),
                );
            }
        }
    }

    let executable = expected.app_path.join(&expected.executable_name);
    validate_executable(&executable)?;
    let architectures =
        macho_architectures(&executable, toolchain, expected.log_dir.as_deref(), 5)?;
    let mut expected_architectures = expected.expected_architectures.clone();
    expected_architectures.sort();
    expected_architectures.dedup();
    if architectures != expected_architectures {
        return invalid(
            &executable,
            format!(
                "Mach-O architectures are {architectures:?}, expected {expected_architectures:?}"
            ),
        );
    }

    let rust_binary_embedded = if let Some(rust_binary) = &expected.rust_binary {
        validate_regular_file(rust_binary, "Cargo-produced Rust executable")?;
        let cargo_uuids = macho_uuids(rust_binary, toolchain, expected.log_dir.as_deref(), 100)?;
        let embedded_uuids = macho_uuids(&executable, toolchain, expected.log_dir.as_deref(), 101)?;
        if cargo_uuids != embedded_uuids {
            return invalid(
                &executable,
                format!(
                    "signed executable Mach-O UUIDs {embedded_uuids:?} differ from Cargo output `{rust_binary}` UUIDs {cargo_uuids:?}; Rust linkage cannot be proven"
                ),
            );
        }
        true
    } else {
        false
    };

    let resources = ["FerryResources.json", "FerryIcon.png", "FerrySplash.png"]
        .into_iter()
        .map(|name| expected.app_path.join(name))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if !resources
        .iter()
        .any(|path| path.file_name() == Some("FerryResources.json"))
    {
        return invalid(
            &expected.app_path,
            "generated resource metadata `FerryResources.json` is absent from the application bundle"
                .to_owned(),
        );
    }
    if let Some(assets) = &expected.project_assets {
        for (name, expected_bytes) in [
            ("FerryIcon.png", assets.icon()),
            ("FerrySplash.png", assets.splash()),
        ] {
            let path = expected.app_path.join(name);
            validate_regular_file(&path, "project image resource")?;
            let actual = fs::read(&path)
                .map_err(|source| io_error("read embedded project image", &path, source))?;
            if actual != expected_bytes {
                return invalid(
                    &path,
                    "embedded image bytes differ from the validated project asset".to_owned(),
                );
            }
        }
    }

    let embedded_frameworks = inspect_frameworks(&expected.app_path)?;
    let runtime_bridge = validate_runtime_bridge(
        &expected.app_path,
        &expected_architectures,
        toolchain,
        expected.log_dir.as_deref(),
    )?;
    let live_activity_enabled = expected
        .extensions
        .iter()
        .any(|extension| extension.kind == ExtensionKind::ActivityKit);
    if live_activity_enabled {
        validate_activity_model(
            &expected.app_path,
            &expected_architectures,
            &runtime_bridge.executable,
            toolchain,
            expected.log_dir.as_deref(),
        )?;
    } else {
        reject_unexpected_activity_model(&expected.app_path)?;
    }
    let application_delegate = if expected.deep_link_schemes.is_empty() {
        None
    } else if runtime_bridge.application_delegate_hook {
        Some("FerryApplicationDelegate".to_owned())
    } else {
        return invalid(
            &runtime_bridge.executable,
            "runtime framework does not contain the UIApplication initialization delegate hook"
                .to_owned(),
        );
    };
    let extensions = validate_extensions(expected, toolchain)?;
    let plugins = expected.app_path.join("PlugIns");
    if plugins.is_dir() {
        let actual_count = fs::read_dir(&plugins)
            .map_err(|source| io_error("inspect embedded app extensions", &plugins, source))?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "appex")
            })
            .count();
        if actual_count != expected.extensions.len() {
            return invalid(
                &plugins,
                format!(
                    "found {actual_count} embedded `.appex` bundles, expected {}",
                    expected.extensions.len()
                ),
            );
        }
    } else if !expected.extensions.is_empty() {
        return invalid(
            &plugins,
            format!(
                "PlugIns directory is absent; expected {} app extension(s)",
                expected.extensions.len()
            ),
        );
    }
    let code_signature = validate_code_signature(
        &expected.app_path,
        &expected.bundle_identifier,
        expected.app_group.as_deref(),
        true,
        toolchain,
        expected.log_dir.as_deref(),
        110,
    )?;

    Ok(IosArtifactValidation {
        schema_version: 6,
        app_path: expected.app_path.clone(),
        bundle_identifier,
        executable,
        architectures,
        rust_binary_embedded,
        resources,
        embedded_frameworks,
        runtime_bridge,
        extensions,
        deep_link_schemes: expected.deep_link_schemes.clone(),
        application_delegate,
        code_signature,
    })
}

fn validate_extensions(
    expected: &IosArtifactExpectation,
    toolchain: &AppleToolchain,
) -> Result<Vec<IosExtensionValidation>, AppleError> {
    let mut validations = Vec::new();
    for (index, extension) in expected.extensions.iter().enumerate() {
        let path = expected
            .app_path
            .join("PlugIns")
            .join(format!("{}.appex", extension.bundle_name));
        validations.push(validate_extension_at(
            &path,
            extension,
            &expected.expected_architectures,
            toolchain,
            expected.log_dir.as_deref(),
            30 + index * 20,
        )?);
    }
    Ok(validations)
}

/// Validate one standalone generated `.appex` product.
///
/// # Errors
///
/// Returns [`AppleError`] when the extension bundle, plist metadata,
/// executable, extension point, or architecture does not match `expected`.
pub fn validate_ios_extension(
    path: &Utf8Path,
    expected: &IosExtensionExpectation,
    expected_architectures: &[String],
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
) -> Result<IosExtensionValidation, AppleError> {
    validate_extension_at(
        path,
        expected,
        expected_architectures,
        toolchain,
        log_dir,
        1,
    )
}

fn validate_extension_at(
    path: &Utf8Path,
    extension: &IosExtensionExpectation,
    expected_architectures: &[String],
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    log_index: usize,
) -> Result<IosExtensionValidation, AppleError> {
    validate_real_directory(path, "embedded app extension")?;
    let info_plist = path.join("Info.plist");
    validate_regular_file(&info_plist, "extension Info.plist")?;
    lint_plist(&info_plist, toolchain, log_dir, log_index)?;
    let bundle_identifier = plist_value(
        &info_plist,
        "CFBundleIdentifier",
        toolchain,
        log_dir,
        log_index + 1,
    )?;
    if bundle_identifier != extension.bundle_identifier {
        return invalid(
            path,
            format!(
                "extension CFBundleIdentifier is `{bundle_identifier}`, expected `{}`",
                extension.bundle_identifier
            ),
        );
    }
    let executable_name = plist_value(
        &info_plist,
        "CFBundleExecutable",
        toolchain,
        log_dir,
        log_index + 2,
    )?;
    if executable_name != extension.executable_name {
        return invalid(
            path,
            format!(
                "extension executable is `{executable_name}`, expected `{}`",
                extension.executable_name
            ),
        );
    }
    let extension_point_identifier = plist_value(
        &info_plist,
        "NSExtension.NSExtensionPointIdentifier",
        toolchain,
        log_dir,
        log_index + 3,
    )?;
    if extension_point_identifier != "com.apple.widgetkit-extension" {
        return invalid(
            path,
            format!(
                "NSExtensionPointIdentifier is `{extension_point_identifier}`, expected `com.apple.widgetkit-extension`"
            ),
        );
    }
    let executable = path.join(&extension.executable_name);
    validate_executable(&executable)?;
    let architectures = macho_architectures(&executable, toolchain, log_dir, log_index + 4)?;
    let mut required = expected_architectures.to_vec();
    required.sort();
    required.dedup();
    if architectures != required {
        return invalid(
            &executable,
            format!("extension architectures are {architectures:?}, expected {required:?}"),
        );
    }
    let activity_model_linked = if extension.kind == ExtensionKind::ActivityKit {
        let dependencies = macho_dependencies(&executable, toolchain, log_dir, log_index + 5)?;
        validate_activity_extension_dependencies(&executable, &dependencies)?
    } else {
        false
    };
    let code_signature = validate_code_signature(
        path,
        &extension.bundle_identifier,
        extension.app_group.as_deref(),
        false,
        toolchain,
        log_dir,
        log_index + 6,
    )?;
    Ok(IosExtensionValidation {
        kind: extension.kind,
        path: path.to_owned(),
        bundle_identifier,
        executable,
        architectures,
        extension_point_identifier,
        activity_model_linked,
        code_signature,
    })
}

fn validate_activity_extension_dependencies(
    executable: &Utf8Path,
    dependencies: &[String],
) -> Result<bool, AppleError> {
    if dependencies
        .iter()
        .any(|dependency| dependency == RUNTIME_BRIDGE_INSTALL_NAME)
    {
        return invalid(
            executable,
            "ActivityKit extension links the app-only FerryRuntimeBridge framework; extensions may only share FerryActivityModel"
                .to_owned(),
        );
    }
    if !dependencies
        .iter()
        .any(|dependency| dependency == ACTIVITY_MODEL_INSTALL_NAME)
    {
        return invalid(
            executable,
            "ActivityKit extension does not link the extension-safe FerryActivityModel framework"
                .to_owned(),
        );
    }
    Ok(true)
}

fn validate_activity_model(
    app_path: &Utf8Path,
    expected_architectures: &[String],
    runtime_bridge_executable: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
) -> Result<(), AppleError> {
    let path = app_path.join("Frameworks/FerryActivityModel.framework");
    validate_real_directory(&path, "embedded Live Activity model framework")?;
    let info_plist = path.join("Info.plist");
    validate_regular_file(&info_plist, "Live Activity model framework Info.plist")?;
    lint_plist(&info_plist, toolchain, log_dir, 170)?;

    let bundle_identifier =
        plist_value(&info_plist, "CFBundleIdentifier", toolchain, log_dir, 171)?;
    if bundle_identifier != ACTIVITY_MODEL_BUNDLE_IDENTIFIER {
        return invalid(
            &path,
            format!(
                "Live Activity model framework bundle identifier is `{bundle_identifier}`, expected `{ACTIVITY_MODEL_BUNDLE_IDENTIFIER}`"
            ),
        );
    }
    let executable_name = plist_value(&info_plist, "CFBundleExecutable", toolchain, log_dir, 172)?;
    if executable_name != "FerryActivityModel" {
        return invalid(
            &path,
            format!(
                "Live Activity model framework executable is `{executable_name}`, expected `FerryActivityModel`"
            ),
        );
    }
    let package_type = plist_value(&info_plist, "CFBundlePackageType", toolchain, log_dir, 173)?;
    if package_type != "FMWK" {
        return invalid(
            &path,
            format!(
                "Live Activity model framework package type is `{package_type}`, expected `FMWK`"
            ),
        );
    }

    let executable = path.join(executable_name);
    validate_executable(&executable)?;
    let architectures = macho_architectures(&executable, toolchain, log_dir, 174)?;
    if architectures != expected_architectures {
        return invalid(
            &executable,
            format!(
                "Live Activity model framework architectures are {architectures:?}, expected {expected_architectures:?}"
            ),
        );
    }
    let install_name = macho_install_name(&executable, toolchain, log_dir, 175)?;
    if install_name != ACTIVITY_MODEL_INSTALL_NAME {
        return invalid(
            &executable,
            format!(
                "Live Activity model framework install name is `{install_name}`, expected `{ACTIVITY_MODEL_INSTALL_NAME}`"
            ),
        );
    }

    let runtime_dependencies =
        macho_dependencies(runtime_bridge_executable, toolchain, log_dir, 176)?;
    if !runtime_dependencies
        .iter()
        .any(|dependency| dependency == ACTIVITY_MODEL_INSTALL_NAME)
    {
        return invalid(
            runtime_bridge_executable,
            "FerryRuntimeBridge does not link the shared FerryActivityModel framework".to_owned(),
        );
    }
    let _ = validate_code_signature(
        &path,
        ACTIVITY_MODEL_BUNDLE_IDENTIFIER,
        None,
        false,
        toolchain,
        log_dir,
        177,
    )?;
    Ok(())
}

fn reject_unexpected_activity_model(app_path: &Utf8Path) -> Result<(), AppleError> {
    let path = app_path.join("Frameworks/FerryActivityModel.framework");
    match fs::symlink_metadata(&path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => invalid(
            &path,
            "Live Activity model framework is embedded but no ActivityKit extension was requested"
                .to_owned(),
        ),
        Err(source) => Err(io_error(
            "inspect unexpected Live Activity model framework",
            &path,
            source,
        )),
    }
}

fn validate_runtime_bridge(
    app_path: &Utf8Path,
    expected_architectures: &[String],
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
) -> Result<IosRuntimeBridgeValidation, AppleError> {
    let path = app_path.join("Frameworks/FerryRuntimeBridge.framework");
    validate_real_directory(&path, "embedded RustFerry runtime framework")?;
    let info_plist = path.join("Info.plist");
    validate_regular_file(&info_plist, "RustFerry runtime framework Info.plist")?;
    lint_plist(&info_plist, toolchain, log_dir, 10)?;
    let bundle_identifier = plist_value(&info_plist, "CFBundleIdentifier", toolchain, log_dir, 11)?;
    if bundle_identifier != "org.rustferry.runtime-bridge" {
        return invalid(
            &path,
            format!(
                "runtime framework bundle identifier is `{bundle_identifier}`, expected `org.rustferry.runtime-bridge`"
            ),
        );
    }
    let executable_name = plist_value(&info_plist, "CFBundleExecutable", toolchain, log_dir, 12)?;
    if executable_name != "FerryRuntimeBridge" {
        return invalid(
            &path,
            format!(
                "runtime framework executable is `{executable_name}`, expected `FerryRuntimeBridge`"
            ),
        );
    }
    let executable = path.join(executable_name);
    validate_executable(&executable)?;
    let architectures = macho_architectures(&executable, toolchain, log_dir, 13)?;
    if architectures != expected_architectures {
        return invalid(
            &executable,
            format!(
                "runtime framework architectures are {architectures:?}, expected {expected_architectures:?}"
            ),
        );
    }
    let install_name = macho_install_name(&executable, toolchain, log_dir, 14)?;
    if install_name != RUNTIME_BRIDGE_INSTALL_NAME {
        return invalid(
            &executable,
            format!(
                "runtime framework install name is `{install_name}`, expected an @rpath framework"
            ),
        );
    }
    let application_delegate_hook = binary_contains(&executable, b"FerryApplicationDelegate")?
        && binary_contains(&executable, b"ferry_bridge_init")?;
    if !application_delegate_hook {
        return invalid(
            &executable,
            "runtime framework is missing the compiled UIApplication delegate-hook markers"
                .to_owned(),
        );
    }
    let exported_symbols = macho_exported_symbols(&executable, toolchain, log_dir, 15)?;
    for required in [
        "_ferry_bridge_call",
        "_ferry_bridge_free",
        "_ferry_bridge_init",
        "_ferry_bridge_install",
        "_ferry_bridge_with_application",
    ] {
        if !exported_symbols.iter().any(|symbol| symbol == required) {
            return invalid(
                &executable,
                format!("runtime framework does not export required C symbol `{required}`"),
            );
        }
    }
    let code_signature = validate_code_signature(
        &path,
        "org.rustferry.runtime-bridge",
        None,
        false,
        toolchain,
        log_dir,
        16,
    )?;
    Ok(IosRuntimeBridgeValidation {
        path,
        executable,
        bundle_identifier,
        architectures,
        install_name,
        application_delegate_hook,
        exported_symbols,
        code_signature,
    })
}

fn binary_contains(path: &Utf8Path, needle: &[u8]) -> Result<bool, AppleError> {
    let bytes = fs::read(path).map_err(|source| io_error("inspect Mach-O bytes", path, source))?;
    Ok(bytes.windows(needle.len()).any(|window| window == needle))
}

fn lint_plist(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<(), AppleError> {
    let mut command = CommandSpec::new(
        "validate Apple property list",
        &toolchain.plutil,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.args = vec!["-lint".to_owned(), path.to_string()];
    run_command(
        &command,
        validation_log(log_dir, index, "plist-lint").as_deref(),
    )
    .map(|_| ())
}

fn plist_value(
    path: &Utf8Path,
    key_path: &str,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<String, AppleError> {
    let mut command = CommandSpec::new(
        format!("read plist key {key_path}"),
        &toolchain.plutil,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.args = vec![
        "-extract".to_owned(),
        key_path.to_owned(),
        "raw".to_owned(),
        "-o".to_owned(),
        "-".to_owned(),
        path.to_string(),
    ];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "plist-value").as_deref(),
    )?;
    let value = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("plist key `{key_path}` is not UTF-8: {error}"),
    })?;
    Ok(value.trim().to_owned())
}

fn macho_architectures(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<Vec<String>, AppleError> {
    let mut command = CommandSpec::new(
        "inspect Mach-O architectures",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec!["lipo".to_owned(), "-archs".to_owned(), path.to_string()];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "lipo-archs").as_deref(),
    )?;
    let source = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("lipo architecture output is not UTF-8: {error}"),
    })?;
    let mut architectures = source
        .split_whitespace()
        .filter(|value| {
            matches!(
                *value,
                "arm64" | "arm64e" | "x86_64" | "i386" | "armv7" | "armv7s"
            )
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    architectures.sort();
    architectures.dedup();
    if architectures.is_empty() {
        return invalid(
            path,
            format!("lipo reported no recognized architecture: {source:?}"),
        );
    }
    Ok(architectures)
}

fn macho_uuids(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<Vec<String>, AppleError> {
    let mut command = CommandSpec::new(
        "inspect Mach-O build UUIDs",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec![
        "dwarfdump".to_owned(),
        "--uuid".to_owned(),
        path.to_string(),
    ];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "dwarfdump-uuid").as_deref(),
    )?;
    let source = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("dwarfdump UUID output is not UTF-8: {error}"),
    })?;
    parse_macho_uuids(path, &source)
}

fn parse_macho_uuids(path: &Utf8Path, source: &str) -> Result<Vec<String>, AppleError> {
    let mut identities = Vec::new();
    for line in source.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("UUID:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let uuid = fields.next().unwrap_or_default();
        let architecture = fields
            .next()
            .and_then(|value| value.strip_prefix('('))
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or_default();
        let uuid_is_valid = uuid.len() == 36
            && uuid.chars().enumerate().all(|(index, character)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    character == '-'
                } else {
                    character.is_ascii_hexdigit()
                }
            });
        if !uuid_is_valid || architecture.is_empty() {
            return invalid(
                path,
                format!("dwarfdump reported a malformed Mach-O UUID line: {line:?}"),
            );
        }
        identities.push(format!("{}:{}", architecture, uuid.to_ascii_uppercase()));
    }
    identities.sort();
    identities.dedup();
    if identities.is_empty() {
        return invalid(
            path,
            format!("dwarfdump reported no Mach-O UUIDs: {source:?}"),
        );
    }
    Ok(identities)
}

fn macho_install_name(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<String, AppleError> {
    let mut command = CommandSpec::new(
        "inspect Mach-O install name",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec!["otool".to_owned(), "-D".to_owned(), path.to_string()];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "otool-install-name").as_deref(),
    )?;
    let output = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("otool install-name output is not UTF-8: {error}"),
    })?;
    output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with('@'))
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppleError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("otool reported no install name: {output:?}"),
        })
}

fn macho_dependencies(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<Vec<String>, AppleError> {
    let mut command = CommandSpec::new(
        "inspect Mach-O linked libraries",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec!["otool".to_owned(), "-L".to_owned(), path.to_string()];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "otool-linked-libraries").as_deref(),
    )?;
    let output = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("otool linked-library output is not UTF-8: {error}"),
    })?;
    Ok(output
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect())
}

fn macho_exported_symbols(
    path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    index: usize,
) -> Result<Vec<String>, AppleError> {
    let mut command = CommandSpec::new(
        "inspect Mach-O exported symbols",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    command.args = vec!["nm".to_owned(), "-gj".to_owned(), path.to_string()];
    let output = run_command(
        &command,
        validation_log(log_dir, index, "nm-exported-symbols").as_deref(),
    )?;
    let output = String::from_utf8(output.stdout).map_err(|error| AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason: format!("nm exported-symbol output is not UTF-8: {error}"),
    })?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn inspect_frameworks(app_path: &Utf8Path) -> Result<Vec<Utf8PathBuf>, AppleError> {
    let directory = app_path.join("Frameworks");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    validate_real_directory(&directory, "embedded Frameworks directory")?;
    let mut entries = fs::read_dir(&directory)
        .map_err(|source| io_error("inspect embedded frameworks", &directory, source))?
        .map(|entry| {
            let entry = entry
                .map_err(|source| io_error("inspect embedded framework", &directory, source))?;
            let path = Utf8PathBuf::from_path_buf(entry.path()).map_err(AppleError::NonUtf8Path)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect embedded framework metadata", &path, source))?;
            if metadata.file_type().is_symlink() {
                return invalid::<Utf8PathBuf>(
                    &path,
                    "top-level embedded framework/library cannot be a symbolic link".to_owned(),
                );
            }
            if metadata.is_file() && metadata.len() == 0 {
                return invalid::<Utf8PathBuf>(&path, "embedded library is empty".to_owned());
            }
            Ok(path)
        })
        .collect::<Result<Vec<_>, AppleError>>()?;
    entries.sort();
    Ok(entries)
}

fn validate_code_signature(
    path: &Utf8Path,
    expected_identifier: &str,
    expected_app_group: Option<&str>,
    deep: bool,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    log_index: usize,
) -> Result<IosCodeSignatureValidation, AppleError> {
    validate_regular_file(
        &path.join("_CodeSignature/CodeResources"),
        "sealed code-signature resources",
    )?;

    let mut verify = CommandSpec::new(
        "strictly verify iOS bundle code signature",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    verify.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    verify.args = vec!["codesign".to_owned(), "--verify".to_owned()];
    if deep {
        verify.args.push("--deep".to_owned());
    }
    verify.args.extend([
        "--strict".to_owned(),
        "--verbose=4".to_owned(),
        "--test-requirement".to_owned(),
        format!("=identifier \"{expected_identifier}\""),
        path.to_string(),
    ]);
    run_command(
        &verify,
        validation_log(log_dir, log_index, "codesign-verify").as_deref(),
    )?;

    let entitlement_file = tempfile::NamedTempFile::new()
        .map_err(|source| io_error("create temporary entitlement output", path, source))?;
    let entitlement_path = Utf8PathBuf::from_path_buf(entitlement_file.path().to_owned())
        .map_err(AppleError::NonUtf8Path)?;
    let mut display = CommandSpec::new(
        "inspect iOS bundle code signature",
        &toolchain.xcrun,
        path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    display.environment.insert(
        "DEVELOPER_DIR".to_owned(),
        toolchain.developer_dir.to_string(),
    );
    display.args = vec![
        "codesign".to_owned(),
        "--display".to_owned(),
        "--verbose=4".to_owned(),
        "--entitlements".to_owned(),
        entitlement_path.to_string(),
        "--xml".to_owned(),
        path.to_string(),
    ];
    let output = run_command(
        &display,
        validation_log(log_dir, log_index + 1, "codesign-display").as_deref(),
    )?;
    let mut metadata =
        String::from_utf8(output.stderr).map_err(|error| AppleError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("codesign metadata is not UTF-8: {error}"),
        })?;
    if !output.stdout.is_empty() {
        metadata.push('\n');
        metadata.push_str(&String::from_utf8(output.stdout).map_err(|error| {
            AppleError::InvalidArtifact {
                path: path.to_owned(),
                reason: format!("codesign metadata is not UTF-8: {error}"),
            }
        })?);
    }
    let displayed = parse_code_signature_display(path, &metadata)?;
    if displayed.identifier != expected_identifier {
        return invalid(
            path,
            format!(
                "code-signature identifier is `{}`, expected `{expected_identifier}`",
                displayed.identifier
            ),
        );
    }
    let app_groups =
        code_signature_app_groups(path, &entitlement_path, toolchain, log_dir, log_index + 2)?;
    let expected_app_groups = expected_app_group
        .map(|group| vec![group.to_owned()])
        .unwrap_or_default();
    if app_groups != expected_app_groups {
        return invalid(
            path,
            format!(
                "signed application groups are {app_groups:?}, expected {expected_app_groups:?}"
            ),
        );
    }

    Ok(IosCodeSignatureValidation {
        identifier: displayed.identifier,
        ad_hoc: true,
        strict_verified: true,
        deep_verified: deep,
        info_plist_sealed: true,
        resources_sealed: true,
        app_groups,
    })
}

struct DisplayedCodeSignature {
    identifier: String,
}

fn parse_code_signature_display(
    path: &Utf8Path,
    source: &str,
) -> Result<DisplayedCodeSignature, AppleError> {
    let identifier = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("Identifier="))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppleError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("codesign reported no signature identifier: {source:?}"),
        })?;
    if !source.lines().any(|line| line.trim() == "Signature=adhoc") {
        return invalid(path, "code signature is not ad-hoc".to_owned());
    }
    if source.lines().any(|line| line.contains("linker-signed")) {
        return invalid(
            path,
            "code has only a linker-generated signature, not a sealed bundle signature".to_owned(),
        );
    }
    if !source
        .lines()
        .any(|line| line.trim().starts_with("Info.plist entries="))
    {
        return invalid(path, "code signature does not seal Info.plist".to_owned());
    }
    if !source
        .lines()
        .any(|line| line.trim().starts_with("Sealed Resources version="))
    {
        return invalid(
            path,
            "code signature does not seal bundle resources".to_owned(),
        );
    }
    Ok(DisplayedCodeSignature { identifier })
}

fn code_signature_app_groups(
    bundle_path: &Utf8Path,
    entitlement_path: &Utf8Path,
    toolchain: &AppleToolchain,
    log_dir: Option<&Utf8Path>,
    log_index: usize,
) -> Result<Vec<String>, AppleError> {
    let metadata = fs::metadata(entitlement_path).map_err(|source| {
        io_error(
            "inspect extracted code-signature entitlements",
            bundle_path,
            source,
        )
    })?;
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }
    let mut command = CommandSpec::new(
        "convert code-signature entitlements to JSON",
        &toolchain.plutil,
        bundle_path.parent().unwrap_or_else(|| Utf8Path::new(".")),
    );
    command.args = vec![
        "-convert".to_owned(),
        "json".to_owned(),
        "-o".to_owned(),
        "-".to_owned(),
        entitlement_path.to_string(),
    ];
    let output = run_command(
        &command,
        validation_log(log_dir, log_index, "entitlements-json").as_deref(),
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|error| AppleError::InvalidArtifact {
            path: bundle_path.to_owned(),
            reason: format!("signed entitlements are not valid JSON: {error}"),
        })?;
    let Some(groups) = value.get("com.apple.security.application-groups") else {
        return Ok(Vec::new());
    };
    let groups = groups
        .as_array()
        .ok_or_else(|| AppleError::InvalidArtifact {
            path: bundle_path.to_owned(),
            reason: "signed application-group entitlement is not an array".to_owned(),
        })?;
    let mut groups = groups
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| AppleError::InvalidArtifact {
                    path: bundle_path.to_owned(),
                    reason: "signed application-group entitlement contains a non-string value"
                        .to_owned(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    groups.sort();
    Ok(groups)
}

fn validate_real_directory(path: &Utf8Path, description: &str) -> Result<(), AppleError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            AppleError::InvalidArtifact {
                path: path.to_owned(),
                reason: format!("{description} does not exist"),
            }
        } else {
            io_error("inspect iOS artifact directory", path, source)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid(path, format!("{description} is not a real directory"));
    }
    Ok(())
}

fn validate_regular_file(path: &Utf8Path, description: &str) -> Result<(), AppleError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            AppleError::InvalidArtifact {
                path: path.to_owned(),
                reason: format!("{description} does not exist"),
            }
        } else {
            io_error("inspect iOS artifact file", path, source)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(path, format!("{description} is not a regular file"));
    }
    if metadata.len() == 0 {
        return invalid(path, format!("{description} is empty"));
    }
    Ok(())
}

fn validate_executable(path: &Utf8Path) -> Result<(), AppleError> {
    validate_regular_file(path, "bundle executable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|source| io_error("inspect executable permissions", path, source))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return invalid(
                path,
                "bundle executable has no executable permission bits".to_owned(),
            );
        }
    }
    Ok(())
}

fn validation_log(log_dir: Option<&Utf8Path>, index: usize, name: &str) -> Option<Utf8PathBuf> {
    log_dir.map(|directory| directory.join(format!("{index:02}-{name}.log")))
}

fn invalid<T>(path: &Utf8Path, reason: String) -> Result<T, AppleError> {
    Err(AppleError::InvalidArtifact {
        path: path.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macho_uuid_identity_by_architecture() {
        let path = Utf8Path::new("FerryApp");
        let parsed = parse_macho_uuids(
            path,
            "UUID: 3ecf92d7-c52e-33a0-9292-5f69e5190057 (arm64) FerryApp\n",
        )
        .unwrap();
        assert_eq!(parsed, ["arm64:3ECF92D7-C52E-33A0-9292-5F69E5190057"]);
        assert!(parse_macho_uuids(path, "UUID: malformed (arm64) FerryApp").is_err());
    }

    #[test]
    fn requires_a_sealed_non_linker_adhoc_signature() {
        let path = Utf8Path::new("RustFerry.app");
        let parsed = parse_code_signature_display(
            path,
            "Identifier=com.example.ferry\nSignature=adhoc\nInfo.plist entries=28\nSealed Resources version=2 rules=13 files=2\n",
        )
        .unwrap();
        assert_eq!(parsed.identifier, "com.example.ferry");
        assert!(
            parse_code_signature_display(
                path,
                "Identifier=ferry-bin\nSignature=adhoc\nCodeDirectory flags=0x20002(adhoc,linker-signed)\nInfo.plist=not bound\nSealed Resources=none\n",
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_symlinked_app_bundle() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let temporary = tempfile::tempdir().unwrap();
            let root = Utf8Path::from_path(temporary.path()).unwrap();
            fs::create_dir(root.join("real.app")).unwrap();
            symlink(root.join("real.app"), root.join("linked.app")).unwrap();
            assert!(matches!(
                validate_real_directory(&root.join("linked.app"), "app"),
                Err(AppleError::InvalidArtifact { .. })
            ));
        }
    }

    #[test]
    fn activity_extension_requires_only_the_safe_model_framework() {
        let executable = Utf8Path::new("FerryLiveActivityExtension");
        assert!(
            validate_activity_extension_dependencies(
                executable,
                &[ACTIVITY_MODEL_INSTALL_NAME.to_owned()]
            )
            .unwrap()
        );
        assert!(validate_activity_extension_dependencies(executable, &[]).is_err());
        assert!(
            validate_activity_extension_dependencies(
                executable,
                &[
                    ACTIVITY_MODEL_INSTALL_NAME.to_owned(),
                    RUNTIME_BRIDGE_INSTALL_NAME.to_owned(),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_stale_activity_model_without_an_activity_extension() {
        let temporary = tempfile::tempdir().unwrap();
        let app = Utf8Path::from_path(temporary.path()).unwrap();
        assert!(reject_unexpected_activity_model(app).is_ok());
        fs::create_dir_all(app.join("Frameworks/FerryActivityModel.framework")).unwrap();
        assert!(reject_unexpected_activity_model(app).is_err());
    }
}
