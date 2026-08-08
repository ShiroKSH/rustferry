use std::{collections::BTreeMap, fmt::Write as _, fs};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rustferry_codegen::{
    GeneratedAssetPlatform, GeneratedAssetSet, read_generated_platform_assets,
    render_platform_assets_for,
};
use rustferry_core::{
    FerryConfig, Orientation, ProjectAssets, Theme, validate_application_identifier,
};
use serde::{Deserialize, Serialize};

use crate::{AppleError, error::io_error};

/// How generated iOS image assets are packaged into a Simulator application.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IosAssetPackaging {
    /// Compile `Assets.xcassets` with Xcode when an iOS Simulator runtime is available.
    #[default]
    CompiledCatalog,
    /// Preserve SDK-only builds with validated PNG resources when no runtime is installed.
    SdkOnlyResources,
}

/// Inputs for deterministic hidden Xcode project generation.
#[derive(Clone, Debug, PartialEq)]
pub struct IosProjectSpec {
    /// Validated application configuration.
    pub config: FerryConfig,
    /// Cargo binary copied to the app's executable location.
    pub binary_name: String,
    /// Validated project icon and splash inputs, when generating a build host.
    pub assets: Option<ProjectAssets>,
    /// Asset representation emitted into the hidden Xcode project.
    pub asset_packaging: IosAssetPackaging,
}

/// Apple SDK and signing behavior encoded in a generated Xcode project.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IosProjectPlatform {
    /// Apple Silicon iOS Simulator with local ad-hoc signing.
    #[default]
    Simulator,
    /// Physical iOS device compilation with all code signing disabled.
    DeviceUnsigned,
}

impl IosProjectPlatform {
    pub(crate) const fn rust_target(self) -> &'static str {
        match self {
            Self::Simulator => "aarch64-apple-ios-sim",
            Self::DeviceUnsigned => "aarch64-apple-ios",
        }
    }
}

impl IosProjectSpec {
    /// Construct a project specification.
    pub fn new(config: FerryConfig, binary_name: impl Into<String>) -> Self {
        Self {
            config,
            binary_name: binary_name.into(),
            assets: None,
            asset_packaging: IosAssetPackaging::CompiledCatalog,
        }
    }

    /// Attach validated project image assets to the generated host.
    #[must_use]
    pub fn with_assets(mut self, assets: ProjectAssets) -> Self {
        self.assets = Some(assets);
        self
    }

    /// Select the generated Xcode project's asset representation.
    #[must_use]
    pub fn with_asset_packaging(mut self, asset_packaging: IosAssetPackaging) -> Self {
        self.asset_packaging = asset_packaging;
        self
    }
}

/// Deterministic generated files, keyed by paths relative to a generated root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeneratedAppleProject {
    /// Generated UTF-8 or binary file contents.
    pub files: BTreeMap<Utf8PathBuf, Vec<u8>>,
}

impl GeneratedAppleProject {
    /// Read one generated UTF-8 file by relative path.
    pub fn text(&self, path: &Utf8Path) -> Option<&str> {
        self.files
            .get(path)
            .and_then(|contents| std::str::from_utf8(contents).ok())
    }
}

/// Render an Xcode app target and any requested extension target without touching disk.
///
/// # Errors
///
/// Returns [`AppleError`] when configuration, bundle identifiers, versions,
/// binary names, application groups, or generated metadata are invalid.
#[allow(clippy::too_many_lines)]
pub fn generate_ios_project(spec: &IosProjectSpec) -> Result<GeneratedAppleProject, AppleError> {
    generate_ios_project_for_platform(spec, IosProjectPlatform::Simulator)
}

/// Render an Xcode app target for an explicit simulator or physical-device platform.
///
/// The physical-device variant is compile-only: its generated project disables
/// signing and therefore cannot produce an installable application on its own.
///
/// # Errors
///
/// Returns [`AppleError`] when configuration, bundle identifiers, versions,
/// binary names, application groups, or generated metadata are invalid.
#[allow(clippy::too_many_lines)]
pub fn generate_ios_project_for_platform(
    spec: &IosProjectSpec,
    platform: IosProjectPlatform,
) -> Result<GeneratedAppleProject, AppleError> {
    let asset_catalog = if spec.asset_packaging == IosAssetPackaging::CompiledCatalog {
        spec.assets.as_ref().map(rendered_ios_catalog).transpose()?
    } else {
        None
    };
    generate_ios_project_with_catalog(spec, asset_catalog, platform)
}

pub(crate) fn generate_ios_project_from_asset_set(
    spec: &IosProjectSpec,
    generated: &GeneratedAssetSet,
) -> Result<GeneratedAppleProject, AppleError> {
    if spec.asset_packaging != IosAssetPackaging::CompiledCatalog {
        return Err(AppleError::InvalidRequest(
            "a generated iOS asset set can only back compiled-catalog packaging".to_owned(),
        ));
    }
    let assets = spec.assets.as_ref().ok_or_else(|| {
        AppleError::InvalidRequest(
            "an iOS generated asset set requires a validated project asset snapshot".to_owned(),
        )
    })?;
    if generated.fingerprint != assets.fingerprint() {
        return Err(AppleError::InvalidRequest(format!(
            "generated iOS asset cache {} differs from the planned source snapshot",
            generated.root
        )));
    }
    let expected = rendered_ios_catalog(assets)?;
    let cached = read_generated_platform_assets(generated, GeneratedAssetPlatform::Ios)?;
    if cached != expected {
        return Err(AppleError::InvalidRequest(format!(
            "generated iOS asset cache {} differs from deterministic catalog output",
            generated.root
        )));
    }
    generate_ios_project_with_catalog(spec, Some(cached), IosProjectPlatform::Simulator)
}

fn rendered_ios_catalog(assets: &ProjectAssets) -> Result<Vec<(Utf8PathBuf, Vec<u8>)>, AppleError> {
    let mut catalog = render_platform_assets_for(assets, GeneratedAssetPlatform::Ios)?
        .files
        .into_iter()
        .filter_map(|(path, bytes)| {
            path.strip_prefix("ios")
                .ok()
                .map(|relative| (relative.to_owned(), bytes))
        })
        .collect::<Vec<_>>();
    catalog.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(catalog)
}

fn generate_ios_project_with_catalog(
    spec: &IosProjectSpec,
    asset_catalog: Option<Vec<(Utf8PathBuf, Vec<u8>)>>,
    platform: IosProjectPlatform,
) -> Result<GeneratedAppleProject, AppleError> {
    validate_spec(spec)?;
    let mut files = BTreeMap::new();
    insert_text(
        &mut files,
        "FerryHost.xcodeproj/project.pbxproj",
        render_pbxproj(spec, platform),
    );
    insert_text(
        &mut files,
        "FerryHost.xcodeproj/xcshareddata/xcschemes/FerryApp.xcscheme",
        render_scheme(&spec.binary_name),
    );
    insert_text(&mut files, "Info.plist", render_app_info_plist(spec));
    insert_app_assets(&mut files, spec, asset_catalog)?;
    insert_text(
        &mut files,
        "FerryResources.json",
        render_resource_metadata(spec, platform)?,
    );
    insert_text(
        &mut files,
        "RuntimeBridge/FerryRuntimeBridge.swift",
        render_runtime_bridge_source(spec),
    );
    insert_text(
        &mut files,
        "RuntimeBridge/Info.plist",
        include_str!("../templates/FerryRuntimeBridge-Info.plist").replace(
            "{{minimum_version}}",
            &xml_escape(&spec.config.ios.min_version),
        ),
    );

    insert_extension_sources(&mut files, spec)?;
    Ok(GeneratedAppleProject { files })
}

fn insert_extension_sources(
    files: &mut BTreeMap<Utf8PathBuf, Vec<u8>>,
    spec: &IosProjectSpec,
) -> Result<(), AppleError> {
    if spec.config.extensions.live_activity.enabled {
        insert_text(
            files,
            "ActivityModel/FerryActivityAttributes.swift",
            render_activity_model_source(),
        );
        insert_text(
            files,
            "ActivityModel/Info.plist",
            include_str!("../templates/FerryActivityModel-Info.plist").replace(
                "{{minimum_version}}",
                &xml_escape(&spec.config.ios.min_version),
            ),
        );
    }
    if spec.config.extensions.widget.enabled {
        let Some(app_group) = spec.config.extensions.widget.app_group.as_deref() else {
            return Err(AppleError::InvalidConfig(
                "extensions.widget.app_group is required when the widget is enabled".to_owned(),
            ));
        };
        insert_text(files, "App.entitlements", render_entitlements(app_group));
        insert_text(
            files,
            "WidgetExtension/Widget.swift",
            render_widget_source(app_group),
        );
        insert_text(
            files,
            "WidgetExtension/Info.plist",
            render_extension_info_plist(
                &format!("{}.widget", spec.config.app.identifier),
                "FerryWidgetExtension",
                &spec.config.app.display_version,
                &format!(
                    "{}.{}.{}",
                    spec.config.app.version.major,
                    spec.config.app.version.minor,
                    spec.config.app.version.patch
                ),
            ),
        );
        insert_text(
            files,
            "WidgetExtension/Widget.entitlements",
            render_entitlements(app_group),
        );
    }

    if spec.config.extensions.live_activity.enabled {
        insert_text(
            files,
            "LiveActivityExtension/LiveActivity.swift",
            render_live_activity_source(),
        );
        insert_text(
            files,
            "LiveActivityExtension/Info.plist",
            render_extension_info_plist(
                &format!("{}.liveactivity", spec.config.app.identifier),
                "FerryLiveActivityExtension",
                &spec.config.app.display_version,
                &format!(
                    "{}.{}.{}",
                    spec.config.app.version.major,
                    spec.config.app.version.minor,
                    spec.config.app.version.patch
                ),
            ),
        );
    }
    Ok(())
}

fn insert_app_assets(
    files: &mut BTreeMap<Utf8PathBuf, Vec<u8>>,
    spec: &IosProjectSpec,
    asset_catalog: Option<Vec<(Utf8PathBuf, Vec<u8>)>>,
) -> Result<(), AppleError> {
    if let Some(asset_catalog) = asset_catalog {
        for (relative, bytes) in asset_catalog {
            validate_relative_path(&relative)?;
            files.insert(relative, bytes);
        }
    } else if spec.asset_packaging == IosAssetPackaging::SdkOnlyResources
        && let Some(assets) = &spec.assets
    {
        files.insert(Utf8PathBuf::from("FerryIcon.png"), assets.icon().to_vec());
        files.insert(
            Utf8PathBuf::from("FerrySplash.png"),
            assets.splash().to_vec(),
        );
    }
    Ok(())
}

/// Write generated files below an internal root, rejecting absolute paths, traversal, and symlinks.
///
/// # Errors
///
/// Returns [`AppleError`] for unsafe relative paths, symlink traversal, or filesystem failures.
pub fn write_ios_project(
    project: &GeneratedAppleProject,
    root: &Utf8Path,
) -> Result<(), AppleError> {
    reject_symlink(root)?;
    fs::create_dir_all(root)
        .map_err(|source| io_error("create generated iOS root", root, source))?;
    for (relative, contents) in &project.files {
        validate_relative_path(relative)?;
        let destination = root.join(relative);
        let parent = destination
            .parent()
            .ok_or_else(|| AppleError::UnsafeGeneratedPath {
                path: destination.clone(),
                reason: "generated file has no parent directory".to_owned(),
            })?;
        create_directories_without_symlinks(root, parent)?;
        reject_symlink(&destination)?;
        fs::write(&destination, contents)
            .map_err(|source| io_error("write generated iOS file", &destination, source))?;
    }
    Ok(())
}

fn validate_spec(spec: &IosProjectSpec) -> Result<(), AppleError> {
    let issues = spec.config.validate();
    if !issues.is_empty() {
        let summary = issues
            .iter()
            .map(|issue| format!("{}: {} ({})", issue.field, issue.message, issue.help))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(AppleError::InvalidConfig(summary));
    }
    validate_binary_name(&spec.binary_name)?;
    validate_apple_version("app.display_version", &spec.config.app.display_version, 3)?;
    validate_apple_version("ios.min_version", &spec.config.ios.min_version, 2)?;
    if let Some(app_group) = spec.config.extensions.widget.app_group.as_deref()
        && (!app_group.starts_with("group.") || validate_application_identifier(app_group).is_err())
    {
        return Err(AppleError::InvalidRequest(format!(
            "widget application group `{app_group}` must start with `group.` and use bundle-identifier characters"
        )));
    }
    for suffix in ["widget", "liveactivity"] {
        let identifier = format!("{}.{}", spec.config.app.identifier, suffix);
        if identifier.len() > 255 {
            return Err(AppleError::InvalidRequest(format!(
                "extension bundle identifier `{identifier}` exceeds 255 bytes"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_binary_name(name: &str) -> Result<(), AppleError> {
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

fn validate_apple_version(
    field: &str,
    value: &str,
    max_components: usize,
) -> Result<(), AppleError> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > max_components
        || components.iter().any(|component| {
            component.is_empty() || !component.chars().all(|ch| ch.is_ascii_digit())
        })
    {
        return Err(AppleError::InvalidRequest(format!(
            "{field} `{value}` must contain one to {max_components} dot-separated numeric components"
        )));
    }
    Ok(())
}

fn insert_text(files: &mut BTreeMap<Utf8PathBuf, Vec<u8>>, path: &str, contents: String) {
    files.insert(Utf8PathBuf::from(path), contents.into_bytes());
}

fn render_app_info_plist(spec: &IosProjectSpec) -> String {
    let app = &spec.config.app;
    let mut extra = String::new();
    let launch_screen = match (spec.assets.is_some(), spec.asset_packaging) {
        (true, IosAssetPackaging::CompiledCatalog) => {
            extra.push_str("  <key>CFBundleIconName</key>\n  <string>AppIcon</string>\n");
            "  <dict>\n    <key>UIImageName</key>\n    <string>FerryLaunch</string>\n  </dict>"
        }
        (true, IosAssetPackaging::SdkOnlyResources) => {
            extra.push_str("  <key>CFBundleIconFile</key>\n  <string>FerryIcon</string>\n  <key>UILaunchImageFile</key>\n  <string>FerrySplash</string>\n");
            "  <dict>\n    <key>UIImageName</key>\n    <string>FerrySplash</string>\n  </dict>"
        }
        (false, _) => "  <dict/>",
    };
    if !spec.config.capabilities.deep_links.schemes.is_empty() {
        extra.push_str("  <key>CFBundleURLTypes</key>\n  <array>\n    <dict>\n      <key>CFBundleURLName</key>\n      <string>");
        extra.push_str(&xml_escape(&app.identifier));
        extra.push_str("</string>\n      <key>CFBundleURLSchemes</key>\n      <array>\n");
        for scheme in &spec.config.capabilities.deep_links.schemes {
            let _ = writeln!(extra, "        <string>{}</string>", xml_escape(scheme));
        }
        extra.push_str("      </array>\n    </dict>\n  </array>\n");
    }
    if spec.config.extensions.live_activity.enabled {
        extra.push_str("  <key>NSSupportsLiveActivities</key>\n  <true/>\n");
    }
    for (key, permission) in [
        ("NSCameraUsageDescription", &spec.config.permissions.camera),
        (
            "NSPhotoLibraryUsageDescription",
            &spec.config.permissions.photos,
        ),
        (
            "NSMicrophoneUsageDescription",
            &spec.config.permissions.microphone,
        ),
        (
            "NSLocationWhenInUseUsageDescription",
            &spec.config.permissions.location_when_in_use,
        ),
        (
            "NSLocalNetworkUsageDescription",
            &spec.config.permissions.local_network,
        ),
    ] {
        if permission.enabled {
            let purpose = permission
                .purpose
                .as_deref()
                .expect("validated enabled permission purpose");
            let _ = writeln!(
                extra,
                "  <key>{key}</key>\n  <string>{}</string>",
                xml_escape(purpose)
            );
        }
    }
    match app.window.theme {
        Theme::System => {}
        Theme::Light => {
            extra.push_str("  <key>UIUserInterfaceStyle</key>\n  <string>Light</string>\n");
        }
        Theme::Dark => {
            extra.push_str("  <key>UIUserInterfaceStyle</key>\n  <string>Dark</string>\n");
        }
    }
    let orientations = match app.window.orientation {
        Orientation::Automatic => [
            "UIInterfaceOrientationPortrait",
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ]
        .as_slice(),
        Orientation::Portrait => ["UIInterfaceOrientationPortrait"].as_slice(),
        Orientation::Landscape => [
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ]
        .as_slice(),
    };
    let orientation_values = orientations
        .iter()
        .map(|orientation| format!("    <string>{orientation}</string>"))
        .collect::<Vec<_>>()
        .join("\n");
    let build_version = format!(
        "{}.{}.{}",
        app.version.major, app.version.minor, app.version.patch
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>CFBundleDevelopmentRegion</key>\n  <string>en</string>\n  <key>CFBundleDisplayName</key>\n  <string>{display_name}</string>\n  <key>CFBundleExecutable</key>\n  <string>{executable}</string>\n  <key>CFBundleIdentifier</key>\n  <string>{identifier}</string>\n  <key>CFBundleInfoDictionaryVersion</key>\n  <string>6.0</string>\n  <key>CFBundleName</key>\n  <string>{display_name}</string>\n  <key>CFBundlePackageType</key>\n  <string>APPL</string>\n  <key>CFBundleShortVersionString</key>\n  <string>{display_version}</string>\n  <key>CFBundleVersion</key>\n  <string>{build_version}</string>\n  <key>LSRequiresIPhoneOS</key>\n  <true/>\n  <key>MinimumOSVersion</key>\n  <string>{minimum_version}</string>\n  <key>UILaunchScreen</key>\n{launch_screen}\n  <key>UIRequiredDeviceCapabilities</key>\n  <array>\n    <string>arm64</string>\n  </array>\n  <key>UISupportedInterfaceOrientations</key>\n  <array>\n{orientation_values}\n  </array>\n  <key>UIApplicationSupportsIndirectInputEvents</key>\n  <true/>\n{extra}</dict>\n</plist>\n",
        display_name = xml_escape(&app.name),
        executable = xml_escape(&spec.binary_name),
        identifier = xml_escape(&app.identifier),
        display_version = xml_escape(&app.display_version),
        build_version = build_version,
        minimum_version = xml_escape(&spec.config.ios.min_version),
        launch_screen = launch_screen,
    )
}

fn render_extension_info_plist(
    identifier: &str,
    executable: &str,
    display_version: &str,
    build_version: &str,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>CFBundleDisplayName</key>\n  <string>{executable}</string>\n  <key>CFBundleExecutable</key>\n  <string>{executable}</string>\n  <key>CFBundleIdentifier</key>\n  <string>{identifier}</string>\n  <key>CFBundleInfoDictionaryVersion</key>\n  <string>6.0</string>\n  <key>CFBundlePackageType</key>\n  <string>XPC!</string>\n  <key>CFBundleShortVersionString</key>\n  <string>{display_version}</string>\n  <key>CFBundleVersion</key>\n  <string>{build_version}</string>\n  <key>NSExtension</key>\n  <dict>\n    <key>NSExtensionPointIdentifier</key>\n    <string>com.apple.widgetkit-extension</string>\n  </dict>\n</dict>\n</plist>\n",
        executable = xml_escape(executable),
        identifier = xml_escape(identifier),
        display_version = xml_escape(display_version),
        build_version = xml_escape(build_version),
    )
}

fn render_entitlements(app_group: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>com.apple.security.application-groups</key>\n  <array>\n    <string>{}</string>\n  </array>\n</dict>\n</plist>\n",
        xml_escape(app_group)
    )
}

fn render_widget_source(app_group: &str) -> String {
    include_str!("../templates/FerryWidget.swift.tpl")
        .replace("{{widget_app_group}}", &swift_string_literal(app_group))
}

fn render_live_activity_source() -> String {
    "import ActivityKit\nimport FerryActivityModel\nimport SwiftUI\nimport WidgetKit\n\n@main\nstruct FerryLiveActivity: Widget {\n    var body: some WidgetConfiguration {\n        ActivityConfiguration(for: FerryActivityAttributes.self) { context in\n            VStack(alignment: .leading) {\n                Text(context.state.title).font(.headline)\n                Text(context.state.status)\n                ProgressView(value: context.state.progress)\n            }\n            .widgetURL(context.state.deepLink.flatMap(URL.init(string:)))\n        } dynamicIsland: { context in\n            DynamicIsland {\n                DynamicIslandExpandedRegion(.leading) { Text(context.state.leadingText) }\n                DynamicIslandExpandedRegion(.trailing) { Text(context.state.trailingText) }\n                DynamicIslandExpandedRegion(.bottom) { ProgressView(value: context.state.progress) }\n            } compactLeading: {\n                Text(context.state.leadingText)\n            } compactTrailing: {\n                Text(context.state.trailingText)\n            } minimal: {\n                Text(context.state.status.prefix(1))\n            }\n            .widgetURL(context.state.deepLink.flatMap(URL.init(string:)))\n        }\n    }\n}\n"
        .to_owned()
}

fn render_activity_model_source() -> String {
    format!(
        "import ActivityKit\nimport Foundation\n\n{}\n",
        include_str!("../templates/FerryActivityAttributes.swift.tpl").trim_end()
    )
}

fn render_runtime_bridge_source(spec: &IosProjectSpec) -> String {
    let enabled = |value: bool| if value { "true" } else { "false" };
    let live_activity = spec.config.extensions.live_activity.enabled;
    let model_import = if live_activity {
        "import FerryActivityModel\n"
    } else {
        ""
    };
    let attributes_declaration = if live_activity {
        String::new()
    } else {
        format!(
            "{}\n\n",
            include_str!("../templates/FerryActivityAttributes.swift.tpl").trim_end()
        )
    };
    let widget_group = spec
        .config
        .extensions
        .widget
        .app_group
        .as_deref()
        .map_or_else(|| "nil".to_owned(), swift_string_literal);
    include_str!("../templates/FerryRuntimeBridge.swift.tpl")
        .replace("{{activity_model_import}}\n", model_import)
        .replace(
            "{{activity_attributes_declaration}}\n\n",
            &attributes_declaration,
        )
        .replace(
            "{{storage_enabled}}",
            enabled(spec.config.capabilities.storage.enabled),
        )
        .replace(
            "{{network_enabled}}",
            enabled(spec.config.capabilities.network.mode != rustferry_core::NetworkMode::None),
        )
        .replace(
            "{{network_probe_enabled}}",
            enabled(matches!(
                spec.config.capabilities.network.mode,
                rustferry_core::NetworkMode::Optional | rustferry_core::NetworkMode::Required
            )),
        )
        .replace(
            "{{haptics_enabled}}",
            enabled(spec.config.capabilities.haptics.enabled),
        )
        .replace(
            "{{notifications_enabled}}",
            enabled(spec.config.capabilities.notifications.local),
        )
        .replace(
            "{{clipboard_enabled}}",
            enabled(spec.config.capabilities.clipboard.enabled),
        )
        .replace(
            "{{share_enabled}}",
            enabled(spec.config.capabilities.share.enabled),
        )
        .replace(
            "{{photos_enabled}}",
            enabled(spec.config.permissions.photos.enabled),
        )
        .replace(
            "{{camera_enabled}}",
            enabled(spec.config.permissions.camera.enabled),
        )
        .replace(
            "{{microphone_enabled}}",
            enabled(spec.config.permissions.microphone.enabled),
        )
        .replace(
            "{{location_enabled}}",
            enabled(spec.config.permissions.location_when_in_use.enabled),
        )
        .replace("{{widget_app_group}}", &widget_group)
        .replace(
            "{{live_activity_enabled}}",
            enabled(spec.config.extensions.live_activity.enabled),
        )
        .replace(
            "{{deep_link_schemes}}",
            &swift_string_set(&spec.config.capabilities.deep_links.schemes),
        )
        .replace(
            "{{deep_link_hosts}}",
            &swift_string_set(&spec.config.capabilities.deep_links.allowed_hosts),
        )
        .replace(
            "{{deep_link_actions}}",
            &swift_string_set(&spec.config.capabilities.deep_links.allowed_actions),
        )
}

fn render_resource_metadata(
    spec: &IosProjectSpec,
    platform: IosProjectPlatform,
) -> Result<String, AppleError> {
    let value = serde_json::json!({
        "schema_version": 1,
        "generator": "cargo-ferry",
        "ui_backend": "slint-1.17.1",
        "rust_target": platform.rust_target(),
        "bundle_identifier": spec.config.app.identifier,
    });
    serde_json::to_string_pretty(&value)
        .map(|mut output| {
            output.push('\n');
            output
        })
        .map_err(|error| {
            AppleError::InvalidRequest(format!("could not encode iOS resource metadata: {error}"))
        })
}

fn render_scheme(binary_name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Scheme LastUpgradeVersion=\"2660\" version=\"1.7\">\n  <BuildAction parallelizeBuildables=\"YES\" buildImplicitDependencies=\"YES\">\n    <BuildActionEntries>\n      <BuildActionEntry buildForTesting=\"YES\" buildForRunning=\"YES\" buildForProfiling=\"YES\" buildForArchiving=\"YES\" buildForAnalyzing=\"YES\">\n        <BuildableReference BuildableIdentifier=\"primary\" BlueprintIdentifier=\"{}\" BuildableName=\"{}.app\" BlueprintName=\"FerryApp\" ReferencedContainer=\"container:FerryHost.xcodeproj\"/>\n      </BuildActionEntry>\n    </BuildActionEntries>\n  </BuildAction>\n  <TestAction buildConfiguration=\"Debug\" selectedDebuggerIdentifier=\"Xcode.DebuggerFoundation.Debugger.LLDB\" selectedLauncherIdentifier=\"Xcode.DebuggerFoundation.Launcher.LLDB\" shouldUseLaunchSchemeArgsEnv=\"YES\"/>\n  <LaunchAction buildConfiguration=\"Debug\" selectedDebuggerIdentifier=\"Xcode.DebuggerFoundation.Debugger.LLDB\" selectedLauncherIdentifier=\"Xcode.DebuggerFoundation.Launcher.LLDB\" launchStyle=\"0\" useCustomWorkingDirectory=\"NO\" ignoresPersistentStateOnLaunch=\"NO\" debugDocumentVersioning=\"YES\" debugServiceExtension=\"internal\" allowLocationSimulation=\"YES\">\n    <BuildableProductRunnable runnableDebuggingMode=\"0\">\n      <BuildableReference BuildableIdentifier=\"primary\" BlueprintIdentifier=\"{}\" BuildableName=\"{}.app\" BlueprintName=\"FerryApp\" ReferencedContainer=\"container:FerryHost.xcodeproj\"/>\n    </BuildableProductRunnable>\n  </LaunchAction>\n  <ProfileAction buildConfiguration=\"Release\" shouldUseLaunchSchemeArgsEnv=\"YES\" savedToolIdentifier=\"\" useCustomWorkingDirectory=\"NO\" debugDocumentVersioning=\"YES\"/>\n  <AnalyzeAction buildConfiguration=\"Debug\"/>\n  <ArchiveAction buildConfiguration=\"Release\" revealArchiveInOrganizer=\"YES\"/>\n</Scheme>\n",
        id(15),
        xml_escape(binary_name),
        id(15),
        xml_escape(binary_name),
    )
}

fn render_pbxproj(spec: &IosProjectSpec, platform: IosProjectPlatform) -> String {
    let project = render_simulator_pbxproj(spec);
    match platform {
        IosProjectPlatform::Simulator => project,
        IosProjectPlatform::DeviceUnsigned => project
            .replace("SDKROOT = iphonesimulator", "SDKROOT = iphoneos")
            .replace(
                "SUPPORTED_PLATFORMS = iphonesimulator",
                "SUPPORTED_PLATFORMS = iphoneos",
            )
            .replace(
                "AD_HOC_CODE_SIGNING_ALLOWED = YES",
                "AD_HOC_CODE_SIGNING_ALLOWED = NO",
            )
            .replace("CODE_SIGN_IDENTITY = \"-\"", "CODE_SIGN_IDENTITY = \"\"")
            .replace("CODE_SIGNING_ALLOWED = YES", "CODE_SIGNING_ALLOWED = NO")
            .replace("CODE_SIGNING_REQUIRED = YES", "CODE_SIGNING_REQUIRED = NO")
            .replace(
                "ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, );",
                "ATTRIBUTES = (RemoveHeadersOnCopy, );",
            ),
    }
}

#[allow(clippy::too_many_lines, clippy::write_with_newline)]
fn render_simulator_pbxproj(spec: &IosProjectSpec) -> String {
    let binary = pbx_quote(&spec.binary_name);
    let app_product = pbx_quote(&format!("{}.app", spec.binary_name));
    let bundle = pbx_quote(&spec.config.app.identifier);
    let min_version = pbx_quote(&spec.config.ios.min_version);
    let marketing = pbx_quote(&spec.config.app.display_version);
    let build_version = pbx_quote(&format!(
        "{}.{}.{}",
        spec.config.app.version.major, spec.config.app.version.minor, spec.config.app.version.patch
    ));
    let widget = spec.config.extensions.widget.enabled;
    let live_activity = spec.config.extensions.live_activity.enabled;
    let assets = spec.assets.is_some();
    let compiled_assets = assets && spec.asset_packaging == IosAssetPackaging::CompiledCatalog;
    let sdk_only_assets = assets && spec.asset_packaging == IosAssetPackaging::SdkOnlyResources;
    let mut output = String::from(
        "// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tclasses = {};\n\tobjectVersion = 77;\n\tobjects = {\n\n",
    );

    output.push_str("/* Begin PBXBuildFile section */\n");
    let _ = writeln!(
        output,
        "\t\t{} /* {} in Install Rust Executable */ = {{isa = PBXBuildFile; fileRef = {} /* {} */; }};",
        id(10),
        spec.binary_name,
        id(11),
        spec.binary_name
    );
    let _ = writeln!(
        output,
        "\t\t{} /* FerryResources.json in Resources */ = {{isa = PBXBuildFile; fileRef = {} /* FerryResources.json */; }};",
        id(12),
        id(6)
    );
    if compiled_assets {
        let _ = writeln!(
            output,
            "\t\t{} /* Assets.xcassets in Resources */ = {{isa = PBXBuildFile; fileRef = {} /* Assets.xcassets */; }};",
            id(9),
            id(5)
        );
    } else if sdk_only_assets {
        let _ = writeln!(
            output,
            "\t\t{} /* FerryIcon.png in Resources */ = {{isa = PBXBuildFile; fileRef = {} /* FerryIcon.png */; }};",
            id(9),
            id(5)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerrySplash.png in Resources */ = {{isa = PBXBuildFile; fileRef = {} /* FerrySplash.png */; }};",
            id(18),
            id(19)
        );
    }
    let _ = writeln!(
        output,
        "\t\t{} /* FerryRuntimeBridge.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {} /* FerryRuntimeBridge.swift */; }};",
        id(80),
        id(81)
    );
    let _ = writeln!(
        output,
        "\t\t{} /* FerryRuntimeBridge.framework in Embed Frameworks */ = {{isa = PBXBuildFile; fileRef = {} /* FerryRuntimeBridge.framework */; settings = {{ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, ); }}; }};",
        id(84),
        id(82)
    );
    if widget {
        let _ = writeln!(
            output,
            "\t\t{} /* Widget.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {} /* Widget.swift */; }};",
            id(34),
            id(30)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryWidgetExtension.appex in Embed App Extensions */ = {{isa = PBXBuildFile; fileRef = {} /* FerryWidgetExtension.appex */; settings = {{ATTRIBUTES = (RemoveHeadersOnCopy, ); }}; }};",
            id(40),
            id(33)
        );
    }
    if live_activity {
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityAttributes.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {} /* FerryActivityAttributes.swift */; }};",
            id(100),
            id(101)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityModel.framework in Embed Frameworks */ = {{isa = PBXBuildFile; fileRef = {} /* FerryActivityModel.framework */; settings = {{ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, ); }}; }};",
            id(103),
            id(102)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityModel.framework in RuntimeBridge Frameworks */ = {{isa = PBXBuildFile; fileRef = {} /* FerryActivityModel.framework */; }};",
            id(104),
            id(102)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityModel.framework in Live Activity Frameworks */ = {{isa = PBXBuildFile; fileRef = {} /* FerryActivityModel.framework */; }};",
            id(105),
            id(102)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* LiveActivity.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {} /* LiveActivity.swift */; }};",
            id(54),
            id(50)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryLiveActivityExtension.appex in Embed App Extensions */ = {{isa = PBXBuildFile; fileRef = {} /* FerryLiveActivityExtension.appex */; settings = {{ATTRIBUTES = (RemoveHeadersOnCopy, ); }}; }};",
            id(60),
            id(53)
        );
    }
    output.push_str("/* End PBXBuildFile section */\n\n");

    output.push_str("/* Begin PBXContainerItemProxy section */\n");
    let _ = writeln!(
        output,
        "\t\t{} /* PBXContainerItemProxy */ = {{isa = PBXContainerItemProxy; containerPortal = {} /* Project object */; proxyType = 1; remoteGlobalIDString = {}; remoteInfo = FerryRuntimeBridge; }};",
        id(86),
        id(1),
        id(90)
    );
    if widget {
        let _ = writeln!(
            output,
            "\t\t{} /* PBXContainerItemProxy */ = {{isa = PBXContainerItemProxy; containerPortal = {} /* Project object */; proxyType = 1; remoteGlobalIDString = {}; remoteInfo = FerryWidgetExtension; }};",
            id(41),
            id(1),
            id(36)
        );
    }
    if live_activity {
        let _ = writeln!(
            output,
            "\t\t{} /* PBXContainerItemProxy */ = {{isa = PBXContainerItemProxy; containerPortal = {} /* Project object */; proxyType = 1; remoteGlobalIDString = {}; remoteInfo = FerryLiveActivityExtension; }};",
            id(61),
            id(1),
            id(56)
        );
        for (proxy, target, owner) in [
            (114, 108, "FerryActivityModel"),
            (116, 108, "FerryActivityModel"),
            (118, 108, "FerryActivityModel"),
        ] {
            let _ = writeln!(
                output,
                "\t\t{} /* PBXContainerItemProxy */ = {{isa = PBXContainerItemProxy; containerPortal = {} /* Project object */; proxyType = 1; remoteGlobalIDString = {}; remoteInfo = {}; }};",
                id(proxy),
                id(1),
                id(target),
                owner
            );
        }
    }
    output.push_str("/* End PBXContainerItemProxy section */\n\n");

    output.push_str("/* Begin PBXCopyFilesBuildPhase section */\n");
    let _ = write!(
        output,
        "\t\t{} /* Install Rust Executable */ = {{\n\t\t\tisa = PBXCopyFilesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tdstPath = \"\";\n\t\t\tdstSubfolderSpec = 1;\n\t\t\tfiles = ({} /* {} in Install Rust Executable */,);\n\t\t\tname = \"Install Rust Executable\";\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}};\n",
        id(14),
        id(10),
        spec.binary_name
    );
    let _ = write!(
        output,
        "\t\t{} /* Embed Frameworks */ = {{\n\t\t\tisa = PBXCopyFilesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tdstPath = \"\";\n\t\t\tdstSubfolderSpec = 10;\n\t\t\tfiles = ({} /* FerryRuntimeBridge.framework in Embed Frameworks */,",
        id(93),
        id(84)
    );
    if live_activity {
        let _ = write!(
            output,
            " {} /* FerryActivityModel.framework in Embed Frameworks */,",
            id(103)
        );
    }
    output.push_str(
        ");\n\t\t\tname = \"Embed Frameworks\";\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t};\n",
    );
    if widget || live_activity {
        let _ = write!(
            output,
            "\t\t{} /* Embed App Extensions */ = {{\n\t\t\tisa = PBXCopyFilesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tdstPath = \"\";\n\t\t\tdstSubfolderSpec = 13;\n\t\t\tfiles = (\n",
            id(70)
        );
        if widget {
            let _ = writeln!(
                output,
                "\t\t\t\t{} /* FerryWidgetExtension.appex in Embed App Extensions */,",
                id(40)
            );
        }
        if live_activity {
            let _ = writeln!(
                output,
                "\t\t\t\t{} /* FerryLiveActivityExtension.appex in Embed App Extensions */,",
                id(60)
            );
        }
        output.push_str("\t\t\t);\n\t\t\tname = \"Embed App Extensions\";\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t};\n");
    }
    output.push_str("/* End PBXCopyFilesBuildPhase section */\n\n");

    output.push_str("/* Begin PBXFileReference section */\n");
    let _ = writeln!(
        output,
        "\t\t{} /* {} */ = {{isa = PBXFileReference; explicitFileType = \"compiled.mach-o.executable\"; path = {}; sourceTree = \"<group>\"; }};",
        id(11),
        spec.binary_name,
        binary
    );
    let _ = writeln!(
        output,
        "\t\t{} /* {}.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = {}; sourceTree = BUILT_PRODUCTS_DIR; }};",
        id(4),
        spec.binary_name,
        app_product
    );
    if compiled_assets {
        let _ = writeln!(
            output,
            "\t\t{} /* Assets.xcassets */ = {{isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = Assets.xcassets; sourceTree = \"<group>\"; }};",
            id(5)
        );
    } else if sdk_only_assets {
        let _ = writeln!(
            output,
            "\t\t{} /* FerryIcon.png */ = {{isa = PBXFileReference; lastKnownFileType = image.png; path = FerryIcon.png; sourceTree = \"<group>\"; }};",
            id(5)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerrySplash.png */ = {{isa = PBXFileReference; lastKnownFileType = image.png; path = FerrySplash.png; sourceTree = \"<group>\"; }};",
            id(19)
        );
    }
    let _ = writeln!(
        output,
        "\t\t{} /* FerryResources.json */ = {{isa = PBXFileReference; lastKnownFileType = text.json; path = FerryResources.json; sourceTree = \"<group>\"; }};",
        id(6)
    );
    let _ = writeln!(
        output,
        "\t\t{} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = \"<group>\"; }};",
        id(7)
    );
    let _ = writeln!(
        output,
        "\t\t{} /* FerryRuntimeBridge.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = FerryRuntimeBridge.swift; sourceTree = \"<group>\"; }};",
        id(81)
    );
    let _ = writeln!(
        output,
        "\t\t{} /* FerryRuntimeBridge.framework */ = {{isa = PBXFileReference; explicitFileType = wrapper.framework; includeInIndex = 0; path = FerryRuntimeBridge.framework; sourceTree = BUILT_PRODUCTS_DIR; }};",
        id(82)
    );
    let _ = writeln!(
        output,
        "\t\t{} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = \"<group>\"; }};",
        id(83)
    );
    if widget {
        let _ = writeln!(
            output,
            "\t\t{} /* App.entitlements */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; path = App.entitlements; sourceTree = \"<group>\"; }};",
            id(8)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* Widget.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = Widget.swift; sourceTree = \"<group>\"; }};",
            id(30)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = \"<group>\"; }};",
            id(31)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* Widget.entitlements */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; path = Widget.entitlements; sourceTree = \"<group>\"; }};",
            id(32)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryWidgetExtension.appex */ = {{isa = PBXFileReference; explicitFileType = \"wrapper.app-extension\"; includeInIndex = 0; path = FerryWidgetExtension.appex; sourceTree = BUILT_PRODUCTS_DIR; }};",
            id(33)
        );
    }
    if live_activity {
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityAttributes.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = FerryActivityAttributes.swift; sourceTree = \"<group>\"; }};",
            id(101)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryActivityModel.framework */ = {{isa = PBXFileReference; explicitFileType = wrapper.framework; includeInIndex = 0; path = FerryActivityModel.framework; sourceTree = BUILT_PRODUCTS_DIR; }};",
            id(102)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = \"<group>\"; }};",
            id(106)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* LiveActivity.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = LiveActivity.swift; sourceTree = \"<group>\"; }};",
            id(50)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = \"<group>\"; }};",
            id(51)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerryLiveActivityExtension.appex */ = {{isa = PBXFileReference; explicitFileType = \"wrapper.app-extension\"; includeInIndex = 0; path = FerryLiveActivityExtension.appex; sourceTree = BUILT_PRODUCTS_DIR; }};",
            id(53)
        );
    }
    output.push_str("/* End PBXFileReference section */\n\n");

    output.push_str("/* Begin PBXGroup section */\n");
    let _ = write!(
        output,
        "\t\t{} = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* {} */,\n\t\t\t\t{} /* Info.plist */,\n\t\t\t\t{} /* FerryResources.json */,\n",
        id(2),
        id(11),
        spec.binary_name,
        id(7),
        id(6)
    );
    if compiled_assets {
        let _ = writeln!(output, "\t\t\t\t{} /* Assets.xcassets */,", id(5));
    } else if sdk_only_assets {
        let _ = writeln!(output, "\t\t\t\t{} /* FerryIcon.png */,", id(5));
        let _ = writeln!(output, "\t\t\t\t{} /* FerrySplash.png */,", id(19));
    }
    let _ = writeln!(output, "\t\t\t\t{} /* RuntimeBridge */,", id(91));
    if widget {
        let _ = writeln!(output, "\t\t\t\t{} /* App.entitlements */,", id(8));
        let _ = writeln!(output, "\t\t\t\t{} /* WidgetExtension */,", id(38));
    }
    if live_activity {
        let _ = writeln!(output, "\t\t\t\t{} /* ActivityModel */,", id(107));
        let _ = writeln!(output, "\t\t\t\t{} /* LiveActivityExtension */,", id(58));
    }
    let _ = write!(
        output,
        "\t\t\t\t{} /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n",
        id(3)
    );
    let _ = write!(
        output,
        "\t\t{} /* Products */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* {}.app */,\n",
        id(3),
        id(4),
        spec.binary_name
    );
    let _ = writeln!(
        output,
        "\t\t\t\t{} /* FerryRuntimeBridge.framework */,",
        id(82)
    );
    if widget {
        let _ = writeln!(
            output,
            "\t\t\t\t{} /* FerryWidgetExtension.appex */,",
            id(33)
        );
    }
    if live_activity {
        let _ = writeln!(
            output,
            "\t\t\t\t{} /* FerryActivityModel.framework */,",
            id(102)
        );
        let _ = writeln!(
            output,
            "\t\t\t\t{} /* FerryLiveActivityExtension.appex */,",
            id(53)
        );
    }
    output.push_str("\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n");
    let _ = write!(
        output,
        "\t\t{} /* RuntimeBridge */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* FerryRuntimeBridge.swift */,\n\t\t\t\t{} /* Info.plist */,\n\t\t\t);\n\t\t\tpath = RuntimeBridge;\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n",
        id(91),
        id(81),
        id(83)
    );
    if widget {
        let _ = write!(
            output,
            "\t\t{} /* WidgetExtension */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* Widget.swift */,\n\t\t\t\t{} /* Info.plist */,\n\t\t\t\t{} /* Widget.entitlements */,\n\t\t\t);\n\t\t\tpath = WidgetExtension;\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n",
            id(38),
            id(30),
            id(31),
            id(32)
        );
    }
    if live_activity {
        let _ = write!(
            output,
            "\t\t{} /* ActivityModel */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* FerryActivityAttributes.swift */,\n\t\t\t\t{} /* Info.plist */,\n\t\t\t);\n\t\t\tpath = ActivityModel;\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n",
            id(107),
            id(101),
            id(106)
        );
        let _ = write!(
            output,
            "\t\t{} /* LiveActivityExtension */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{} /* LiveActivity.swift */,\n\t\t\t\t{} /* Info.plist */,\n\t\t\t);\n\t\t\tpath = LiveActivityExtension;\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n",
            id(58),
            id(50),
            id(51)
        );
    }
    output.push_str("/* End PBXGroup section */\n\n");

    output.push_str("/* Begin PBXNativeTarget section */\n");
    let _ = write!(
        output,
        "\t\t{} /* FerryApp */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryApp\" */;\n\t\t\tbuildPhases = (\n\t\t\t\t{} /* Resources */,\n\t\t\t\t{} /* Install Rust Executable */,\n\t\t\t\t{} /* Embed Frameworks */,\n",
        id(15),
        id(25),
        id(13),
        id(14),
        id(93)
    );
    if widget || live_activity {
        let _ = writeln!(output, "\t\t\t\t{} /* Embed App Extensions */,", id(70));
    }
    let _ = writeln!(
        output,
        "\t\t\t);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = (\n\t\t\t\t{} /* PBXTargetDependency */,",
        id(87)
    );
    if widget {
        let _ = writeln!(output, "\t\t\t\t{} /* PBXTargetDependency */,", id(42));
    }
    if live_activity {
        let _ = writeln!(output, "\t\t\t\t{} /* PBXTargetDependency */,", id(115));
        let _ = writeln!(output, "\t\t\t\t{} /* PBXTargetDependency */,", id(62));
    }
    let _ = write!(
        output,
        "\t\t\t);\n\t\t\tname = FerryApp;\n\t\t\tproductName = {};\n\t\t\tproductReference = {} /* {}.app */;\n\t\t\tproductType = \"com.apple.product-type.application\";\n\t\t}};\n",
        binary,
        id(4),
        spec.binary_name
    );
    let _ = write!(
        output,
        "\t\t{} /* FerryRuntimeBridge */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryRuntimeBridge\" */;\n\t\t\tbuildPhases = ({} /* Sources */,",
        id(90),
        id(95),
        id(92)
    );
    if live_activity {
        let _ = write!(output, " {} /* Frameworks */,", id(113));
    }
    output.push_str(");\n\t\t\tbuildRules = ();\n\t\t\tdependencies = (");
    if live_activity {
        let _ = write!(output, "{} /* PBXTargetDependency */,", id(117));
    }
    let _ = write!(
        output,
        ");\n\t\t\tname = FerryRuntimeBridge;\n\t\t\tproductName = FerryRuntimeBridge;\n\t\t\tproductReference = {} /* FerryRuntimeBridge.framework */;\n\t\t\tproductType = \"com.apple.product-type.framework\";\n\t\t}};\n",
        id(82)
    );
    if widget {
        let _ = write!(
            output,
            "\t\t{} /* FerryWidgetExtension */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryWidgetExtension\" */;\n\t\t\tbuildPhases = ({} /* Sources */,);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ();\n\t\t\tname = FerryWidgetExtension;\n\t\t\tproductName = FerryWidgetExtension;\n\t\t\tproductReference = {} /* FerryWidgetExtension.appex */;\n\t\t\tproductType = \"com.apple.product-type.app-extension\";\n\t\t}};\n",
            id(36),
            id(39),
            id(35),
            id(33)
        );
    }
    if live_activity {
        let _ = write!(
            output,
            "\t\t{} /* FerryActivityModel */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryActivityModel\" */;\n\t\t\tbuildPhases = ({} /* Sources */,);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ();\n\t\t\tname = FerryActivityModel;\n\t\t\tproductName = FerryActivityModel;\n\t\t\tproductReference = {} /* FerryActivityModel.framework */;\n\t\t\tproductType = \"com.apple.product-type.framework\";\n\t\t}};\n",
            id(108),
            id(112),
            id(109),
            id(102)
        );
        let _ = write!(
            output,
            "\t\t{} /* FerryLiveActivityExtension */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryLiveActivityExtension\" */;\n\t\t\tbuildPhases = ({} /* Sources */, {} /* Frameworks */,);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({} /* PBXTargetDependency */,);\n\t\t\tname = FerryLiveActivityExtension;\n\t\t\tproductName = FerryLiveActivityExtension;\n\t\t\tproductReference = {} /* FerryLiveActivityExtension.appex */;\n\t\t\tproductType = \"com.apple.product-type.app-extension\";\n\t\t}};\n",
            id(56),
            id(59),
            id(55),
            id(94),
            id(119),
            id(53)
        );
    }
    output.push_str("/* End PBXNativeTarget section */\n\n");

    output.push_str("/* Begin PBXProject section */\n");
    let _ = write!(
        output,
        "\t\t{} /* Project object */ = {{\n\t\t\tisa = PBXProject;\n\t\t\tattributes = {{\n\t\t\t\tBuildIndependentTargetsInParallel = YES;\n\t\t\t\tLastSwiftUpdateCheck = 2660;\n\t\t\t\tLastUpgradeCheck = 2660;\n\t\t\t}};\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXProject \"FerryHost\" */;\n\t\t\tcompatibilityVersion = \"Xcode 15.0\";\n\t\t\tdevelopmentRegion = en;\n\t\t\thasScannedForEncodings = 0;\n\t\t\tknownRegions = (en, Base,);\n\t\t\tmainGroup = {};\n\t\t\tproductRefGroup = {} /* Products */;\n\t\t\tprojectDirPath = \"\";\n\t\t\tprojectRoot = \"\";\n\t\t\ttargets = (\n\t\t\t\t{} /* FerryApp */,\n",
        id(1),
        id(22),
        id(2),
        id(3),
        id(15)
    );
    let _ = writeln!(output, "\t\t\t\t{} /* FerryRuntimeBridge */,", id(90));
    if widget {
        let _ = writeln!(output, "\t\t\t\t{} /* FerryWidgetExtension */,", id(36));
    }
    if live_activity {
        let _ = writeln!(output, "\t\t\t\t{} /* FerryActivityModel */,", id(108));
        let _ = writeln!(
            output,
            "\t\t\t\t{} /* FerryLiveActivityExtension */,",
            id(56)
        );
    }
    output.push_str("\t\t\t);\n\t\t};\n/* End PBXProject section */\n\n");

    output.push_str("/* Begin PBXResourcesBuildPhase section */\n");
    if compiled_assets {
        let _ = write!(
            output,
            "\t\t{} /* Resources */ = {{isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* Assets.xcassets in Resources */, {} /* FerryResources.json in Resources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(13),
            id(9),
            id(12)
        );
    } else if sdk_only_assets {
        let _ = write!(
            output,
            "\t\t{} /* Resources */ = {{isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryIcon.png in Resources */, {} /* FerrySplash.png in Resources */, {} /* FerryResources.json in Resources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(13),
            id(9),
            id(18),
            id(12)
        );
    } else {
        let _ = write!(
            output,
            "\t\t{} /* Resources */ = {{isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryResources.json in Resources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(13),
            id(12)
        );
    }
    output.push_str("/* End PBXResourcesBuildPhase section */\n\n");

    if live_activity {
        output.push_str("/* Begin PBXFrameworksBuildPhase section */\n");
        let _ = write!(
            output,
            "\t\t{} /* Frameworks */ = {{isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryActivityModel.framework in RuntimeBridge Frameworks */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(113),
            id(104)
        );
        let _ = write!(
            output,
            "\t\t{} /* Frameworks */ = {{isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryActivityModel.framework in Live Activity Frameworks */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(94),
            id(105)
        );
        output.push_str("/* End PBXFrameworksBuildPhase section */\n\n");
    }

    output.push_str("/* Begin PBXSourcesBuildPhase section */\n");
    let _ = write!(
        output,
        "\t\t{} /* Sources */ = {{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryRuntimeBridge.swift in Sources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
        id(92),
        id(80)
    );
    if widget {
        let _ = write!(
            output,
            "\t\t{} /* Sources */ = {{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* Widget.swift in Sources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(35),
            id(34)
        );
    }
    if live_activity {
        let _ = write!(
            output,
            "\t\t{} /* Sources */ = {{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryActivityAttributes.swift in Sources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(109),
            id(100)
        );
        let _ = write!(
            output,
            "\t\t{} /* Sources */ = {{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({} /* LiveActivity.swift in Sources */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(55),
            id(54)
        );
    }
    output.push_str("/* End PBXSourcesBuildPhase section */\n\n");

    output.push_str("/* Begin PBXTargetDependency section */\n");
    let _ = writeln!(
        output,
        "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryRuntimeBridge */; targetProxy = {} /* PBXContainerItemProxy */; }};",
        id(87),
        id(90),
        id(86)
    );
    if widget {
        let _ = writeln!(
            output,
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryWidgetExtension */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(42),
            id(36),
            id(41)
        );
    }
    if live_activity {
        let _ = writeln!(
            output,
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryLiveActivityExtension */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(62),
            id(56),
            id(61)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryActivityModel */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(115),
            id(108),
            id(114)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryActivityModel */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(117),
            id(108),
            id(116)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryActivityModel */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(119),
            id(108),
            id(118)
        );
    }
    output.push_str("/* End PBXTargetDependency section */\n\n");

    output.push_str("/* Begin XCBuildConfiguration section */\n");
    for (config_id, name) in [(20, "Debug"), (21, "Release")] {
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{CLANG_ENABLE_MODULES = YES; IPHONEOS_DEPLOYMENT_TARGET = {}; SDKROOT = iphonesimulator; }}; name = {}; }};\n",
            id(config_id),
            name,
            min_version,
            name
        );
    }
    for (config_id, name) in [(23, "Debug"), (24, "Release")] {
        let code_sign_entitlements = if widget {
            "CODE_SIGN_ENTITLEMENTS = App.entitlements; "
        } else {
            ""
        };
        let asset_catalog_settings = if compiled_assets {
            "ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon; "
        } else {
            ""
        };
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; ARCHS = arm64; {}ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS = NO; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; {}COMPRESS_PNG_FILES = NO; CURRENT_PROJECT_VERSION = {}; GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = Info.plist; IPHONEOS_DEPLOYMENT_TARGET = {}; LD_RUNPATH_SEARCH_PATHS = (\"$(inherited)\", \"@executable_path/Frameworks\",); MARKETING_VERSION = {}; ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = {}; PRODUCT_NAME = {}; SDKROOT = iphonesimulator; SKIP_INSTALL = NO; STRIP_PNG_TEXT = NO; SUPPORTED_PLATFORMS = iphonesimulator; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
            id(config_id),
            name,
            asset_catalog_settings,
            code_sign_entitlements,
            build_version,
            min_version,
            marketing,
            bundle,
            binary,
            name
        );
    }
    for (config_id, name) in [(96, "Debug"), (97, "Release")] {
        let activity_model_runpath = if live_activity {
            "LD_RUNPATH_SEARCH_PATHS = (\"$(inherited)\", \"@loader_path\",); "
        } else {
            ""
        };
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; APPLICATION_EXTENSION_API_ONLY = NO; ARCHS = arm64; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; CURRENT_PROJECT_VERSION = 1; DEFINES_MODULE = YES; DYLIB_INSTALL_NAME_BASE = \"@rpath\"; GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = RuntimeBridge/Info.plist; IPHONEOS_DEPLOYMENT_TARGET = {}; {}MARKETING_VERSION = 1.0; ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = org.rustferry.runtime-bridge; PRODUCT_NAME = FerryRuntimeBridge; SDKROOT = iphonesimulator; SKIP_INSTALL = YES; SUPPORTED_PLATFORMS = iphonesimulator; SWIFT_EMIT_LOC_STRINGS = NO; SWIFT_INSTALL_OBJC_HEADER = YES; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
            id(config_id),
            name,
            min_version,
            activity_model_runpath,
            name
        );
    }
    if live_activity {
        for (config_id, name) in [(110, "Debug"), (111, "Release")] {
            let _ = write!(
                output,
                "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; APPLICATION_EXTENSION_API_ONLY = YES; ARCHS = arm64; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; CURRENT_PROJECT_VERSION = 1; DEFINES_MODULE = YES; DYLIB_INSTALL_NAME_BASE = \"@rpath\"; GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = ActivityModel/Info.plist; IPHONEOS_DEPLOYMENT_TARGET = {}; MARKETING_VERSION = 1.0; ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = org.rustferry.activity-model; PRODUCT_NAME = FerryActivityModel; SDKROOT = iphonesimulator; SKIP_INSTALL = YES; SUPPORTED_PLATFORMS = iphonesimulator; SWIFT_EMIT_LOC_STRINGS = NO; SWIFT_INSTALL_OBJC_HEADER = YES; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
                id(config_id),
                name,
                min_version,
                name
            );
        }
    }
    if widget {
        render_extension_build_configs(
            &mut output,
            37,
            38_000,
            "WidgetExtension/Info.plist",
            Some("WidgetExtension/Widget.entitlements"),
            &format!("{}.widget", spec.config.app.identifier),
            "FerryWidgetExtension",
            &spec.config.ios.min_version,
        );
    }
    if live_activity {
        render_extension_build_configs(
            &mut output,
            57,
            58_000,
            "LiveActivityExtension/Info.plist",
            None,
            &format!("{}.liveactivity", spec.config.app.identifier),
            "FerryLiveActivityExtension",
            &spec.config.ios.min_version,
        );
    }
    output.push_str("/* End XCBuildConfiguration section */\n\n");

    output.push_str("/* Begin XCConfigurationList section */\n");
    let _ = write!(
        output,
        "\t\t{} /* Build configuration list for PBXProject \"FerryHost\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
        id(22),
        id(20),
        id(21)
    );
    let _ = write!(
        output,
        "\t\t{} /* Build configuration list for PBXNativeTarget \"FerryApp\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
        id(25),
        id(23),
        id(24)
    );
    let _ = write!(
        output,
        "\t\t{} /* Build configuration list for PBXNativeTarget \"FerryRuntimeBridge\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
        id(95),
        id(96),
        id(97)
    );
    if live_activity {
        let _ = write!(
            output,
            "\t\t{} /* Build configuration list for PBXNativeTarget \"FerryActivityModel\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
            id(112),
            id(110),
            id(111)
        );
    }
    if widget {
        let _ = write!(
            output,
            "\t\t{} /* Build configuration list for PBXNativeTarget \"FerryWidgetExtension\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
            id(39),
            id(37),
            id(38_000)
        );
    }
    if live_activity {
        let _ = write!(
            output,
            "\t\t{} /* Build configuration list for PBXNativeTarget \"FerryLiveActivityExtension\" */ = {{isa = XCConfigurationList; buildConfigurations = ({} /* Debug */, {} /* Release */,); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }};\n",
            id(59),
            id(57),
            id(58_000)
        );
    }
    output.push_str("/* End XCConfigurationList section */\n\n");
    let _ = write!(
        output,
        "\t}};\n\trootObject = {} /* Project object */;\n}}\n",
        id(1)
    );
    output
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::write_with_newline)]
fn render_extension_build_configs(
    output: &mut String,
    debug_id: u64,
    release_id: u64,
    info_plist: &str,
    entitlements: Option<&str>,
    identifier: &str,
    product_name: &str,
    min_version: &str,
) {
    for (config_id, name) in [(debug_id, "Debug"), (release_id, "Release")] {
        let entitlement_setting = entitlements
            .map(|path| format!("CODE_SIGN_ENTITLEMENTS = {}; ", pbx_quote(path)))
            .unwrap_or_default();
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; APPLICATION_EXTENSION_API_ONLY = YES; ARCHS = arm64; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; {}GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = {}; IPHONEOS_DEPLOYMENT_TARGET = {}; LD_RUNPATH_SEARCH_PATHS = (\"$(inherited)\", \"@executable_path/Frameworks\", \"@executable_path/../../Frameworks\",); ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = {}; PRODUCT_NAME = {}; SDKROOT = iphonesimulator; SKIP_INSTALL = YES; SUPPORTED_PLATFORMS = iphonesimulator; SWIFT_EMIT_LOC_STRINGS = YES; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
            id(config_id),
            name,
            entitlement_setting,
            pbx_quote(info_plist),
            pbx_quote(min_version),
            pbx_quote(identifier),
            pbx_quote(product_name),
            name
        );
    }
}

fn id(number: u64) -> String {
    format!("AA{number:022X}")
}

fn pbx_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn swift_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{{{:X}}}", u32::from(character));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn swift_string_literal(value: &str) -> String {
    format!("\"{}\"", swift_escape(value))
}

fn swift_string_set(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| swift_string_literal(value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn validate_relative_path(path: &Utf8Path) -> Result<(), AppleError> {
    if path.is_absolute() || path.as_str().is_empty() {
        return Err(AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: "generated paths must be non-empty and relative".to_owned(),
        });
    }
    if path
        .components()
        .any(|component| !matches!(component, Utf8Component::Normal(_)))
    {
        return Err(AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: "generated paths cannot contain parent, root, or prefix components".to_owned(),
        });
    }
    Ok(())
}

fn reject_symlink(path: &Utf8Path) -> Result<(), AppleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AppleError::UnsafeGeneratedPath {
            path: path.to_owned(),
            reason: "generated output cannot traverse a symbolic link".to_owned(),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect generated path", path, source)),
    }
}

fn create_directories_without_symlinks(
    root: &Utf8Path,
    destination: &Utf8Path,
) -> Result<(), AppleError> {
    let relative = destination
        .strip_prefix(root)
        .map_err(|_| AppleError::UnsafeGeneratedPath {
            path: destination.to_owned(),
            reason: format!("path is outside generated root `{root}`"),
        })?;
    let mut current = root.to_owned();
    for component in relative.components() {
        let Utf8Component::Normal(component) = component else {
            return Err(AppleError::UnsafeGeneratedPath {
                path: destination.to_owned(),
                reason: "directory path contains traversal components".to_owned(),
            });
        };
        current.push(component);
        reject_symlink(&current)?;
        fs::create_dir_all(&current)
            .map_err(|source| io_error("create generated iOS directory", &current, source))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod png_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/opaque_png.rs"
        ));
    }

    use png_fixture::OPAQUE_1024_PNG as PNG;

    fn starter() -> IosProjectSpec {
        IosProjectSpec::new(
            FerryConfig::starter("Weather & Wind", "com.example.weather"),
            "weather-app",
        )
    }

    #[test]
    fn base_project_is_deterministic_and_escapes_plist_values() {
        let first = generate_ios_project(&starter()).unwrap();
        let second = generate_ios_project(&starter()).unwrap();
        assert_eq!(first, second);
        let plist = first.text(Utf8Path::new("Info.plist")).unwrap();
        assert!(plist.contains("Weather &amp; Wind"));
        let pbx = first
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();
        assert!(pbx.contains("Install Rust Executable"));
        assert!(pbx.contains("dstSubfolderSpec = 1"));
        assert!(!pbx.contains("PBXShellScriptBuildPhase"));
        assert!(pbx.contains("AD_HOC_CODE_SIGNING_ALLOWED = YES"));
        assert!(pbx.contains("CODE_SIGN_IDENTITY = \"-\""));
        assert!(pbx.contains("CODE_SIGNING_ALLOWED = YES"));
        assert!(pbx.contains("CODE_SIGNING_REQUIRED = YES"));
        assert!(!pbx.contains("CODE_SIGNING_ALLOWED = NO"));
        assert!(!pbx.contains("CODE_SIGNING_REQUIRED = NO"));
        assert!(pbx.contains("aarch64") || pbx.contains("ARCHS = arm64"));
        assert!(!pbx.contains("FerryWidgetExtension"));
        assert!(!plist.contains("UIApplicationDelegateClassName"));
        let bridge = first
            .text(Utf8Path::new("RuntimeBridge/FerryRuntimeBridge.swift"))
            .unwrap();
        assert!(bridge.contains("installApplicationDelegateHook()"));
        assert!(bridge.contains("@_cdecl(\"ferry_bridge_init\")"));
        assert!(bridge.contains("method_setImplementation"));
        assert!(!bridge.contains("UIApplication.shared"));
        assert!(!bridge.contains("import FerryActivityModel"));
        assert!(bridge.contains("public struct FerryActivityAttributes"));
        assert!(
            !first
                .files
                .contains_key(Utf8Path::new("ActivityModel/FerryActivityAttributes.swift"))
        );
    }

    #[test]
    fn project_assets_emit_a_real_catalog_and_build_settings() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let generated =
            generate_ios_project(&starter().with_assets(ProjectAssets::load(root).unwrap()))
                .unwrap();
        assert!(generated.files.contains_key(Utf8Path::new(
            "Assets.xcassets/AppIcon.appiconset/AppIcon-1024-1x.png"
        )));
        assert!(generated.files.contains_key(Utf8Path::new(
            "Assets.xcassets/AppIcon.appiconset/Contents.json"
        )));
        assert!(generated.files.contains_key(Utf8Path::new(
            "Assets.xcassets/FerryLaunch.imageset/Contents.json"
        )));
        let plist = generated.text(Utf8Path::new("Info.plist")).unwrap();
        assert!(plist.contains("<string>AppIcon</string>"));
        assert!(plist.contains("<string>FerryLaunch</string>"));
        assert!(!plist.contains("UILaunchImageFile"));
        let pbx = generated
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();
        assert!(pbx.contains("Assets.xcassets in Resources"));
        assert!(pbx.contains("folder.assetcatalog"));
        assert!(pbx.contains("ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon"));
        assert!(pbx.contains("COMPRESS_PNG_FILES = NO"));
    }

    #[test]
    fn sdk_only_assets_preserve_runtime_free_xcode_builds() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let generated = generate_ios_project(
            &starter()
                .with_assets(ProjectAssets::load(root).unwrap())
                .with_asset_packaging(IosAssetPackaging::SdkOnlyResources),
        )
        .unwrap();

        assert_eq!(generated.files[Utf8Path::new("FerryIcon.png")], PNG);
        assert_eq!(generated.files[Utf8Path::new("FerrySplash.png")], PNG);
        assert!(
            !generated
                .files
                .keys()
                .any(|path| path.starts_with("Assets.xcassets"))
        );
        let plist = generated.text(Utf8Path::new("Info.plist")).unwrap();
        assert!(plist.contains("<key>CFBundleIconFile</key>"));
        assert!(plist.contains("<string>FerryIcon</string>"));
        assert!(plist.contains("<key>UILaunchImageFile</key>"));
        assert!(plist.contains("<string>FerrySplash</string>"));
        assert!(!plist.contains("CFBundleIconName"));
        let pbx = generated
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();
        assert!(pbx.contains("FerryIcon.png in Resources"));
        assert!(pbx.contains("FerrySplash.png in Resources"));
        assert!(!pbx.contains("Assets.xcassets in Resources"));
        assert!(!pbx.contains("ASSETCATALOG_COMPILER_APPICON_NAME"));
    }

    #[test]
    fn cached_catalog_is_consumed_and_tampering_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let assets = ProjectAssets::load(root).unwrap();
        let generated_assets = rustferry_codegen::generate_platform_assets(root, None).unwrap();
        let spec = starter().with_assets(assets);
        let generated = generate_ios_project_from_asset_set(&spec, &generated_assets).unwrap();
        let catalog_path = Utf8Path::new("Assets.xcassets/AppIcon.appiconset/AppIcon-1024-1x.png");
        assert_eq!(
            generated.files.get(catalog_path),
            Some(&fs::read(generated_assets.root.join("ios").join(catalog_path)).unwrap())
        );

        fs::write(
            generated_assets
                .root
                .join("ios/Assets.xcassets/AppIcon.appiconset/AppIcon-1024-1x.png"),
            b"tampered",
        )
        .unwrap();
        assert!(generate_ios_project_from_asset_set(&spec, &generated_assets).is_err());
    }

    #[test]
    fn extensions_are_real_separate_xcode_targets() {
        let mut spec = starter();
        spec.config.extensions.widget.enabled = true;
        spec.config.extensions.widget.app_group = Some("group.com.example.weather".into());
        spec.config.extensions.live_activity.enabled = true;
        spec.config.ios.min_version = "16.1".into();
        let generated = generate_ios_project(&spec).unwrap();
        let pbx = generated
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();
        assert!(pbx.contains("com.apple.product-type.app-extension"));
        assert!(pbx.contains("FerryWidgetExtension.appex in Embed App Extensions"));
        assert!(pbx.contains("FerryLiveActivityExtension.appex in Embed App Extensions"));
        assert!(
            generated
                .files
                .contains_key(Utf8Path::new("WidgetExtension/Widget.swift"))
        );
        assert!(
            generated
                .files
                .contains_key(Utf8Path::new("LiveActivityExtension/LiveActivity.swift"))
        );
        let activity_model = generated
            .text(Utf8Path::new("ActivityModel/FerryActivityAttributes.swift"))
            .unwrap();
        assert!(activity_model.contains("public struct FerryActivityAttributes"));
        assert!(activity_model.contains("import ActivityKit"));
        assert!(!activity_model.contains("UIKit"));
        assert!(!activity_model.contains("UIApplication"));
        assert!(!activity_model.contains("FerryBridge"));
        let bridge = generated
            .text(Utf8Path::new("RuntimeBridge/FerryRuntimeBridge.swift"))
            .unwrap();
        assert!(bridge.contains("import FerryActivityModel"));
        assert!(!bridge.contains("public struct FerryActivityAttributes"));
        assert!(bridge.contains("UIApplicationDelegate"));
        let live_activity = generated
            .text(Utf8Path::new("LiveActivityExtension/LiveActivity.swift"))
            .unwrap();
        assert!(live_activity.contains("import FerryActivityModel"));
        assert!(!live_activity.contains("FerryRuntimeBridge"));
        assert!(pbx.contains("FerryActivityModel.framework in RuntimeBridge Frameworks"));
        assert!(pbx.contains("FerryActivityModel.framework in Live Activity Frameworks"));
        assert!(pbx.contains("LD_RUNPATH_SEARCH_PATHS = (\"$(inherited)\", \"@loader_path\",)"));
        assert!(pbx.contains("@executable_path/../../Frameworks"));
        assert!(!pbx.contains("FerryRuntimeBridge.framework in Frameworks"));
        assert_eq!(
            pbx.matches("APPLICATION_EXTENSION_API_ONLY = NO").count(),
            2
        );
        assert_eq!(
            pbx.matches("APPLICATION_EXTENSION_API_ONLY = YES").count(),
            6
        );
        let widget = generated
            .text(Utf8Path::new("WidgetExtension/Widget.swift"))
            .unwrap();
        assert!(widget.contains("snapshot[\"caption\"]"));
        assert!(widget.contains("ProgressView(value: progress)"));
        assert!(widget.contains("Link(action.label, destination: action.destination)"));
        assert!(widget.contains(".widgetURL(entry.deepLink)"));
    }

    #[test]
    fn device_live_activity_model_is_extension_safe_and_iphoneos_only() {
        let mut spec = starter();
        spec.config.extensions.live_activity.enabled = true;
        spec.config.ios.min_version = "16.1".into();
        let generated =
            generate_ios_project_for_platform(&spec, IosProjectPlatform::DeviceUnsigned).unwrap();
        let pbx = generated
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();

        assert!(!pbx.contains("iphonesimulator"));
        assert!(pbx.contains("SDKROOT = iphoneos"));
        assert!(pbx.contains("SUPPORTED_PLATFORMS = iphoneos"));
        assert!(pbx.contains("PRODUCT_NAME = FerryActivityModel"));
        assert_eq!(
            pbx.matches("APPLICATION_EXTENSION_API_ONLY = NO").count(),
            2
        );
        assert_eq!(
            pbx.matches("APPLICATION_EXTENSION_API_ONLY = YES").count(),
            4
        );
        assert!(!pbx.contains("FerryRuntimeBridge.framework in Frameworks"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires full Xcode"]
    fn xcode_builds_the_safe_activity_model_dependency_graph() {
        let mut spec = starter();
        spec.config.extensions.live_activity.enabled = true;
        spec.config.ios.min_version = "16.1".into();
        let generated = generate_ios_project(&spec).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        write_ios_project(&generated, root).unwrap();

        let output = std::process::Command::new("/usr/bin/xcrun")
            .args(["xcodebuild", "-project"])
            .arg(root.join("FerryHost.xcodeproj"))
            .args(["-list", "-json"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "xcodebuild failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let targets = listing["project"]["targets"].as_array().unwrap();
        for expected in [
            "FerryApp",
            "FerryRuntimeBridge",
            "FerryActivityModel",
            "FerryLiveActivityExtension",
        ] {
            assert!(targets.iter().any(|target| target == expected));
        }

        let products = root.join("Products");
        let intermediates = root.join("Intermediates");
        let build = std::process::Command::new("/usr/bin/xcrun")
            .args(["xcodebuild", "-project"])
            .arg(root.join("FerryHost.xcodeproj"))
            .args([
                "-target",
                "FerryRuntimeBridge",
                "-target",
                "FerryLiveActivityExtension",
                "-configuration",
                "Debug",
                "-sdk",
                "iphonesimulator",
                "AD_HOC_CODE_SIGNING_ALLOWED=YES",
                "CODE_SIGN_IDENTITY=-",
                "CODE_SIGNING_ALLOWED=YES",
                "CODE_SIGNING_REQUIRED=YES",
                "ARCHS=arm64",
                "ONLY_ACTIVE_ARCH=NO",
            ])
            .arg(format!("SYMROOT={products}"))
            .arg(format!("OBJROOT={intermediates}"))
            .arg(format!("CONFIGURATION_BUILD_DIR={products}"))
            .arg("build")
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "xcodebuild failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let executable =
            products.join("FerryLiveActivityExtension.appex/FerryLiveActivityExtension");
        assert!(executable.is_file());
        assert!(
            products
                .join("FerryActivityModel.framework/FerryActivityModel")
                .is_file()
        );
        let linked_libraries = |executable: &Utf8Path| {
            let output = std::process::Command::new("/usr/bin/xcrun")
                .args(["otool", "-L"])
                .arg(executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "otool failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        let dependencies = linked_libraries(&executable);
        assert!(dependencies.contains("@rpath/FerryActivityModel.framework/FerryActivityModel"));
        assert!(!dependencies.contains("FerryRuntimeBridge"));
        let runtime_dependencies =
            linked_libraries(&products.join("FerryRuntimeBridge.framework/FerryRuntimeBridge"));
        assert!(
            runtime_dependencies.contains("@rpath/FerryActivityModel.framework/FerryActivityModel")
        );
    }

    #[test]
    fn emits_only_enabled_permission_purpose_strings() {
        let mut spec = starter();
        spec.config.permissions.camera.enabled = true;
        spec.config.permissions.camera.purpose = Some("Scan <labels> & receipts".into());
        let generated = generate_ios_project(&spec).unwrap();
        let plist = generated.text(Utf8Path::new("Info.plist")).unwrap();
        assert!(plist.contains("NSCameraUsageDescription"));
        assert!(plist.contains("Scan &lt;labels&gt; &amp; receipts"));
        assert!(!plist.contains("NSMicrophoneUsageDescription"));
        assert!(!plist.contains("NSLocationWhenInUseUsageDescription"));
    }

    #[test]
    fn writes_only_relative_generated_files() {
        let mut generated = GeneratedAppleProject {
            files: BTreeMap::new(),
        };
        generated
            .files
            .insert(Utf8PathBuf::from("../escape"), Vec::new());
        let root = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap();
        assert!(matches!(
            write_ios_project(&generated, root),
            Err(AppleError::UnsafeGeneratedPath { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_generated_directories() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let temporary = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(temporary.join("outside")).unwrap();
        fs::create_dir(temporary.join("generated")).unwrap();
        symlink(
            temporary.join("outside"),
            temporary.join("generated/FerryHost.xcodeproj"),
        )
        .unwrap();
        assert!(matches!(
            write_ios_project(
                &generate_ios_project(&starter()).unwrap(),
                &temporary.join("generated")
            ),
            Err(AppleError::UnsafeGeneratedPath { .. })
        ));
    }
}
