use std::{collections::BTreeMap, fmt::Write as _, fs};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rustferry_core::{
    FerryConfig, Orientation, ProjectAssets, Theme, validate_application_identifier,
};
use serde::{Deserialize, Serialize};

use crate::{AppleError, error::io_error};

/// Inputs for deterministic hidden Xcode project generation.
#[derive(Clone, Debug, PartialEq)]
pub struct IosProjectSpec {
    /// Validated application configuration.
    pub config: FerryConfig,
    /// Cargo binary copied to the app's executable location.
    pub binary_name: String,
    /// Validated project icon and splash inputs, when generating a build host.
    pub assets: Option<ProjectAssets>,
}

impl IosProjectSpec {
    /// Construct a project specification.
    pub fn new(config: FerryConfig, binary_name: impl Into<String>) -> Self {
        Self {
            config,
            binary_name: binary_name.into(),
            assets: None,
        }
    }

    /// Attach validated project image assets to the generated host.
    #[must_use]
    pub fn with_assets(mut self, assets: ProjectAssets) -> Self {
        self.assets = Some(assets);
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
    validate_spec(spec)?;
    let mut files = BTreeMap::new();
    insert_text(
        &mut files,
        "FerryHost.xcodeproj/project.pbxproj",
        render_pbxproj(spec),
    );
    insert_text(
        &mut files,
        "FerryHost.xcodeproj/xcshareddata/xcschemes/FerryApp.xcscheme",
        render_scheme(&spec.binary_name),
    );
    insert_text(&mut files, "Info.plist", render_app_info_plist(spec));
    if let Some(assets) = &spec.assets {
        files.insert(Utf8PathBuf::from("FerryIcon.png"), assets.icon().to_vec());
        files.insert(
            Utf8PathBuf::from("FerrySplash.png"),
            assets.splash().to_vec(),
        );
    }
    insert_text(
        &mut files,
        "FerryResources.json",
        render_resource_metadata(spec)?,
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

    if spec.config.extensions.widget.enabled {
        let Some(app_group) = spec.config.extensions.widget.app_group.as_deref() else {
            return Err(AppleError::InvalidConfig(
                "extensions.widget.app_group is required when the widget is enabled".to_owned(),
            ));
        };
        insert_text(
            &mut files,
            "App.entitlements",
            render_entitlements(app_group),
        );
        insert_text(
            &mut files,
            "WidgetExtension/Widget.swift",
            render_widget_source(app_group),
        );
        insert_text(
            &mut files,
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
            &mut files,
            "WidgetExtension/Widget.entitlements",
            render_entitlements(app_group),
        );
    }

    if spec.config.extensions.live_activity.enabled {
        insert_text(
            &mut files,
            "LiveActivityExtension/LiveActivity.swift",
            render_live_activity_source(),
        );
        insert_text(
            &mut files,
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

    Ok(GeneratedAppleProject { files })
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
    let launch_screen = if spec.assets.is_some() {
        extra.push_str("  <key>CFBundleIconFile</key>\n  <string>FerryIcon</string>\n  <key>UILaunchImageFile</key>\n  <string>FerrySplash</string>\n");
        "  <dict>\n    <key>UIImageName</key>\n    <string>FerrySplash</string>\n  </dict>"
    } else {
        "  <dict/>"
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
    "import ActivityKit\nimport FerryRuntimeBridge\nimport SwiftUI\nimport WidgetKit\n\n@main\nstruct FerryLiveActivity: Widget {\n    var body: some WidgetConfiguration {\n        ActivityConfiguration(for: FerryActivityAttributes.self) { context in\n            VStack(alignment: .leading) {\n                Text(context.state.title).font(.headline)\n                Text(context.state.status)\n                ProgressView(value: context.state.progress)\n            }\n            .widgetURL(context.state.deepLink.flatMap(URL.init(string:)))\n        } dynamicIsland: { context in\n            DynamicIsland {\n                DynamicIslandExpandedRegion(.leading) { Text(context.state.leadingText) }\n                DynamicIslandExpandedRegion(.trailing) { Text(context.state.trailingText) }\n                DynamicIslandExpandedRegion(.bottom) { ProgressView(value: context.state.progress) }\n            } compactLeading: {\n                Text(context.state.leadingText)\n            } compactTrailing: {\n                Text(context.state.trailingText)\n            } minimal: {\n                Text(context.state.status.prefix(1))\n            }\n            .widgetURL(context.state.deepLink.flatMap(URL.init(string:)))\n        }\n    }\n}\n"
        .to_owned()
}

fn render_runtime_bridge_source(spec: &IosProjectSpec) -> String {
    let enabled = |value: bool| if value { "true" } else { "false" };
    let widget_group = spec
        .config
        .extensions
        .widget
        .app_group
        .as_deref()
        .map_or_else(|| "nil".to_owned(), swift_string_literal);
    include_str!("../templates/FerryRuntimeBridge.swift.tpl")
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

fn render_resource_metadata(spec: &IosProjectSpec) -> Result<String, AppleError> {
    let value = serde_json::json!({
        "schema_version": 1,
        "generator": "cargo-ferry",
        "ui_backend": "slint-1.17.1",
        "rust_target": "aarch64-apple-ios-sim",
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

#[allow(clippy::too_many_lines, clippy::write_with_newline)]
fn render_pbxproj(spec: &IosProjectSpec) -> String {
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
    if assets {
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
            "\t\t{} /* FerryRuntimeBridge.framework in Frameworks */ = {{isa = PBXBuildFile; fileRef = {} /* FerryRuntimeBridge.framework */; }};",
            id(85),
            id(82)
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
        let _ = writeln!(
            output,
            "\t\t{} /* PBXContainerItemProxy */ = {{isa = PBXContainerItemProxy; containerPortal = {} /* Project object */; proxyType = 1; remoteGlobalIDString = {}; remoteInfo = FerryRuntimeBridge; }};",
            id(88),
            id(1),
            id(90)
        );
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
        "\t\t{} /* Embed Frameworks */ = {{\n\t\t\tisa = PBXCopyFilesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tdstPath = \"\";\n\t\t\tdstSubfolderSpec = 10;\n\t\t\tfiles = ({} /* FerryRuntimeBridge.framework in Embed Frameworks */,);\n\t\t\tname = \"Embed Frameworks\";\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}};\n",
        id(93),
        id(84)
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
    if assets {
        let _ = writeln!(
            output,
            "\t\t{} /* FerryIcon.png */ = {{isa = PBXFileReference; lastKnownFileType = file; path = FerryIcon.png; sourceTree = \"<group>\"; }};",
            id(5)
        );
        let _ = writeln!(
            output,
            "\t\t{} /* FerrySplash.png */ = {{isa = PBXFileReference; lastKnownFileType = file; path = FerrySplash.png; sourceTree = \"<group>\"; }};",
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
    if assets {
        let _ = writeln!(output, "\t\t\t\t{} /* FerryIcon.png */,", id(5));
        let _ = writeln!(output, "\t\t\t\t{} /* FerrySplash.png */,", id(19));
    }
    let _ = writeln!(output, "\t\t\t\t{} /* RuntimeBridge */,", id(91));
    if widget {
        let _ = writeln!(output, "\t\t\t\t{} /* App.entitlements */,", id(8));
        let _ = writeln!(output, "\t\t\t\t{} /* WidgetExtension */,", id(38));
    }
    if live_activity {
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
        "\t\t{} /* FerryRuntimeBridge */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryRuntimeBridge\" */;\n\t\t\tbuildPhases = ({} /* Sources */,);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ();\n\t\t\tname = FerryRuntimeBridge;\n\t\t\tproductName = FerryRuntimeBridge;\n\t\t\tproductReference = {} /* FerryRuntimeBridge.framework */;\n\t\t\tproductType = \"com.apple.product-type.framework\";\n\t\t}};\n",
        id(90),
        id(95),
        id(92),
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
            "\t\t{} /* FerryLiveActivityExtension */ = {{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {} /* Build configuration list for PBXNativeTarget \"FerryLiveActivityExtension\" */;\n\t\t\tbuildPhases = ({} /* Sources */, {} /* Frameworks */,);\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({} /* PBXTargetDependency */,);\n\t\t\tname = FerryLiveActivityExtension;\n\t\t\tproductName = FerryLiveActivityExtension;\n\t\t\tproductReference = {} /* FerryLiveActivityExtension.appex */;\n\t\t\tproductType = \"com.apple.product-type.app-extension\";\n\t\t}};\n",
            id(56),
            id(59),
            id(55),
            id(94),
            id(89),
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
        let _ = writeln!(
            output,
            "\t\t\t\t{} /* FerryLiveActivityExtension */,",
            id(56)
        );
    }
    output.push_str("\t\t\t);\n\t\t};\n/* End PBXProject section */\n\n");

    output.push_str("/* Begin PBXResourcesBuildPhase section */\n");
    if assets {
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
            "\t\t{} /* Frameworks */ = {{isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({} /* FerryRuntimeBridge.framework in Frameworks */,); runOnlyForDeploymentPostprocessing = 0; }};\n",
            id(94),
            id(85)
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
            "\t\t{} /* PBXTargetDependency */ = {{isa = PBXTargetDependency; target = {} /* FerryRuntimeBridge */; targetProxy = {} /* PBXContainerItemProxy */; }};",
            id(89),
            id(90),
            id(88)
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
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; ARCHS = arm64; ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS = NO; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; {}COMPRESS_PNG_FILES = NO; CURRENT_PROJECT_VERSION = {}; GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = Info.plist; IPHONEOS_DEPLOYMENT_TARGET = {}; LD_RUNPATH_SEARCH_PATHS = (\"$(inherited)\", \"@executable_path/Frameworks\",); MARKETING_VERSION = {}; ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = {}; PRODUCT_NAME = {}; SDKROOT = iphonesimulator; SKIP_INSTALL = NO; STRIP_PNG_TEXT = NO; SUPPORTED_PLATFORMS = iphonesimulator; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
            id(config_id),
            name,
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
        let _ = write!(
            output,
            "\t\t{} /* {} */ = {{isa = XCBuildConfiguration; buildSettings = {{AD_HOC_CODE_SIGNING_ALLOWED = YES; APPLICATION_EXTENSION_API_ONLY = NO; ARCHS = arm64; CODE_SIGN_IDENTITY = \"-\"; CODE_SIGNING_ALLOWED = YES; CODE_SIGNING_REQUIRED = YES; CURRENT_PROJECT_VERSION = 1; DEFINES_MODULE = YES; DYLIB_INSTALL_NAME_BASE = \"@rpath\"; GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = RuntimeBridge/Info.plist; IPHONEOS_DEPLOYMENT_TARGET = {}; MARKETING_VERSION = 1.0; ONLY_ACTIVE_ARCH = NO; PRODUCT_BUNDLE_IDENTIFIER = org.rustferry.runtime-bridge; PRODUCT_NAME = FerryRuntimeBridge; SDKROOT = iphonesimulator; SKIP_INSTALL = YES; SUPPORTED_PLATFORMS = iphonesimulator; SWIFT_EMIT_LOC_STRINGS = NO; SWIFT_INSTALL_OBJC_HEADER = YES; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = \"1,2\"; }}; name = {}; }};\n",
            id(config_id),
            name,
            min_version,
            name
        );
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
    }

    #[test]
    fn project_assets_are_compiled_and_referenced_by_plist() {
        const PNG: &[u8] = include_bytes!("../../../examples/counter/assets/icon.png");
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let generated =
            generate_ios_project(&starter().with_assets(ProjectAssets::load(root).unwrap()))
                .unwrap();
        assert_eq!(
            generated
                .files
                .get(Utf8Path::new("FerryIcon.png"))
                .map(Vec::as_slice),
            Some(PNG)
        );
        assert!(
            generated
                .files
                .contains_key(Utf8Path::new("FerrySplash.png"))
        );
        let plist = generated.text(Utf8Path::new("Info.plist")).unwrap();
        assert!(plist.contains("<string>FerryIcon</string>"));
        assert!(plist.contains("<string>FerrySplash</string>"));
        let pbx = generated
            .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
            .unwrap();
        assert!(pbx.contains("FerryIcon.png in Resources"));
        assert!(pbx.contains("FerrySplash.png in Resources"));
        assert!(pbx.contains("COMPRESS_PNG_FILES = NO"));
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
        let widget = generated
            .text(Utf8Path::new("WidgetExtension/Widget.swift"))
            .unwrap();
        assert!(widget.contains("snapshot[\"caption\"]"));
        assert!(widget.contains("ProgressView(value: progress)"));
        assert!(widget.contains("Link(action.label, destination: action.destination)"));
        assert!(widget.contains(".widgetURL(entry.deepLink)"));
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
