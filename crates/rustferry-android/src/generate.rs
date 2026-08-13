use std::{fmt::Write as _, fs};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_codegen::{
    GeneratedAssetPlatform, GeneratedAssetSet, read_generated_platform_assets,
    render_platform_assets_for,
};
use rustferry_core::{
    AndroidLiveActivityFallback, FerryConfig, NetworkMode, Orientation, ProjectAssets, Theme,
};
use sha2::{Digest, Sha256};

use crate::{
    ACTIVITY_CLASS, AndroidError, FILE_PROVIDER_CLASS, NOTIFICATION_RECEIVER_CLASS,
    WIDGET_PROVIDER_CLASS, bridge::generate_bridge_sources, error::io_error,
};

/// Deterministic Android manifest and resource source files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedAndroidContent {
    /// Text Android manifest.
    pub manifest: String,
    /// Resource files relative to the generated root.
    pub resources: Vec<(Utf8PathBuf, String)>,
    /// Binary resource files relative to the generated root.
    pub binary_resources: Vec<(Utf8PathBuf, Vec<u8>)>,
    /// Internal Java bridge sources relative to the generated root.
    pub java_sources: Vec<(Utf8PathBuf, String)>,
    /// Content fingerprint used to isolate stale generated files.
    pub fingerprint: String,
}

/// Paths written for AAPT2 consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedAndroidFiles {
    /// Fingerprinted generated root.
    pub root: Utf8PathBuf,
    /// `AndroidManifest.xml` path.
    pub manifest: Utf8PathBuf,
    /// Android `res` directory.
    pub resources: Utf8PathBuf,
    /// Internal Java source files passed directly to `javac`.
    pub java_sources: Vec<Utf8PathBuf>,
}

/// Create manifest and resource source text without filesystem access.
///
/// # Errors
///
/// Returns an error for invalid configuration, unsafe metadata, or XML-incompatible control
/// characters.
pub fn generate_android_content(
    config: &FerryConfig,
    native_library_name: &str,
    target_sdk: u32,
    has_dex: bool,
    debuggable: bool,
) -> Result<GeneratedAndroidContent, AndroidError> {
    generate_android_content_inner(
        config,
        native_library_name,
        target_sdk,
        has_dex,
        debuggable,
        None,
    )
}

pub(crate) fn generate_android_content_with_assets(
    config: &FerryConfig,
    native_library_name: &str,
    target_sdk: u32,
    has_dex: bool,
    debuggable: bool,
    assets: &ProjectAssets,
) -> Result<GeneratedAndroidContent, AndroidError> {
    generate_android_content_inner(
        config,
        native_library_name,
        target_sdk,
        has_dex,
        debuggable,
        Some(assets),
    )
}

fn generate_android_content_inner(
    config: &FerryConfig,
    native_library_name: &str,
    target_sdk: u32,
    has_dex: bool,
    debuggable: bool,
    assets: Option<&ProjectAssets>,
) -> Result<GeneratedAndroidContent, AndroidError> {
    if !has_dex {
        return Err(AndroidError::InvalidRequest(
            "the mandatory Android runtime bridge requires DEX".to_owned(),
        ));
    }
    validate_native_library_name(native_library_name)?;
    config
        .validate_or_error()
        .map_err(|error| AndroidError::InvalidConfig(error.to_string()))?;
    let app_name = escape_xml(&config.app.name)?;
    let application_id = escape_xml(&config.app.identifier)?;
    let native_library_name = escape_xml(native_library_name)?;
    let permissions = android_manifest_permissions(config, target_sdk);
    let mut permission_xml = String::new();
    for (permission, max_sdk) in permissions {
        if let Some(max_sdk) = max_sdk {
            let _ = writeln!(
                permission_xml,
                "    <uses-permission android:name=\"{permission}\" android:maxSdkVersion=\"{max_sdk}\" />"
            );
        } else {
            let _ = writeln!(
                permission_xml,
                "    <uses-permission android:name=\"{permission}\" />"
            );
        }
    }

    let orientation = match config.app.window.orientation {
        Orientation::Automatic => String::new(),
        Orientation::Portrait => "\n            android:screenOrientation=\"portrait\"".to_owned(),
        Orientation::Landscape => {
            "\n            android:screenOrientation=\"landscape\"".to_owned()
        }
    };
    let deep_links = if config.capabilities.deep_links.schemes.is_empty() {
        String::new()
    } else {
        let hosts = if config.capabilities.deep_links.allowed_hosts.is_empty() {
            vec![None]
        } else {
            config
                .capabilities
                .deep_links
                .allowed_hosts
                .iter()
                .map(|host| Some(host.as_str()))
                .collect()
        };
        let actions = if config.capabilities.deep_links.allowed_actions.is_empty() {
            vec![None]
        } else {
            config
                .capabilities
                .deep_links
                .allowed_actions
                .iter()
                .map(|action| Some(action.as_str()))
                .collect()
        };
        let mut data = String::new();
        for scheme in &config.capabilities.deep_links.schemes {
            let scheme = escape_xml(scheme)?;
            for host in &hosts {
                for action in &actions {
                    let _ = write!(data, "                <data android:scheme=\"{scheme}\"");
                    if let Some(host) = host {
                        let _ = write!(data, " android:host=\"{}\"", escape_xml(host)?);
                    }
                    if let Some(action) = action {
                        let _ = write!(data, " android:pathPrefix=\"/{}\"", escape_xml(action)?);
                    }
                    data.push_str(" />\n");
                }
            }
        }
        format!(
            "            <intent-filter>\n                <action android:name=\"android.intent.action.VIEW\" />\n                <category android:name=\"android.intent.category.DEFAULT\" />\n                <category android:name=\"android.intent.category.BROWSABLE\" />\n{data}            </intent-filter>\n"
        )
    };
    let widget_component = if config.extensions.widget.enabled {
        format!(
            "        <receiver\n            android:name=\"{WIDGET_PROVIDER_CLASS}\"\n            android:enabled=\"true\"\n            android:exported=\"false\">\n            <intent-filter>\n                <action android:name=\"android.appwidget.action.APPWIDGET_UPDATE\" />\n            </intent-filter>\n            <meta-data\n                android:name=\"android.appwidget.provider\"\n                android:resource=\"@xml/ferry_widget_info\" />\n        </receiver>\n"
        )
    } else {
        String::new()
    };
    let live_activity_fallback = config.extensions.live_activity.enabled
        && config.extensions.live_activity.android_fallback
            == AndroidLiveActivityFallback::OngoingNotification;
    let notification_component = if config.capabilities.notifications.local
        || live_activity_fallback
    {
        format!(
            "        <receiver\n            android:name=\"{NOTIFICATION_RECEIVER_CLASS}\"\n            android:enabled=\"true\"\n            android:exported=\"false\" />\n"
        )
    } else {
        String::new()
    };
    let file_provider_component = if config.capabilities.share.enabled {
        format!(
            "        <provider\n            android:name=\"{FILE_PROVIDER_CLASS}\"\n            android:authorities=\"{application_id}.ferry-files\"\n            android:exported=\"false\"\n            android:grantUriPermissions=\"true\" />\n"
        )
    } else {
        String::new()
    };
    let icon_resource = if assets.is_some() {
        "@mipmap/ferry_icon"
    } else {
        "@drawable/ferry_icon"
    };
    let manifest = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"{application_id}\">\n{permission_xml}    <uses-sdk android:minSdkVersion=\"{}\" android:targetSdkVersion=\"{target_sdk}\" />\n    <application\n        android:allowBackup=\"false\"\n        android:debuggable=\"{}\"\n        android:extractNativeLibs=\"false\"\n        android:hasCode=\"true\"\n        android:icon=\"{icon_resource}\"\n        android:label=\"@string/app_name\"\n        android:supportsRtl=\"true\"\n        android:theme=\"@style/FerryTheme\">\n        <activity\n            android:name=\"{ACTIVITY_CLASS}\"\n            android:configChanges=\"orientation|screenSize|keyboardHidden|uiMode|density\"\n            android:exported=\"true\"\n            android:launchMode=\"singleTop\"{orientation}>\n            <meta-data android:name=\"android.app.lib_name\" android:value=\"{native_library_name}\" />\n            <intent-filter>\n                <action android:name=\"android.intent.action.MAIN\" />\n                <category android:name=\"android.intent.category.LAUNCHER\" />\n            </intent-filter>\n{deep_links}        </activity>\n{notification_component}{widget_component}{file_provider_component}    </application>\n</manifest>\n",
        config.android.min_sdk,
        if debuggable { "true" } else { "false" },
    );

    let mut resources = vec![
        (
            Utf8PathBuf::from("res/values/strings.xml"),
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n    <string name=\"app_name\">{app_name}</string>\n</resources>\n"
            ),
        ),
        (
            Utf8PathBuf::from("res/values/styles.xml"),
            styles(config.app.window.theme, false),
        ),
        (
            Utf8PathBuf::from("res/drawable/ferry_icon.xml"),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<vector xmlns:android=\"http://schemas.android.com/apk/res/android\" android:width=\"48dp\" android:height=\"48dp\" android:viewportWidth=\"48\" android:viewportHeight=\"48\">\n    <path android:fillColor=\"#315CF5\" android:pathData=\"M8,4h32a4,4 0,0 1,4 4v32a4,4 0,0 1,-4 4h-32a4,4 0,0 1,-4 -4v-32a4,4 0,0 1,4 -4z\" />\n    <path android:fillColor=\"#FFFFFFFF\" android:pathData=\"M15,14h13a8,8 0,0 1,0 16h-7v6h-6zM21,20v4h7a2,2 0,0 0,0 -4z\" />\n</vector>\n".to_owned(),
        ),
        (
            Utf8PathBuf::from("res/drawable/ferry_splash.xml"),
            splash(config.app.window.theme),
        ),
    ];
    if config.app.window.theme == Theme::System {
        resources.extend([
            (
                Utf8PathBuf::from("res/drawable-night/ferry_splash.xml"),
                splash(Theme::Dark),
            ),
            (
                Utf8PathBuf::from("res/values-night/styles.xml"),
                styles(Theme::Dark, true),
            ),
        ]);
    }
    if config.extensions.widget.enabled {
        resources.extend([
            (
                Utf8PathBuf::from("res/layout/ferry_widget.xml"),
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" android:orientation=\"vertical\" android:gravity=\"center\" android:padding=\"16dp\">\n  <TextView android:id=\"@+id/ferry_widget_text\" android:layout_width=\"match_parent\" android:layout_height=\"0dp\" android:layout_weight=\"1\" android:gravity=\"center\" android:text=\"@string/app_name\" android:textSize=\"18sp\" />\n  <ProgressBar android:id=\"@+id/ferry_widget_progress\" style=\"?android:attr/progressBarStyleHorizontal\" android:layout_width=\"match_parent\" android:layout_height=\"wrap_content\" android:max=\"100\" android:visibility=\"gone\" />\n</LinearLayout>\n".to_owned(),
            ),
            (
                Utf8PathBuf::from("res/xml/ferry_widget_info.xml"),
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<appwidget-provider xmlns:android=\"http://schemas.android.com/apk/res/android\" android:initialLayout=\"@layout/ferry_widget\" android:minWidth=\"110dp\" android:minHeight=\"40dp\" android:resizeMode=\"horizontal|vertical\" android:updatePeriodMillis=\"0\" android:widgetCategory=\"home_screen\" />\n".to_owned(),
            ),
        ]);
    }
    let mut binary_resources = Vec::new();
    if let Some(assets) = assets {
        resources.retain(|(path, _)| {
            !matches!(
                path.as_str(),
                "res/drawable/ferry_icon.xml"
                    | "res/drawable/ferry_splash.xml"
                    | "res/drawable-night/ferry_splash.xml"
            )
        });
        binary_resources = android_resource_paths(
            render_platform_assets_for(assets, GeneratedAssetPlatform::Android)?
                .files
                .into_iter()
                .filter_map(|(path, bytes)| {
                    path.strip_prefix("android")
                        .ok()
                        .map(|relative| (relative.to_owned(), bytes))
                })
                .collect(),
        )?;
    }
    resources.sort_by(|left, right| left.0.cmp(&right.0));
    binary_resources.sort_by(|left, right| left.0.cmp(&right.0));
    let java_sources = generate_bridge_sources(config, &native_library_name);

    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_vec(config)
            .map_err(|error| AndroidError::InvalidConfig(error.to_string()))?,
    );
    hasher.update(manifest.as_bytes());
    for (path, contents) in &resources {
        hasher.update(path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(contents.as_bytes());
        hasher.update([0]);
    }
    for (path, contents) in &binary_resources {
        hasher.update(path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(contents);
        hasher.update([0]);
    }
    for (path, contents) in &java_sources {
        hasher.update(path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(contents.as_bytes());
        hasher.update([0]);
    }
    let fingerprint = hex::encode(&hasher.finalize()[..12]);
    Ok(GeneratedAndroidContent {
        manifest,
        resources,
        binary_resources,
        java_sources,
        fingerprint,
    })
}

pub(crate) fn content_from_generated_asset_set(
    planned: &GeneratedAndroidContent,
    generated: &GeneratedAssetSet,
) -> Result<GeneratedAndroidContent, AndroidError> {
    let cached = android_resource_paths(read_generated_platform_assets(
        generated,
        GeneratedAssetPlatform::Android,
    )?)?;
    if cached != planned.binary_resources {
        return Err(AndroidError::InvalidRequest(format!(
            "generated Android asset cache {} differs from the planned source snapshot",
            generated.root
        )));
    }
    let mut content = planned.clone();
    content.binary_resources = cached;
    Ok(content)
}

fn android_resource_paths(
    files: Vec<(Utf8PathBuf, Vec<u8>)>,
) -> Result<Vec<(Utf8PathBuf, Vec<u8>)>, AndroidError> {
    let mut resources = Vec::with_capacity(files.len());
    for (relative, bytes) in files {
        if relative.is_absolute()
            || relative.as_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, camino::Utf8Component::Normal(_)))
        {
            return Err(AndroidError::InvalidRequest(format!(
                "generated Android asset path is unsafe: {relative}"
            )));
        }
        resources.push((Utf8PathBuf::from("res").join(relative), bytes));
    }
    resources.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(resources)
}

pub(crate) fn android_manifest_permissions(
    config: &FerryConfig,
    target_sdk: u32,
) -> Vec<(&'static str, Option<u32>)> {
    let mut permissions = Vec::new();
    match config.capabilities.network.mode {
        NetworkMode::None => {}
        NetworkMode::Status => {
            permissions.push(("android.permission.ACCESS_NETWORK_STATE", None));
        }
        NetworkMode::Optional | NetworkMode::Required => {
            permissions.push(("android.permission.ACCESS_NETWORK_STATE", None));
            permissions.push(("android.permission.INTERNET", None));
        }
    }
    if config.capabilities.network.probe_url.is_some()
        && !permissions
            .iter()
            .any(|(name, _)| *name == "android.permission.INTERNET")
    {
        permissions.push(("android.permission.INTERNET", None));
    }
    let live_activity_fallback = config.extensions.live_activity.enabled
        && config.extensions.live_activity.android_fallback
            == AndroidLiveActivityFallback::OngoingNotification;
    if config.capabilities.notifications.local || live_activity_fallback {
        permissions.push(("android.permission.POST_NOTIFICATIONS", None));
    }
    if config.capabilities.haptics.enabled {
        permissions.push(("android.permission.VIBRATE", None));
    }
    if config.permissions.camera.enabled {
        permissions.push(("android.permission.CAMERA", None));
    }
    if config.permissions.microphone.enabled {
        permissions.push(("android.permission.RECORD_AUDIO", None));
    }
    if config.permissions.location_when_in_use.enabled {
        permissions.push(("android.permission.ACCESS_COARSE_LOCATION", None));
        permissions.push(("android.permission.ACCESS_FINE_LOCATION", None));
    }
    if config.permissions.photos.enabled {
        if config.android.min_sdk < 33 {
            permissions.push(("android.permission.READ_EXTERNAL_STORAGE", Some(32)));
        }
        if target_sdk >= 33 {
            permissions.push(("android.permission.READ_MEDIA_IMAGES", None));
        }
    }
    permissions.sort_unstable();
    permissions.dedup();
    permissions
}

/// Write generated content below a fingerprinted output directory.
///
/// # Errors
///
/// Returns an error when generated directories or files cannot be written.
pub fn write_android_content(
    output_root: &Utf8Path,
    content: &GeneratedAndroidContent,
) -> Result<GeneratedAndroidFiles, AndroidError> {
    let root = output_root.join(&content.fingerprint);
    let manifest = root.join("AndroidManifest.xml");
    write_if_changed(&manifest, &content.manifest)?;
    for (relative, contents) in &content.resources {
        write_if_changed(&root.join(relative), contents)?;
    }
    for (relative, contents) in &content.binary_resources {
        write_bytes_if_changed(&root.join(relative), contents)?;
    }
    let mut java_sources = Vec::with_capacity(content.java_sources.len());
    for (relative, contents) in &content.java_sources {
        let path = root.join(relative);
        write_if_changed(&path, contents)?;
        java_sources.push(path);
    }
    Ok(GeneratedAndroidFiles {
        root: root.clone(),
        manifest,
        resources: root.join("res"),
        java_sources,
    })
}

fn write_if_changed(path: &Utf8Path, contents: &str) -> Result<(), AndroidError> {
    if matches!(fs::read_to_string(path), Ok(existing) if existing == contents) {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        AndroidError::InvalidRequest(format!("generated path has no parent: {path}"))
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create generated resource directory", parent, source))?;
    fs::write(path, contents)
        .map_err(|source| io_error("write generated Android file", path, source))
}

fn write_bytes_if_changed(path: &Utf8Path, contents: &[u8]) -> Result<(), AndroidError> {
    if matches!(fs::read(path), Ok(existing) if existing == contents) {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        AndroidError::InvalidRequest(format!("generated path has no parent: {path}"))
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create generated resource directory", parent, source))?;
    fs::write(path, contents)
        .map_err(|source| io_error("write generated Android file", path, source))
}

fn styles(theme: Theme, night_override: bool) -> String {
    let parent = match theme {
        Theme::Dark => "@android:style/Theme.Material.NoActionBar",
        Theme::System | Theme::Light => "@android:style/Theme.Material.Light.NoActionBar",
    };
    let marker = if night_override {
        " <!-- system night override -->"
    } else {
        ""
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>{marker}\n    <style name=\"FerryTheme\" parent=\"{parent}\">\n        <item name=\"android:windowBackground\">@drawable/ferry_splash</item>\n        <item name=\"android:fontFamily\">sans</item>\n        <item name=\"android:windowNoTitle\">true</item>\n    </style>\n</resources>\n"
    )
}

fn splash(theme: Theme) -> String {
    let color = if theme == Theme::Dark {
        "#FF101216"
    } else {
        "#FFF7F7FA"
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<layer-list xmlns:android=\"http://schemas.android.com/apk/res/android\">\n    <item>\n        <shape android:shape=\"rectangle\">\n            <solid android:color=\"{color}\" />\n        </shape>\n    </item>\n    <item android:drawable=\"@drawable/ferry_icon\" android:gravity=\"center\" android:width=\"96dp\" android:height=\"96dp\" />\n</layer-list>\n"
    )
}

fn validate_native_library_name(name: &str) -> Result<(), AndroidError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(AndroidError::InvalidRequest(format!(
            "native library name `{name}` must contain only ASCII letters, digits, or underscores"
        )));
    }
    Ok(())
}

fn escape_xml(value: &str) -> Result<String, AndroidError> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(character),
            character if character.is_control() => {
                return Err(AndroidError::InvalidRequest(
                    "application metadata contains a control character that XML cannot encode"
                        .to_owned(),
                ));
            }
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use rustferry_core::{FerryConfig, NetworkMode};

    use super::*;

    mod png_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/opaque_png.rs"
        ));
    }

    use png_fixture::OPAQUE_1024_PNG as PNG;

    #[test]
    fn default_manifest_matches_golden() {
        let config = FerryConfig::starter("RustFerry Counter", "com.example.counter");
        let content = generate_android_content(&config, "counter", 35, true, true).unwrap();
        assert_eq!(
            content.manifest,
            include_str!("../tests/golden/starter-AndroidManifest.xml")
        );
        let styles = content
            .resources
            .iter()
            .find(|(path, _)| path == "res/values/styles.xml")
            .map(|(_, source)| source)
            .unwrap();
        assert_eq!(styles, include_str!("../tests/golden/starter-styles.xml"));
        assert!(content.resources.iter().any(|(path, source)| path
            == "res/drawable-night/ferry_splash.xml"
            && source.contains("#FF101216")));
    }

    #[test]
    fn project_assets_use_density_icons_and_cached_packaging_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let assets = ProjectAssets::load(root).unwrap();
        let planned = generate_android_content_with_assets(
            &FerryConfig::starter("Assets", "com.example.assets"),
            "assets",
            35,
            true,
            true,
            &assets,
        )
        .unwrap();

        assert!(
            planned
                .manifest
                .contains("android:icon=\"@mipmap/ferry_icon\"")
        );
        assert_eq!(planned.binary_resources.len(), 6);
        for (density, size) in [
            ("mdpi", 48),
            ("hdpi", 72),
            ("xhdpi", 96),
            ("xxhdpi", 144),
            ("xxxhdpi", 192),
        ] {
            let path = Utf8PathBuf::from(format!("res/mipmap-{density}/ferry_icon.png"));
            let bytes = planned
                .binary_resources
                .iter()
                .find_map(|(candidate, bytes)| (candidate == &path).then_some(bytes))
                .unwrap();
            assert_eq!(png_dimensions(bytes), (size, size));
        }
        assert!(planned.binary_resources.iter().any(|(path, bytes)| path
            == "res/drawable-nodpi/ferry_splash.png"
            && png_dimensions(bytes) == (1_024, 1_024)));

        let generated = rustferry_codegen::generate_platform_assets(root, None).unwrap();
        let packaged = content_from_generated_asset_set(&planned, &generated).unwrap();
        assert_eq!(packaged.binary_resources, planned.binary_resources);

        fs::write(
            generated.root.join("android/mipmap-mdpi/ferry_icon.png"),
            b"tampered",
        )
        .unwrap();
        assert!(content_from_generated_asset_set(&planned, &generated).is_err());
    }

    fn png_dimensions(bytes: &[u8]) -> (u32, u32) {
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        (
            u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
        )
    }

    #[test]
    fn permissions_are_capability_minimal() {
        let mut config = FerryConfig::starter("Offline", "com.example.offline");
        config.capabilities.network.mode = NetworkMode::None;
        config.capabilities.notifications.local = false;
        let content = generate_android_content(&config, "offline", 35, true, true).unwrap();
        assert!(!content.manifest.contains("permission.INTERNET"));
        assert!(!content.manifest.contains("permission.ACCESS_NETWORK_STATE"));
        assert!(!content.manifest.contains("permission.POST_NOTIFICATIONS"));
        assert!(!content.manifest.contains("<receiver"));
    }

    #[test]
    fn enabled_components_and_links_are_escaped_and_scoped() {
        let mut config = FerryConfig::starter("Weather & More", "com.example.weather");
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
        config.capabilities.deep_links.schemes = vec!["weather".to_owned()];
        config.capabilities.deep_links.allowed_hosts = vec!["app.example.com".to_owned()];
        config.capabilities.deep_links.allowed_actions = vec!["forecast".to_owned()];
        let content = generate_android_content(&config, "weather", 35, true, false).unwrap();
        assert!(
            content
                .resources
                .iter()
                .any(|(_, source)| source.contains("Weather &amp; More"))
        );
        assert!(content.manifest.contains(WIDGET_PROVIDER_CLASS));
        assert!(
            content
                .manifest
                .contains("android:launchMode=\"singleTop\"")
        );
        assert!(content.manifest.contains("android:scheme=\"weather\""));
        assert!(
            content
                .manifest
                .contains("android:host=\"app.example.com\"")
        );
        assert!(
            content
                .manifest
                .contains("android:pathPrefix=\"/forecast\"")
        );
        assert!(
            content
                .resources
                .iter()
                .any(|(path, _)| path == "res/xml/ferry_widget_info.xml")
        );
    }

    #[test]
    fn rejects_library_path_injection() {
        let config = FerryConfig::starter("App", "com.example.app");
        assert!(generate_android_content(&config, "../evil", 35, true, true).is_err());
    }

    #[test]
    fn platform_permissions_follow_android_api_policy() {
        let mut config = FerryConfig::starter("Media", "com.example.media");
        config.permissions.camera.enabled = true;
        config.permissions.camera.purpose = Some("Scan a document".to_owned());
        config.permissions.photos.enabled = true;
        config.permissions.photos.purpose = Some("Choose an image".to_owned());
        config.permissions.microphone.enabled = true;
        config.permissions.microphone.purpose = Some("Record a note".to_owned());
        config.permissions.location_when_in_use.enabled = true;
        config.permissions.location_when_in_use.purpose = Some("Show local weather".to_owned());
        config.permissions.local_network.enabled = true;
        config.permissions.local_network.purpose = Some("Find a local service".to_owned());
        let manifest = generate_android_content(&config, "media", 35, true, true)
            .unwrap()
            .manifest;
        for permission in [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_MEDIA_IMAGES",
        ] {
            assert!(manifest.contains(permission));
        }
        assert!(
            manifest
                .contains("android.permission.READ_EXTERNAL_STORAGE\" android:maxSdkVersion=\"32")
        );
        assert!(!manifest.contains("LOCAL_NETWORK"));
        assert!(!manifest.contains("Find a local service"));
    }
}
