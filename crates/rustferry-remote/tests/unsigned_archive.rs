//! Unsigned physical-iPhone archive structure and security regression tests.

use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use plist::{Dictionary, Value};
use rustferry_remote::{
    ArtifactError, UnsignedNestedBundleExpectation, UnsignedNestedBundleKind,
    UnsignedXcarchiveExpectation, inspect_unsigned_xcarchive,
};
use sha2::{Digest, Sha256};

const APP_NAME: &str = "FerryDemo.app";
const EXECUTABLE: &str = "FerryDemo";
const BUNDLE_ID: &str = "org.example.ferry-demo";
const APP_VERSION: &str = "1.2.3";
const BUILD_NUMBER: &str = "1.2.3";
const MINIMUM_OS: &str = "16.1";
const SDK_VERSION: &str = "26.5";
const SDK_BUILD: &str = "23F54";
const RUNTIME_BRIDGE_INSTALL_NAME: &str = "@rpath/FerryRuntimeBridge.framework/FerryRuntimeBridge";
const ACTIVITY_MODEL_INSTALL_NAME: &str = "@rpath/FerryActivityModel.framework/FerryActivityModel";

struct Fixture {
    _temporary: tempfile::TempDir,
    archive: Utf8PathBuf,
    app: Utf8PathBuf,
    expectation: UnsignedXcarchiveExpectation,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new(widget: bool, live_activity: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let archive = root.join("FerryDemo.xcarchive");
        let app = archive.join("Products").join("Applications").join(APP_NAME);
        fs::create_dir_all(&app).unwrap();

        write_plist(&archive.join("Info.plist"), archive_info());
        write_plist(&app.join("Info.plist"), app_info());
        write_macho(
            &app.join(EXECUTABLE),
            &macho(2, 0x2, version(16, 1, 0), version(26, 5, 0), false),
        );

        let resource_metadata = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "generator": "cargo-ferry",
            "ui_backend": "slint-1.17.1",
            "rust_target": "aarch64-apple-ios",
            "bundle_identifier": BUNDLE_ID,
        }))
        .unwrap();
        let icon = b"validated-icon-png".to_vec();
        let splash = b"validated-splash-png".to_vec();
        write_file(&app.join("FerryResources.json"), &resource_metadata);
        write_file(&app.join("FerryIcon.png"), &icon);
        write_file(&app.join("FerrySplash.png"), &splash);

        let mut nested_bundles = vec![UnsignedNestedBundleExpectation {
            relative_path: "Frameworks/FerryRuntimeBridge.framework".to_owned(),
            bundle_identifier: "org.rustferry.runtime-bridge".to_owned(),
            executable: "FerryRuntimeBridge".to_owned(),
            kind: UnsignedNestedBundleKind::Framework,
        }];
        write_framework(
            &app,
            "FerryRuntimeBridge",
            "org.rustferry.runtime-bridge",
            if live_activity {
                &[ACTIVITY_MODEL_INSTALL_NAME]
            } else {
                &[]
            },
        );

        if live_activity {
            nested_bundles.push(UnsignedNestedBundleExpectation {
                relative_path: "Frameworks/FerryActivityModel.framework".to_owned(),
                bundle_identifier: "org.rustferry.activity-model".to_owned(),
                executable: "FerryActivityModel".to_owned(),
                kind: UnsignedNestedBundleKind::Framework,
            });
            write_framework(
                &app,
                "FerryActivityModel",
                "org.rustferry.activity-model",
                &[],
            );
            nested_bundles.push(UnsignedNestedBundleExpectation {
                relative_path: "PlugIns/FerryLiveActivityExtension.appex".to_owned(),
                bundle_identifier: format!("{BUNDLE_ID}.liveactivity"),
                executable: "FerryLiveActivityExtension".to_owned(),
                kind: UnsignedNestedBundleKind::AppExtension,
            });
            write_extension(
                &app,
                "FerryLiveActivityExtension",
                &format!("{BUNDLE_ID}.liveactivity"),
                &[ACTIVITY_MODEL_INSTALL_NAME],
            );
        }
        if widget {
            nested_bundles.push(UnsignedNestedBundleExpectation {
                relative_path: "PlugIns/FerryWidgetExtension.appex".to_owned(),
                bundle_identifier: format!("{BUNDLE_ID}.widget"),
                executable: "FerryWidgetExtension".to_owned(),
                kind: UnsignedNestedBundleKind::AppExtension,
            });
            write_extension(
                &app,
                "FerryWidgetExtension",
                &format!("{BUNDLE_ID}.widget"),
                &[],
            );
        }

        Self {
            _temporary: temporary,
            archive,
            app,
            expectation: UnsignedXcarchiveExpectation {
                app_directory_name: APP_NAME.to_owned(),
                bundle_identifier: BUNDLE_ID.to_owned(),
                executable: EXECUTABLE.to_owned(),
                app_version: APP_VERSION.to_owned(),
                build_number: BUILD_NUMBER.to_owned(),
                minimum_os: MINIMUM_OS.to_owned(),
                sdk_version: SDK_VERSION.to_owned(),
                sdk_build_version: SDK_BUILD.to_owned(),
                nested_bundles,
                required_resources: [
                    ("FerryResources.json".to_owned(), sha256(&resource_metadata)),
                    ("FerryIcon.png".to_owned(), sha256(&icon)),
                    ("FerrySplash.png".to_owned(), sha256(&splash)),
                ]
                .into_iter()
                .collect(),
            },
        }
    }

    fn inspect(&self) -> Result<rustferry_remote::UnsignedXcarchiveInspection, ArtifactError> {
        inspect_unsigned_xcarchive(&self.archive, &self.expectation)
    }
}

#[test]
fn valid_generated_extension_matrices_pass() {
    for (widget, live_activity) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = Fixture::new(widget, live_activity);
        let inspection = fixture.inspect().unwrap();
        assert_eq!(
            inspection.application_path,
            format!("Applications/{APP_NAME}")
        );
        assert_eq!(inspection.architectures, ["arm64"]);
        assert_eq!(inspection.app.bundle_identifier, BUNDLE_ID);
        assert_eq!(inspection.app.main_executable[0].architecture, "arm64");
        assert_eq!(
            inspection.app.extensions.len(),
            usize::from(widget) + usize::from(live_activity)
        );
    }
}

#[test]
fn compatible_prebuilt_swift_runtime_is_allowed() {
    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture.app.join("Frameworks/libswiftCore.dylib"),
        &macho(2, 0x6, version(12, 0, 0), version(25, 0, 0), false),
    );
    let inspection = fixture.inspect().unwrap();
    assert!(
        inspection
            .app
            .nested_executables
            .contains_key("Frameworks/libswiftCore.dylib")
    );
}

#[test]
fn generic_or_multi_product_archive_is_rejected() {
    let fixture = Fixture::new(false, false);
    fs::create_dir_all(fixture.archive.join("Products/Library/Frameworks")).unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(ArtifactError::InvalidAppleBundle { .. })
    ));

    let fixture = Fixture::new(false, false);
    fs::create_dir_all(fixture.archive.join("Products/Applications/Unexpected.app")).unwrap();
    assert!(fixture.inspect().is_err());
}

#[test]
fn unexpected_bundle_or_hidden_macho_is_rejected() {
    let fixture = Fixture::new(false, false);
    fs::create_dir_all(fixture.app.join("PlugIns/Unexpected.appex")).unwrap();
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture.app.join("FerrySplash.dat"),
        &macho(7, 0x2, version(16, 1, 0), version(26, 5, 0), false),
    );
    assert!(fixture.inspect().is_err());
}

#[test]
fn signature_simulator_and_version_drift_are_rejected() {
    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture.app.join(EXECUTABLE),
        &macho(2, 0x2, version(16, 1, 0), version(26, 5, 0), true),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture.app.join(EXECUTABLE),
        &macho(7, 0x2, version(16, 1, 0), version(26, 5, 0), false),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture.app.join(EXECUTABLE),
        &macho(2, 0x2, version(16, 0, 0), version(26, 5, 0), false),
    );
    assert!(fixture.inspect().is_err());
}

#[test]
fn generated_framework_install_names_are_exact() {
    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture
            .app
            .join("Frameworks/FerryRuntimeBridge.framework/FerryRuntimeBridge"),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some("@rpath/Wrong.framework/Wrong"),
            &[],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, true);
    write_macho(
        &fixture
            .app
            .join("Frameworks/FerryActivityModel.framework/FerryActivityModel"),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some("@loader_path/FerryActivityModel"),
            &[],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());
}

#[test]
fn runtime_bridge_links_activity_model_if_and_only_if_live_activity_is_enabled() {
    let fixture = Fixture::new(false, true);
    write_macho(
        &fixture
            .app
            .join("Frameworks/FerryRuntimeBridge.framework/FerryRuntimeBridge"),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some(RUNTIME_BRIDGE_INSTALL_NAME),
            &[],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    write_macho(
        &fixture
            .app
            .join("Frameworks/FerryRuntimeBridge.framework/FerryRuntimeBridge"),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some(RUNTIME_BRIDGE_INSTALL_NAME),
            &[ACTIVITY_MODEL_INSTALL_NAME],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());
}

#[test]
fn live_activity_extension_links_only_the_safe_ferry_model() {
    let fixture = Fixture::new(false, true);
    let executable = fixture
        .app
        .join("PlugIns/FerryLiveActivityExtension.appex/FerryLiveActivityExtension");
    write_macho(
        &executable,
        &macho_with_dylibs(
            2,
            0x2,
            version(16, 1, 0),
            version(26, 5, 0),
            None,
            &[],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, true);
    let executable = fixture
        .app
        .join("PlugIns/FerryLiveActivityExtension.appex/FerryLiveActivityExtension");
    write_macho(
        &executable,
        &macho_with_dylibs(
            2,
            0x2,
            version(16, 1, 0),
            version(26, 5, 0),
            None,
            &[ACTIVITY_MODEL_INSTALL_NAME, RUNTIME_BRIDGE_INSTALL_NAME],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, true);
    write_macho(
        &fixture
            .app
            .join("Frameworks/FerryActivityModel.framework/FerryActivityModel"),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some(ACTIVITY_MODEL_INSTALL_NAME),
            &[RUNTIME_BRIDGE_INSTALL_NAME],
            false,
        ),
    );
    assert!(fixture.inspect().is_err());
}

#[test]
fn resource_and_archive_identity_drift_are_rejected() {
    let fixture = Fixture::new(false, false);
    write_file(&fixture.app.join("FerryIcon.png"), b"different");
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    let mut info = archive_info();
    info.get_mut("ApplicationProperties")
        .and_then(Value::as_dictionary_mut)
        .unwrap()
        .insert(
            "ApplicationPath".to_owned(),
            Value::String("../FerryDemo.app".to_owned()),
        );
    write_plist(&fixture.archive.join("Info.plist"), info);
    assert!(fixture.inspect().is_err());
}

#[cfg(unix)]
#[test]
fn links_and_case_collisions_are_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(false, false);
    symlink(
        fixture.app.join("FerryIcon.png"),
        fixture.app.join("linked-icon.png"),
    )
    .unwrap();
    assert!(fixture.inspect().is_err());

    let fixture = Fixture::new(false, false);
    fs::hard_link(
        fixture.app.join("FerryIcon.png"),
        fixture.app.join("hardlinked-icon.png"),
    )
    .unwrap();
    assert!(fixture.inspect().is_err());

    let mut fixture = Fixture::new(false, false);
    fixture
        .expectation
        .nested_bundles
        .push(UnsignedNestedBundleExpectation {
            relative_path: "Frameworks/ferryruntimebridge.framework".to_owned(),
            bundle_identifier: "org.rustferry.collision".to_owned(),
            executable: "Collision".to_owned(),
            kind: UnsignedNestedBundleKind::Framework,
        });
    assert!(fixture.inspect().is_err());
}

#[cfg(unix)]
#[test]
fn artifact_root_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(false, false);
    let real_archive = fixture.archive.with_extension("real-xcarchive");
    fs::rename(&fixture.archive, &real_archive).unwrap();
    symlink(&real_archive, &fixture.archive).unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(ArtifactError::InvalidAppleBundle { .. })
    ));
}

fn archive_info() -> Dictionary {
    let mut properties = Dictionary::new();
    properties.insert(
        "ApplicationPath".to_owned(),
        Value::String(format!("Applications/{APP_NAME}")),
    );
    properties.insert(
        "Architectures".to_owned(),
        Value::Array(vec![Value::String("arm64".to_owned())]),
    );
    properties.insert(
        "CFBundleIdentifier".to_owned(),
        Value::String(BUNDLE_ID.to_owned()),
    );
    properties.insert(
        "CFBundleShortVersionString".to_owned(),
        Value::String(APP_VERSION.to_owned()),
    );
    properties.insert(
        "CFBundleVersion".to_owned(),
        Value::String(BUILD_NUMBER.to_owned()),
    );
    let mut dictionary = Dictionary::new();
    dictionary.insert(
        "ApplicationProperties".to_owned(),
        Value::Dictionary(properties),
    );
    dictionary
}

fn app_info() -> Dictionary {
    let mut dictionary = built_info(BUNDLE_ID, EXECUTABLE, "APPL", APP_VERSION, BUILD_NUMBER);
    dictionary.insert("LSRequiresIPhoneOS".to_owned(), Value::Boolean(true));
    dictionary.insert(
        "UIRequiredDeviceCapabilities".to_owned(),
        Value::Array(vec![Value::String("arm64".to_owned())]),
    );
    dictionary
}

fn built_info(
    bundle_identifier: &str,
    executable: &str,
    package_type: &str,
    app_version: &str,
    build_number: &str,
) -> Dictionary {
    let mut dictionary = Dictionary::new();
    for (key, value) in [
        ("CFBundleIdentifier", bundle_identifier),
        ("CFBundleExecutable", executable),
        ("CFBundlePackageType", package_type),
        ("CFBundleShortVersionString", app_version),
        ("CFBundleVersion", build_number),
        ("MinimumOSVersion", MINIMUM_OS),
        ("DTPlatformName", "iphoneos"),
        ("DTSDKName", "iphoneos26.5"),
        ("DTSDKBuild", SDK_BUILD),
    ] {
        dictionary.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    dictionary.insert(
        "CFBundleSupportedPlatforms".to_owned(),
        Value::Array(vec![Value::String("iPhoneOS".to_owned())]),
    );
    dictionary
}

fn write_framework(
    app: &Utf8Path,
    executable: &str,
    bundle_identifier: &str,
    dependencies: &[&str],
) {
    let root = app.join(format!("Frameworks/{executable}.framework"));
    write_plist(
        &root.join("Info.plist"),
        built_info(bundle_identifier, executable, "FMWK", "1.0", "1"),
    );
    let install_name = format!("@rpath/{executable}.framework/{executable}");
    write_macho(
        &root.join(executable),
        &macho_with_dylibs(
            2,
            0x6,
            version(16, 1, 0),
            version(26, 5, 0),
            Some(&install_name),
            dependencies,
            false,
        ),
    );
}

fn write_extension(
    app: &Utf8Path,
    executable: &str,
    bundle_identifier: &str,
    dependencies: &[&str],
) {
    let root = app.join(format!("PlugIns/{executable}.appex"));
    let mut info = built_info(
        bundle_identifier,
        executable,
        "XPC!",
        APP_VERSION,
        BUILD_NUMBER,
    );
    let mut extension = Dictionary::new();
    extension.insert(
        "NSExtensionPointIdentifier".to_owned(),
        Value::String("com.apple.widgetkit-extension".to_owned()),
    );
    info.insert("NSExtension".to_owned(), Value::Dictionary(extension));
    write_plist(&root.join("Info.plist"), info);
    write_macho(
        &root.join(executable),
        &macho_with_dylibs(
            2,
            0x2,
            version(16, 1, 0),
            version(26, 5, 0),
            None,
            dependencies,
            false,
        ),
    );
}

fn write_plist(path: &Utf8Path, dictionary: Dictionary) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    Value::Dictionary(dictionary).to_file_xml(path).unwrap();
}

fn write_file(path: &Utf8Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn write_macho(path: &Utf8Path, bytes: &[u8]) {
    write_file(path, bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn macho(platform: u32, filetype: u32, minos: u32, sdk: u32, signed: bool) -> Vec<u8> {
    macho_with_dylibs(platform, filetype, minos, sdk, None, &[], signed)
}

fn macho_with_dylibs(
    platform: u32,
    filetype: u32,
    minos: u32,
    sdk: u32,
    install_name: Option<&str>,
    dependencies: &[&str],
    signed: bool,
) -> Vec<u8> {
    let mut dylib_commands = Vec::new();
    if let Some(install_name) = install_name {
        dylib_commands.push(dylib_command(0x0d, install_name));
    }
    dylib_commands.extend(
        dependencies
            .iter()
            .map(|dependency| dylib_command(0x0c, dependency)),
    );
    let command_count = 1 + u32::try_from(dylib_commands.len()).unwrap() + u32::from(signed);
    let command_size =
        24 + dylib_commands.iter().map(Vec::len).sum::<usize>() + if signed { 16 } else { 0 };
    let command_size_u32 = u32::try_from(command_size).unwrap();
    let mut bytes = Vec::new();
    for value in [
        0xfeed_facfu32,
        0x0100_000c,
        0,
        filetype,
        command_count,
        command_size_u32,
        0,
        0,
        0x32,
        24,
        platform,
        minos,
        sdk,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for command in dylib_commands {
        bytes.extend_from_slice(&command);
    }
    if signed {
        for value in [0x1d_u32, 16, 32 + command_size_u32, 4] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(b"SIGN");
    }
    bytes
}

fn dylib_command(command: u32, name: &str) -> Vec<u8> {
    let size = (24 + name.len() + 1).next_multiple_of(8);
    let size_u32 = u32::try_from(size).unwrap();
    let mut bytes = Vec::with_capacity(size);
    for value in [command, size_u32, 24, 0, 0x1_0000, 0x1_0000] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(name.as_bytes());
    bytes.resize(size, 0);
    bytes
}

const fn version(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
