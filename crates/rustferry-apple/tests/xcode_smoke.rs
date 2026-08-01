//! macOS-only artifact smoke tests for the generated Xcode host.
#![cfg(target_os = "macos")]

use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_apple::{
    AppleDiscoveryOptions, CommandSpec, ExtensionKind, IosExtensionExpectation, IosProjectSpec,
    IosSimulatorBuildRequest, build_ios_simulator, discover_apple, generate_ios_project,
    plan_ios_simulator, run_command, validate_ios_extension, write_ios_project,
};
use rustferry_core::FerryConfig;

fn test_project(environment_name: &str) -> (Option<tempfile::TempDir>, Utf8PathBuf) {
    let result = if let Some(path) = std::env::var_os(environment_name) {
        let path = Utf8PathBuf::from_path_buf(path.into()).expect("UTF-8 smoke project path");
        fs::create_dir_all(&path).unwrap();
        (None, path)
    } else {
        let temporary = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        (Some(temporary), path)
    };
    write_test_assets(&result.1);
    result
}

fn write_test_assets(project: &Utf8Path) {
    const PNG: &[u8] = include_bytes!("../../../examples/counter/assets/icon.png");
    fs::create_dir_all(project.join("assets")).unwrap();
    fs::write(project.join("assets/icon.png"), PNG).unwrap();
    fs::write(project.join("assets/splash.png"), PNG).unwrap();
}

#[test]
#[ignore = "requires full Xcode and the aarch64-apple-ios-sim Rust target"]
fn builds_and_validates_real_simulator_app() {
    let (_temporary, project) = test_project("FERRY_APPLE_BASE_PROJECT");
    fs::create_dir_all(project.join("src")).unwrap();
    let runtime = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry");
    fs::write(
        project.join("Cargo.toml"),
        format!(
            "[package]\nname = \"rustferry-ios-smoke\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nrustferry = {{ path = {runtime:?}, default-features = false, features = [\"storage\", \"network\", \"haptics\", \"notifications\", \"clipboard\", \"share\", \"widgets\", \"live-activity\"] }}\n\n[workspace]\n"
        ),
    )
    .unwrap();
    fs::write(
        project.join("src/main.rs"),
        "fn main() { rustferry::ios::install().expect(\"install generated iOS runtime\"); }\n",
    )
    .unwrap();

    let request = IosSimulatorBuildRequest::new(
        &project,
        FerryConfig::starter("RustFerry Smoke", "com.example.ferrysmoke"),
        "rustferry-ios-smoke",
    );
    let outcome = build_ios_simulator(&request).unwrap();
    let artifact = outcome.artifact.expect("non-dry-run artifact");
    let validation = outcome.validation.expect("artifact validation");
    assert!(artifact.is_dir());
    assert_eq!(validation.bundle_identifier, "com.example.ferrysmoke");
    assert_eq!(validation.architectures, ["arm64"]);
    assert!(validation.rust_binary_embedded);
    assert!(validation.code_signature.deep_verified);
    assert_eq!(
        validation.code_signature.identifier,
        "com.example.ferrysmoke"
    );
    assert!(validation.runtime_bridge.code_signature.strict_verified);
    assert!(validation.runtime_bridge.application_delegate_hook);
    for symbol in [
        "_ferry_bridge_call",
        "_ferry_bridge_free",
        "_ferry_bridge_init",
        "_ferry_bridge_install",
        "_ferry_bridge_with_application",
    ] {
        assert!(
            validation
                .runtime_bridge
                .exported_symbols
                .iter()
                .any(|exported| exported == symbol)
        );
    }
    assert_eq!(
        validation.application_delegate.as_deref(),
        Some("FerryApplicationDelegate")
    );
    assert!(
        validation
            .resources
            .iter()
            .any(|path| path.file_name() == Some("FerryResources.json"))
    );
}

#[test]
#[ignore = "requires full Xcode, network/cache access, and the iOS Simulator Rust target"]
fn builds_and_validates_slint_simulator_app() {
    let (_temporary, project) = test_project("FERRY_APPLE_SLINT_PROJECT");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"ferry-slint-smoke\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.92\"\n\n[dependencies]\nslint = { version = \"=1.17.1\", default-features = false, features = [\"std\", \"compat-1-2\", \"backend-winit\", \"renderer-skia\"] }\n\n[workspace]\n",
    )
    .unwrap();
    fs::write(
        project.join("src/main.rs"),
        "slint::slint! { export component FerryWindow inherits Window { Text { text: \"RustFerry on iOS\"; } } }\nfn main() { FerryWindow::new().unwrap().run().unwrap(); }\n",
    )
    .unwrap();

    let request = IosSimulatorBuildRequest::new(
        &project,
        FerryConfig::starter("RustFerry Slint", "com.example.ferryslint"),
        "ferry-slint-smoke",
    );
    let outcome = build_ios_simulator(&request).unwrap();
    let validation = outcome.validation.expect("artifact validation");
    assert_eq!(validation.bundle_identifier, "com.example.ferryslint");
    assert_eq!(validation.architectures, ["arm64"]);
    assert!(validation.rust_binary_embedded);
    assert!(validation.code_signature.deep_verified);
}

#[test]
#[ignore = "requires full Xcode and the iPhone Simulator SDK"]
#[allow(clippy::too_many_lines)]
fn builds_real_widgetkit_and_activitykit_targets() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    write_test_assets(root);
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"ferry-extensions\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    let mut config = FerryConfig::starter("RustFerry Extensions", "com.example.ferryextensions");
    config.extensions.widget.enabled = true;
    config.extensions.widget.app_group = Some("group.com.example.ferryextensions".into());
    config.extensions.live_activity.enabled = true;
    config.ios.min_version = "16.1".into();

    let discovery = discover_apple(&AppleDiscoveryOptions {
        current_dir: root.to_owned(),
        ..AppleDiscoveryOptions::from_environment()
    })
    .unwrap();
    let toolchain = discovery.select_toolchain().unwrap();
    let request = IosSimulatorBuildRequest::new(root, config.clone(), "ferry-extensions");
    let plan = plan_ios_simulator(&request, &toolchain).expect("plan extension build");
    let generated = generate_ios_project(&IosProjectSpec::new(config, "ferry-extensions"))
        .expect("generate extension targets");
    write_ios_project(&generated, &plan.generated_root).expect("write extension targets");
    let products = plan.artifact_path.join("PlugIns");
    fs::create_dir_all(&products).unwrap();

    for target in ["FerryWidgetExtension", "FerryLiveActivityExtension"] {
        let mut command = CommandSpec::new(
            format!("build generated {target}"),
            &toolchain.xcodebuild,
            root,
        );
        command.environment.insert(
            "DEVELOPER_DIR".to_owned(),
            toolchain.developer_dir.to_string(),
        );
        command.args = vec![
            "-project".into(),
            plan.generated_root.join("FerryHost.xcodeproj").to_string(),
            "-target".into(),
            target.into(),
            "-configuration".into(),
            "Debug".into(),
            "-sdk".into(),
            "iphonesimulator".into(),
            "AD_HOC_CODE_SIGNING_ALLOWED=YES".into(),
            "CODE_SIGN_IDENTITY=-".into(),
            "CODE_SIGNING_ALLOWED=YES".into(),
            "CODE_SIGNING_REQUIRED=YES".into(),
            "ARCHS=arm64".into(),
            "ONLY_ACTIVE_ARCH=NO".into(),
            format!("SYMROOT={}", root.join("xcode")),
            format!("OBJROOT={}", root.join("xcode/Intermediates")),
            format!("CONFIGURATION_BUILD_DIR={products}"),
            "build".into(),
        ];
        run_command(&command, Some(&root.join(format!("{target}.log"))))
            .expect("build generated extension target");
    }
    let widget_resign = plan
        .commands
        .get(2)
        .expect("production plan includes WidgetKit entitlement re-signing");
    run_command(widget_resign, Some(&root.join("widget-resign.log")))
        .expect("re-sign WidgetKit extension with production command");

    assert!(products.join("FerryWidgetExtension.appex").is_dir());
    assert!(products.join("FerryLiveActivityExtension.appex").is_dir());
    assert!(
        products
            .join("FerryWidgetExtension.appex/FerryWidgetExtension")
            .is_file()
    );
    assert!(
        products
            .join("FerryLiveActivityExtension.appex/FerryLiveActivityExtension")
            .is_file()
    );
    for expected in [
        IosExtensionExpectation {
            kind: ExtensionKind::WidgetKit,
            bundle_name: "FerryWidgetExtension".into(),
            bundle_identifier: "com.example.ferryextensions.widget".into(),
            executable_name: "FerryWidgetExtension".into(),
            app_group: Some("group.com.example.ferryextensions".into()),
        },
        IosExtensionExpectation {
            kind: ExtensionKind::ActivityKit,
            bundle_name: "FerryLiveActivityExtension".into(),
            bundle_identifier: "com.example.ferryextensions.liveactivity".into(),
            executable_name: "FerryLiveActivityExtension".into(),
            app_group: None,
        },
    ] {
        let validation = validate_ios_extension(
            &products.join(format!("{}.appex", expected.bundle_name)),
            &expected,
            &["arm64".into()],
            &toolchain,
            Some(&root.join("validation")),
        )
        .expect("validate generated extension product");
        assert_eq!(validation.kind, expected.kind);
        assert_eq!(
            validation.activity_model_linked,
            expected.kind == ExtensionKind::ActivityKit
        );
        assert!(validation.code_signature.strict_verified);
        assert_eq!(
            validation.code_signature.app_groups,
            expected.app_group.iter().cloned().collect::<Vec<_>>()
        );
    }
}

#[test]
#[ignore = "requires full Xcode and the aarch64-apple-ios-sim Rust target"]
fn builds_app_with_embedded_widgetkit_and_activitykit_extensions() {
    let (_temporary, project) = test_project("FERRY_APPLE_EXTENSIONS_PROJECT");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"ferry-extension-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .unwrap();
    fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();
    let mut config =
        FerryConfig::starter("RustFerry Extension App", "com.example.ferryextensionapp");
    config.extensions.widget.enabled = true;
    config.extensions.widget.app_group = Some("group.com.example.ferryextensionapp".into());
    config.extensions.live_activity.enabled = true;
    config.ios.min_version = "16.1".into();

    let request = IosSimulatorBuildRequest::new(&project, config, "ferry-extension-app");
    let outcome = build_ios_simulator(&request).expect("build extension app");
    let validation = outcome.validation.expect("artifact validation");
    assert_eq!(validation.extensions.len(), 2);
    assert!(
        validation
            .embedded_frameworks
            .iter()
            .any(|path| path.file_name() == Some("FerryActivityModel.framework"))
    );
    assert_eq!(
        validation.code_signature.app_groups,
        ["group.com.example.ferryextensionapp"]
    );
    assert!(validation.code_signature.deep_verified);
    assert!(
        validation
            .extensions
            .iter()
            .any(|extension| extension.kind == ExtensionKind::WidgetKit)
    );
    assert!(
        validation
            .extensions
            .iter()
            .any(|extension| extension.kind == ExtensionKind::ActivityKit)
    );
    for extension in validation.extensions {
        assert_eq!(
            extension.activity_model_linked,
            extension.kind == ExtensionKind::ActivityKit
        );
        assert_eq!(extension.architectures, ["arm64"]);
        assert_eq!(
            extension.extension_point_identifier,
            "com.apple.widgetkit-extension"
        );
        assert!(extension.path.starts_with(&validation.app_path));
        if extension.kind == ExtensionKind::WidgetKit {
            assert_eq!(
                extension.code_signature.app_groups,
                ["group.com.example.ferryextensionapp"]
            );
        } else {
            assert!(extension.code_signature.app_groups.is_empty());
        }
    }
}
