//! Physical-iPhone compile/archive planning contracts.

use std::fs;
#[cfg(target_os = "macos")]
use std::process::Command;

use camino::Utf8Path;
#[cfg(target_os = "macos")]
use rustferry_apple::{
    AppleDiscoveryOptions, build_ios_device_unsigned, discover_apple, write_ios_project,
};
use rustferry_apple::{
    IOS_DEVICE_TARGET, IosDeviceArchiveRequest, IosDeviceArtifactDisposition, IosDeviceSdk,
    IosDeviceToolchain, IosProjectPlatform, IosProjectSpec, derive_ios_device_product_expectation,
    generate_ios_project, generate_ios_project_for_platform, plan_ios_device_unsigned,
};
use rustferry_core::FerryConfig;
#[cfg(target_os = "macos")]
use rustferry_core::ProjectAssets;
#[cfg(target_os = "macos")]
use rustferry_remote::inspect_unsigned_xcarchive;

fn fake_toolchain(root: &Utf8Path) -> IosDeviceToolchain {
    IosDeviceToolchain {
        developer_dir: root.join("Xcode.app/Contents/Developer"),
        xcode_version: "Xcode 26.0".to_owned(),
        device_sdk: IosDeviceSdk {
            path: root.join("iPhoneOS.sdk"),
            version: "26.0".to_owned(),
            build_version: "23A1".to_owned(),
        },
        cargo: root.join("bin/cargo"),
        rustup: root.join("bin/rustup"),
        xcodebuild: root.join("bin/xcodebuild"),
        xcrun: root.join("bin/xcrun"),
        plutil: root.join("bin/plutil"),
        host_arch: "aarch64".to_owned(),
    }
}

fn request(root: &Utf8Path) -> IosDeviceArchiveRequest {
    const PNG: &[u8] = include_bytes!("../../../examples/counter/assets/icon.png");

    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='weather'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("assets")).unwrap();
    fs::write(root.join("assets/icon.png"), PNG).unwrap();
    fs::write(root.join("assets/splash.png"), PNG).unwrap();
    IosDeviceArchiveRequest::new(
        root,
        FerryConfig::starter("Weather", "com.example.weather"),
        "weather",
    )
}

fn adjacent_argument<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|arguments| arguments[0] == flag)
        .map(|arguments| arguments[1].as_str())
}

#[test]
fn device_plan_uses_physical_target_sdk_destination_and_unsigned_archive() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let plan = plan_ios_device_unsigned(&request(root), &fake_toolchain(root)).unwrap();

    assert_eq!(plan.rust_target, IOS_DEVICE_TARGET);
    assert_eq!(plan.sdk, "iphoneos");
    assert_eq!(plan.destination, "generic/platform=iOS");
    assert_eq!(
        plan.disposition,
        IosDeviceArtifactDisposition::UnsignedCompileOnly
    );
    assert!(plan.generated_root.starts_with(root.join("target/ferry")));
    assert!(plan.archive_path.as_str().ends_with("weather.xcarchive"));
    assert_eq!(
        plan.app_path,
        plan.archive_path.join("Products/Applications/weather.app")
    );

    let preflight = &plan.commands[0];
    assert_eq!(adjacent_argument(&preflight.args, "-sdk"), Some("iphoneos"));
    assert_eq!(
        preflight.args.last().map(String::as_str),
        Some("-showdestinations")
    );
    let cargo = &plan.commands[1];
    assert_eq!(
        adjacent_argument(&cargo.args, "--target"),
        Some(IOS_DEVICE_TARGET)
    );
    let xcode = &plan.commands[2];
    assert_eq!(adjacent_argument(&xcode.args, "-sdk"), Some("iphoneos"));
    assert_eq!(
        adjacent_argument(&xcode.args, "-destination"),
        Some("generic/platform=iOS")
    );
    assert_eq!(
        adjacent_argument(&xcode.args, "-archivePath"),
        Some(plan.archive_path.as_str())
    );
    assert_eq!(xcode.args.last().map(String::as_str), Some("archive"));
    for setting in [
        "AD_HOC_CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGN_IDENTITY=",
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
        "DEVELOPMENT_TEAM=",
        "PROVISIONING_PROFILE_SPECIFIER=",
        "ARCHS=arm64",
        "ONLY_ACTIVE_ARCH=NO",
    ] {
        assert!(xcode.args.iter().any(|argument| argument == setting));
    }
    assert!(!xcode.args.iter().any(|argument| {
        argument.contains("iphonesimulator")
            || argument.contains("aarch64-apple-ios-sim")
            || argument == "CODE_SIGNING_ALLOWED=YES"
    }));
}

#[test]
fn client_product_expectation_matches_the_worker_archive_plan() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let request = request(root);
    let product =
        derive_ios_device_product_expectation(&request.config, &request.binary_name).unwrap();
    let plan = plan_ios_device_unsigned(&request, &fake_toolchain(root)).unwrap();

    assert_eq!(product.app_directory_name, "weather.app");
    assert_eq!(product.executable, "weather");
    assert_eq!(product.app_version, request.config.app.display_version);
    assert_eq!(product.nested_bundles.len(), 1);
    assert_eq!(
        plan.archive_expectation.app_directory_name,
        product.app_directory_name
    );
    assert_eq!(plan.archive_expectation.executable, product.executable);
    assert_eq!(plan.archive_expectation.app_version, product.app_version);
    assert_eq!(plan.archive_expectation.build_number, product.build_number);
    assert_eq!(
        plan.archive_expectation.nested_bundles,
        product.nested_bundles
    );
}

#[test]
fn validation_hook_requires_arm64_and_physical_ios_platform() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let toolchain = fake_toolchain(root);
    let plan = plan_ios_device_unsigned(&request(root), &toolchain).unwrap();
    let validation = &plan.macho_validation;

    assert_eq!(validation.executable_path, plan.app_path.join("weather"));
    assert_eq!(validation.expected_architecture, "arm64");
    assert_eq!(validation.expected_platform, "IOS");
    assert_eq!(validation.expected_minimum_os, "16.0");
    assert_eq!(validation.expected_sdk, "26.0");
    assert_eq!(validation.commands.len(), 2);
    assert_eq!(validation.commands[0].program, toolchain.xcrun);
    assert_eq!(
        validation.commands[0].args,
        vec!["lipo", "-archs", validation.executable_path.as_str(),]
    );
    assert_eq!(
        validation.commands[1].args,
        vec!["vtool", "-show-build", validation.executable_path.as_str(),]
    );
}

#[test]
fn device_project_switches_every_target_to_iphoneos_without_signing() {
    let mut config = FerryConfig::starter("Weather", "com.example.weather");
    config.extensions.widget.enabled = true;
    config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
    config.extensions.live_activity.enabled = true;
    config.ios.min_version = "16.1".to_owned();
    let spec = IosProjectSpec::new(config, "weather");
    let generated =
        generate_ios_project_for_platform(&spec, IosProjectPlatform::DeviceUnsigned).unwrap();
    let project = generated
        .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
        .unwrap();

    assert!(!project.contains("iphonesimulator"));
    assert!(!project.contains("CODE_SIGNING_ALLOWED = YES"));
    assert!(!project.contains("CODE_SIGNING_REQUIRED = YES"));
    assert!(!project.contains("CODE_SIGN_IDENTITY = \"-\""));
    assert!(!project.contains("CodeSignOnCopy"));
    assert!(project.contains("SDKROOT = iphoneos"));
    assert!(project.contains("SUPPORTED_PLATFORMS = iphoneos"));
    assert!(project.contains("AD_HOC_CODE_SIGNING_ALLOWED = NO"));
    assert!(project.contains("CODE_SIGN_IDENTITY = \"\""));
    assert!(project.contains("CODE_SIGNING_ALLOWED = NO"));
    assert!(project.contains("CODE_SIGNING_REQUIRED = NO"));
    let resources = generated
        .text(Utf8Path::new("FerryResources.json"))
        .unwrap();
    assert!(resources.contains("\"rust_target\": \"aarch64-apple-ios\""));
    assert!(!resources.contains("aarch64-apple-ios-sim"));
}

#[test]
fn device_project_platform_rewrite_does_not_change_user_identifiers() {
    let config = FerryConfig::starter(
        "iPhone Simulator Weather",
        "com.example.iphonesimulator.weather",
    );
    let spec = IosProjectSpec::new(config, "iphonesimulator-weather");
    let generated =
        generate_ios_project_for_platform(&spec, IosProjectPlatform::DeviceUnsigned).unwrap();
    let project = generated
        .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
        .unwrap();

    assert!(project.contains("com.example.iphonesimulator.weather"));
    assert!(project.contains("iphonesimulator-weather"));
    assert!(!project.contains("SDKROOT = iphonesimulator"));
    assert!(!project.contains("SUPPORTED_PLATFORMS = iphonesimulator"));
}

#[test]
fn default_simulator_generation_remains_byte_for_byte_identical() {
    let spec = IosProjectSpec::new(
        FerryConfig::starter("Weather", "com.example.weather"),
        "weather",
    );
    let default = generate_ios_project(&spec).unwrap();
    let explicit = generate_ios_project_for_platform(&spec, IosProjectPlatform::Simulator).unwrap();

    assert_eq!(default.files, explicit.files);
    let project = default
        .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
        .unwrap();
    assert!(project.contains("SDKROOT = iphonesimulator"));
    assert!(project.contains("SUPPORTED_PLATFORMS = iphonesimulator"));
    assert!(project.contains("AD_HOC_CODE_SIGNING_ALLOWED = YES"));
    assert!(project.contains("CODE_SIGN_IDENTITY = \"-\""));
    assert!(project.contains("CODE_SIGNING_ALLOWED = YES"));
    assert!(project.contains("CODE_SIGNING_REQUIRED = YES"));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires full Xcode"]
fn xcode_accepts_generated_unsigned_device_project() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let generated_root = root.join("generated");
    let spec = IosProjectSpec::new(
        FerryConfig::starter("Weather", "com.example.weather"),
        "weather",
    );
    let generated =
        generate_ios_project_for_platform(&spec, IosProjectPlatform::DeviceUnsigned).unwrap();
    write_ios_project(&generated, &generated_root).unwrap();

    let discovery = discover_apple(&AppleDiscoveryOptions {
        current_dir: root.to_owned(),
        ..AppleDiscoveryOptions::from_environment()
    })
    .unwrap();
    let toolchain = discovery.select_toolchain().unwrap();
    let output = Command::new(&toolchain.xcodebuild)
        .args([
            "-project",
            generated_root.join("FerryHost.xcodeproj").as_str(),
            "-list",
        ])
        .env("DEVELOPER_DIR", &toolchain.developer_dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "xcodebuild rejected generated project: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires full Xcode with an installed physical-iOS platform component"]
fn xcode_archives_real_unsigned_device_products_for_structural_validation() {
    for extensions in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(temporary.path()).unwrap();
        let mut request = request(root);
        if extensions {
            request.config.extensions.widget.enabled = true;
            request.config.extensions.widget.app_group =
                Some("group.com.example.weather".to_owned());
            request.config.extensions.live_activity.enabled = true;
            request.config.ios.min_version = "16.1".to_owned();
        }
        let discovery = discover_apple(&AppleDiscoveryOptions {
            current_dir: root.to_owned(),
            ..AppleDiscoveryOptions::from_environment()
        })
        .unwrap();
        let simulator_tools = discovery.select_toolchain().unwrap();
        let toolchain = IosDeviceToolchain {
            developer_dir: simulator_tools.developer_dir,
            xcode_version: simulator_tools.xcode_version,
            device_sdk: discovery.device_sdk.unwrap(),
            cargo: simulator_tools.cargo,
            rustup: simulator_tools.rustup,
            xcodebuild: simulator_tools.xcodebuild,
            xcrun: simulator_tools.xcrun,
            plutil: simulator_tools.plutil,
            host_arch: simulator_tools.host_arch,
        };
        let plan = plan_ios_device_unsigned(&request, &toolchain).unwrap();
        let assets = ProjectAssets::load(root).unwrap();
        let generated = generate_ios_project_for_platform(
            &IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
                .with_assets(assets),
            IosProjectPlatform::DeviceUnsigned,
        )
        .unwrap();
        write_ios_project(&generated, &plan.generated_root).unwrap();

        let source = root.join("physical-device-fixture.c");
        fs::write(&source, "int main(void) { return 0; }\n").unwrap();
        let target = format!("arm64-apple-ios{}", request.config.ios.min_version);
        let output = Command::new(&toolchain.xcrun)
            .args([
                "--sdk",
                "iphoneos",
                "clang",
                "-target",
                &target,
                "-isysroot",
                toolchain.device_sdk.path.as_str(),
                "-Wl,-e,_main",
                "-o",
                plan.rust_binary_copy.destination.as_str(),
                source.as_str(),
            ])
            .env("DEVELOPER_DIR", &toolchain.developer_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "clang could not create physical-iOS fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        fs::create_dir_all(&plan.xcode_derived_data).unwrap();
        fs::create_dir_all(plan.archive_path.parent().unwrap()).unwrap();
        let xcode = &plan.commands[2];
        let output = Command::new(&xcode.program)
            .args(&xcode.args)
            .current_dir(&xcode.current_dir)
            .envs(&xcode.environment)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "xcodebuild could not create unsigned device archive: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let inspection =
            inspect_unsigned_xcarchive(&plan.archive_path, &plan.archive_expectation).unwrap();
        assert_eq!(inspection.architectures, ["arm64"]);
        assert_eq!(
            inspection.app.extensions.len(),
            if extensions { 2 } else { 0 }
        );
    }
}

#[test]
fn serialized_plan_never_claims_installability_or_signing() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let plan = plan_ios_device_unsigned(&request(root), &fake_toolchain(root)).unwrap();
    let encoded = serde_json::to_string(&plan).unwrap();

    assert!(encoded.contains("unsigned-compile-only"));
    assert!(encoded.contains("CODE_SIGNING_ALLOWED=NO"));
    assert!(!encoded.contains("CODE_SIGNING_ALLOWED=YES"));
    assert!(!encoded.contains("iphonesimulator"));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires full Xcode and the aarch64-apple-ios Rust target"]
fn builds_and_validates_real_unsigned_device_archive() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(temporary.path()).unwrap();
    let request = request(root);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    let discovery = discover_apple(&AppleDiscoveryOptions {
        current_dir: root.to_owned(),
        ..AppleDiscoveryOptions::from_environment()
    })
    .unwrap();
    let toolchain = discovery.select_device_toolchain().unwrap();

    let outcome = build_ios_device_unsigned(&request, &toolchain).unwrap();
    assert_eq!(
        outcome.plan.disposition,
        IosDeviceArtifactDisposition::UnsignedCompileOnly
    );
    assert!(outcome.archive.as_ref().is_some_and(|path| path.is_dir()));
    assert!(outcome.app.as_ref().is_some_and(|path| path.is_dir()));
    let validation = outcome.macho_validation.unwrap();
    assert_eq!(validation.architecture, "arm64");
    assert_eq!(validation.platform, "IOS");
    assert_eq!(validation.minimum_os, request.config.ios.min_version);
    assert_eq!(validation.sdk, toolchain.device_sdk.version);
    assert!(outcome.archive_inspection.is_some());
}
