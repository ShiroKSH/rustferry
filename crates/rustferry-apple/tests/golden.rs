//! Golden contracts for deterministic Apple platform generation.

use std::fmt::Write as _;

use camino::Utf8Path;
use rustferry_apple::{IosProjectSpec, generate_ios_project};
use rustferry_core::FerryConfig;

fn file_list(spec: &IosProjectSpec) -> String {
    let generated = generate_ios_project(spec).unwrap();
    let mut output = String::new();
    for path in generated.files.keys() {
        writeln!(output, "{path}").unwrap();
    }
    output
}

#[test]
fn base_info_plist_and_file_set_match_golden() {
    let spec = IosProjectSpec::new(
        FerryConfig::starter("Weather", "com.example.weather"),
        "weather",
    );
    let generated = generate_ios_project(&spec).unwrap();
    assert_eq!(
        generated.text(Utf8Path::new("Info.plist")).unwrap(),
        include_str!("golden/base-info.plist")
    );
    assert_eq!(file_list(&spec), include_str!("golden/base-files.txt"));
}

#[test]
fn extension_file_set_and_xcode_structure_match_golden() {
    let mut config = FerryConfig::starter("Weather", "com.example.weather");
    config.extensions.widget.enabled = true;
    config.extensions.widget.app_group = Some("group.com.example.weather".into());
    config.extensions.live_activity.enabled = true;
    config.ios.min_version = "16.1".into();
    let spec = IosProjectSpec::new(config, "weather");
    let generated = generate_ios_project(&spec).unwrap();
    assert_eq!(
        file_list(&spec),
        include_str!("golden/extensions-files.txt")
    );
    let project = generated
        .text(Utf8Path::new("FerryHost.xcodeproj/project.pbxproj"))
        .unwrap();
    assert_eq!(
        project_structure_snapshot(project),
        include_str!("golden/extension-project-structure.txt")
    );
}

fn project_structure_snapshot(project: &str) -> String {
    let mut output = String::new();
    for (label, needle) in [
        (
            "com.apple.product-type.application",
            "com.apple.product-type.application",
        ),
        (
            "com.apple.product-type.app-extension",
            "com.apple.product-type.app-extension",
        ),
        (
            "FerryWidgetExtension.appex in Embed App Extensions",
            "FerryWidgetExtension.appex in Embed App Extensions",
        ),
        (
            "FerryLiveActivityExtension.appex in Embed App Extensions",
            "FerryLiveActivityExtension.appex in Embed App Extensions",
        ),
        ("Widget.swift in Sources", "Widget.swift in Sources"),
        (
            "LiveActivity.swift in Sources",
            "LiveActivity.swift in Sources",
        ),
        ("PBXTargetDependency", "PBXTargetDependency"),
        ("Install Rust Executable", "Install Rust Executable"),
        (
            "AD_HOC_CODE_SIGNING_ALLOWED = YES",
            "AD_HOC_CODE_SIGNING_ALLOWED = YES",
        ),
        ("CODE_SIGN_IDENTITY = \"-\"", "CODE_SIGN_IDENTITY = \"-\""),
        ("CODE_SIGNING_ALLOWED = YES", " CODE_SIGNING_ALLOWED = YES;"),
        ("CODE_SIGNING_REQUIRED = YES", "CODE_SIGNING_REQUIRED = YES"),
        (
            "SUPPORTED_PLATFORMS = iphonesimulator",
            "SUPPORTED_PLATFORMS = iphonesimulator",
        ),
    ] {
        writeln!(output, "{label}: {}", project.matches(needle).count()).unwrap();
    }
    writeln!(
        output,
        "disabled signing settings: {}",
        project.matches("CODE_SIGNING_ALLOWED = NO").count()
            + project.matches("CODE_SIGNING_REQUIRED = NO").count()
    )
    .unwrap();
    output
}
