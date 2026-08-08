//! Opt-in end-to-end Android SDK/NDK artifact validation.

use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_android::{
    AndroidBuildOutcome, AndroidBuildRequest, AndroidSigningConfig, DoctorOptions, build_android,
    doctor_android,
};
use rustferry_codegen::{
    PlatformSelection, ProjectGenerator, ProjectRequest, RuntimeDependency, TemplateKind,
};

#[test]
#[ignore = "requires Android SDK/NDK/JDK, the aarch64 Rust target, and registry access"]
fn generated_minimal_project_produces_verified_apk() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = Utf8Path::from_path(temporary.path()).unwrap();
    let manifest_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().unwrap().parent().unwrap();
    let generated = ProjectGenerator::new(
        parent,
        ProjectRequest {
            name: "android-probe".to_owned(),
            display_name: None,
            identifier: Some("com.example.androidprobe".to_owned()),
            template: TemplateKind::Minimal,
            platforms: PlatformSelection::Android,
            runtime_dependency: RuntimeDependency::Path(workspace.join("crates/rustferry")),
        },
    )
    .generate()
    .unwrap();
    let mut config =
        rustferry_core::FerryConfig::load(&generated.destination.join("ferry.toml")).unwrap();
    config.capabilities.network.mode = rustferry_core::NetworkMode::Optional;
    config.capabilities.haptics.enabled = true;
    config.capabilities.share.enabled = true;
    config.capabilities.notifications.local = true;
    config.capabilities.deep_links.schemes = vec!["probe".to_owned()];
    config.capabilities.deep_links.allowed_hosts = vec!["open.example".to_owned()];
    config.capabilities.deep_links.allowed_actions = vec!["details".to_owned()];
    config.extensions.widget.enabled = true;
    config.extensions.widget.app_group = Some("group.com.example.androidprobe".to_owned());
    config.permissions.camera.enabled = true;
    config.permissions.camera.purpose = Some("Capture a test image".to_owned());
    config.permissions.photos.enabled = true;
    config.permissions.photos.purpose = Some("Choose a test image".to_owned());
    config.permissions.microphone.enabled = true;
    config.permissions.microphone.purpose = Some("Record test audio".to_owned());
    config.permissions.location_when_in_use.enabled = true;
    config.permissions.location_when_in_use.purpose = Some("Test local conditions".to_owned());
    let mut request = AndroidBuildRequest::new(
        &generated.destination,
        config,
        "android-probe",
        "android_probe",
    );
    request.cargo_target_dir = workspace.join("target/android-e2e");
    request.signing = AndroidSigningConfig::Debug {
        config_dir: Some(Utf8PathBuf::from_path_buf(temporary.path().join("config")).unwrap()),
    };
    request.command_timeout = Duration::from_mins(30);

    let outcome = build_android(&request).unwrap();
    let AndroidBuildOutcome::Built(artifact) = outcome else {
        panic!("non-dry build returned a dry-run plan");
    };
    let validation = artifact.validation();
    assert!(artifact.apk().is_file());
    assert_eq!(validation.package_name, "com.example.androidprobe");
    assert_eq!(
        validation.launcher_activity,
        rustferry_android::ACTIVITY_CLASS
    );
    assert_eq!(validation.native_abis, ["arm64-v8a"]);
    assert!(validation.dex_files >= 1);
    assert!(
        validation
            .manifest
            .permissions
            .contains(&"android.permission.CAMERA".to_owned())
    );
    assert_eq!(
        validation.manifest.deep_link_filters,
        ["scheme=probe;host=open.example;pathPrefix=/details"]
    );
    for component in [
        format!("activity:{}", rustferry_android::ACTIVITY_CLASS),
        format!("provider:{}", rustferry_android::FILE_PROVIDER_CLASS),
        format!(
            "receiver:{}",
            rustferry_android::NOTIFICATION_RECEIVER_CLASS
        ),
        format!("receiver:{}", rustferry_android::WIDGET_PROVIDER_CLASS),
    ] {
        assert!(validation.manifest.components.contains(&component));
    }
    eprintln!("verified APK: {}", artifact.apk());
    eprintln!("validation: {validation:?}");

    let repeated = build_android(&request).unwrap();
    let AndroidBuildOutcome::Built(repeated) = repeated else {
        panic!("repeated build returned a dry-run plan");
    };
    for stage in ["aapt2-compile", "aapt2-link", "d8"] {
        assert!(
            repeated.cache_hits().iter().any(|hit| hit == stage),
            "repeated build did not reuse {stage}"
        );
    }
}

#[test]
#[ignore = "requires the configured Android SDK/NDK/JDK and aarch64 Rust target"]
fn host_doctor_reports_build_ready() {
    let report = doctor_android(&DoctorOptions::default());
    eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());
    assert!(report.ready_for_build);
}
