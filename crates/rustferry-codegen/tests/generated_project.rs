//! End-to-end host compilation tests for generated application projects.

use std::{fs, process::Command};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_codegen::{
    PlatformSelection, ProjectGenerator, ProjectRequest, RuntimeDependency, TemplateKind,
};

#[test]
fn every_template_passes_cargo_check() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = Utf8Path::from_path(temporary.path()).unwrap();
    let runtime = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rustferry");
    let target = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/generated-template-checks");

    for (name, template) in [
        ("starter-check", TemplateKind::Starter),
        ("minimal-check", TemplateKind::Minimal),
        ("counter-check", TemplateKind::Counter),
        ("network-check", TemplateKind::Network),
        ("notifications-check", TemplateKind::Notifications),
        ("widget-check", TemplateKind::Widget),
        ("live-activity-check", TemplateKind::LiveActivity),
        ("kitchen-sink-check", TemplateKind::KitchenSink),
    ] {
        let generated = ProjectGenerator::new(
            parent,
            ProjectRequest {
                name: name.to_owned(),
                identifier: None,
                template,
                platforms: PlatformSelection::Both,
                runtime_dependency: RuntimeDependency::Path(runtime.clone()),
            },
        )
        .generate()
        .unwrap();
        assert!(
            fs::read_to_string(generated.destination.join("Cargo.toml"))
                .unwrap()
                .contains("[workspace]")
        );
        let output = Command::new(env!("CARGO"))
            .arg("check")
            .arg("--all-targets")
            .current_dir(&generated.destination)
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_TERM_COLOR", "never")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "generated {name} failed cargo check:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
