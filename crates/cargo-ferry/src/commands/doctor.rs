use rustferry_android::{DoctorOptions as AndroidDoctorOptions, doctor_android};
use rustferry_apple::{AppleDoctorOptions, doctor_apple};
use serde::Serialize;

use crate::cli::DoctorArgs;
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorResult {
    schema_version: u32,
    ready_for_android_build: bool,
    ready_for_ios_simulator_build: bool,
    ready_for_ios_simulator_run: bool,
    include_optional_tools: bool,
    android: rustferry_android::DoctorReport,
    ios: rustferry_apple::AppleDoctorReport,
}

pub fn run(arguments: &DoctorArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let android_config = project_android_config().unwrap_or_default();
    let android = doctor_android(&AndroidDoctorOptions {
        android: android_config,
        ..AndroidDoctorOptions::default()
    });
    let ios = doctor_apple(&AppleDoctorOptions::default());
    let result = DoctorResult {
        schema_version: 1,
        ready_for_android_build: android.ready_for_build,
        ready_for_ios_simulator_build: ios.ready_for_simulator_build,
        ready_for_ios_simulator_run: ios.ready_for_simulator_run,
        include_optional_tools: arguments.all,
        android,
        ios,
    };

    if arguments.fix && !dry_run {
        let fixes = fixes(&result);
        if !fixes.is_empty() {
            return Err(CliError::Unsupported {
                message: "doctor --fix will not change this machine without an interactive confirmation flow"
                    .to_owned(),
                help: format!(
                    "Run `cargo ferry doctor --fix --dry-run` to inspect changes, or apply the listed actions yourself:\n{}",
                    fixes.join("\n")
                ),
            });
        }
    }

    reporter.success(
        "doctor",
        &result,
        || human_report(&result, arguments.fix && dry_run),
        &[],
    );
    Ok(())
}

fn project_android_config() -> Option<rustferry_core::AndroidConfig> {
    let root = find_project_root(None).ok()?;
    rustferry_core::FerryConfig::load(&root.join("ferry.toml"))
        .ok()
        .map(|config| config.android)
}

fn fixes(result: &DoctorResult) -> Vec<String> {
    let mut values = result
        .android
        .checks
        .iter()
        .filter_map(|check| check.fix.clone())
        .chain(
            result
                .ios
                .checks
                .iter()
                .filter_map(|check| check.fix.clone()),
        )
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn human_report(result: &DoctorResult, show_fixes: bool) -> String {
    let mut lines = vec!["Android".to_owned()];
    for check in &result.android.checks {
        let marker = match check.status {
            rustferry_android::DoctorStatus::Passed => "✓",
            rustferry_android::DoctorStatus::Warning => "•",
            rustferry_android::DoctorStatus::Failed => "✗",
        };
        lines.push(format!("  {marker} {}: {}", check.name, check.detail));
        if show_fixes && let Some(fix) = &check.fix {
            lines.push(format!("      Fix: {fix}"));
        }
    }
    lines.push(String::new());
    lines.push("iOS".to_owned());
    for check in &result.ios.checks {
        let marker = match check.status {
            rustferry_apple::DoctorStatus::Passed => "✓",
            rustferry_apple::DoctorStatus::Warning => "•",
            rustferry_apple::DoctorStatus::Failed => "✗",
        };
        lines.push(format!("  {marker} {}: {}", check.name, check.detail));
        if show_fixes && let Some(fix) = &check.fix {
            lines.push(format!("      Fix: {fix}"));
        }
    }
    lines.extend([
        String::new(),
        format!(
            "Android build: {}",
            readiness(result.ready_for_android_build)
        ),
        format!(
            "iOS Simulator build: {}",
            readiness(result.ready_for_ios_simulator_build)
        ),
        format!(
            "iOS Simulator install/run: {}",
            readiness(result.ready_for_ios_simulator_run)
        ),
    ]);
    lines.join("\n")
}

const fn readiness(ready: bool) -> &'static str {
    if ready { "ready" } else { "blocked" }
}
