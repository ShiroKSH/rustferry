use serde::{Deserialize, Serialize};

use crate::{AppleDiscovery, AppleDiscoveryOptions, IOS_SIMULATOR_TARGET, discover_apple};

/// Severity and result of one Apple doctor check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorStatus {
    /// Required or optional component is available.
    Passed,
    /// Optional runtime is absent or a non-blocking limitation was found.
    Warning,
    /// A required build-only component is absent or invalid.
    Failed,
}

/// One stable, machine-readable Apple doctor finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppleDoctorCheck {
    /// Stable check identifier.
    pub id: String,
    /// User-facing component name.
    pub name: String,
    /// Check outcome.
    pub status: DoctorStatus,
    /// Found version/path or missing-component explanation.
    pub detail: String,
    /// Concrete remediation when action is useful.
    pub fix: Option<String>,
}

/// Apple doctor inputs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppleDoctorOptions {
    /// Read-only discovery configuration.
    pub discovery: AppleDiscoveryOptions,
}

/// Complete Apple doctor report. Generating it never installs or changes tools.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppleDoctorReport {
    /// Stable report schema version.
    pub schema_version: u32,
    /// Whether every component required for a build-only simulator artifact is present.
    pub ready_for_simulator_build: bool,
    /// Whether a usable Simulator runtime is present for later install/run commands.
    pub ready_for_simulator_run: bool,
    /// Ordered checks.
    pub checks: Vec<AppleDoctorCheck>,
    /// Raw inventory, absent only when discovery itself could not start.
    pub discovery: Option<AppleDiscovery>,
}

/// Inspect every iOS Simulator build prerequisite without modifying the system.
#[allow(clippy::too_many_lines)]
pub fn doctor_apple(options: &AppleDoctorOptions) -> AppleDoctorReport {
    let discovery = match discover_apple(&options.discovery) {
        Ok(discovery) => discovery,
        Err(error) => {
            return AppleDoctorReport {
                schema_version: 1,
                ready_for_simulator_build: false,
                ready_for_simulator_run: false,
                checks: vec![fail(
                    "discovery",
                    "Apple toolchain discovery",
                    error.to_string(),
                    "Use an existing project directory and rerun `cargo ferry doctor`.",
                )],
                discovery: None,
            };
        }
    };

    let mut checks = Vec::new();
    if discovery.host_os == "macos" {
        checks.push(pass(
            "host",
            "Build host",
            format!("macOS ({})", discovery.host_arch),
        ));
    } else {
        checks.push(fail(
            "host",
            "Build host",
            discovery.host_os.clone(),
            "Build iOS applications on macOS with full Xcode installed.",
        ));
    }

    match (&discovery.developer_dir, &discovery.xcode_version) {
        (Some(path), Some(version))
            if path
                .join("Platforms/iPhoneSimulator.platform/Developer/SDKs")
                .is_dir() =>
        {
            checks.push(pass(
                "xcode",
                "Full Xcode",
                format!("{} ({path})", version.replace('\n', ", ")),
            ));
        }
        (path, version) => checks.push(fail(
            "xcode",
            "Full Xcode",
            format!("developer directory: {path:?}; version: {version:?}"),
            "Install Xcode from Apple, select it with xcode-select, then rerun `cargo ferry doctor`.",
        )),
    }

    executable_check(
        &mut checks,
        "xcodebuild",
        "xcodebuild",
        discovery.host_tools.xcodebuild.as_ref(),
        "Install full Xcode and select its developer directory.",
    );
    executable_check(
        &mut checks,
        "xcrun",
        "xcrun",
        discovery.host_tools.xcrun.as_ref(),
        "Install full Xcode and select its developer directory.",
    );
    executable_check(
        &mut checks,
        "plutil",
        "plutil",
        discovery.host_tools.plutil.as_ref(),
        "Restore the macOS command-line tools or reinstall Xcode.",
    );
    executable_check(
        &mut checks,
        "cargo",
        "Cargo",
        discovery.host_tools.cargo.as_ref(),
        "Install Rust with rustup.",
    );
    executable_check(
        &mut checks,
        "rustup",
        "rustup",
        discovery.host_tools.rustup.as_ref(),
        "Install rustup so iOS Rust targets can be managed.",
    );

    if let Some(sdk) = &discovery.simulator_sdk {
        checks.push(pass(
            "iphonesimulator-sdk",
            "iPhone Simulator SDK",
            format!("{} ({})", sdk.version, sdk.path),
        ));
    } else {
        checks.push(fail(
            "iphonesimulator-sdk",
            "iPhone Simulator SDK",
            "xcrun did not return an installed SDK".to_owned(),
            "Open Xcode Settings > Platforms and install an iOS platform SDK.",
        ));
    }

    if discovery
        .installed_rust_targets
        .iter()
        .any(|target| target == IOS_SIMULATOR_TARGET)
    {
        checks.push(pass(
            "rust-target-ios-simulator",
            format!("Rust target {IOS_SIMULATOR_TARGET}"),
            "installed".to_owned(),
        ));
    } else {
        checks.push(fail(
            "rust-target-ios-simulator",
            format!("Rust target {IOS_SIMULATOR_TARGET}"),
            "not installed".to_owned(),
            format!("Run `rustup target add {IOS_SIMULATOR_TARGET}`."),
        ));
    }

    let available_runtimes = discovery
        .simulator_runtimes
        .iter()
        .filter(|runtime| runtime.available)
        .collect::<Vec<_>>();
    let ready_for_simulator_run = !available_runtimes.is_empty();
    if ready_for_simulator_run {
        checks.push(pass(
            "simulator-runtime",
            "Simulator runtime",
            available_runtimes
                .iter()
                .map(|runtime| format!("{} {}", runtime.name, runtime.version))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    } else {
        checks.push(warn(
            "simulator-runtime",
            "Simulator runtime",
            "no available runtime; build-only remains supported".to_owned(),
            Some(
                "Install a runtime in Xcode Settings > Platforms only for install/run validation."
                    .to_owned(),
            ),
        ));
    }

    if discovery.host_arch != "aarch64" {
        checks.push(warn(
            "host-architecture",
            "Simulator host architecture",
            format!(
                "{} host; cargo-ferry currently emits an arm64 simulator executable",
                discovery.host_arch
            ),
            Some(
                "Build-only can cross-compile, but run validation requires an Apple Silicon Mac."
                    .to_owned(),
            ),
        ));
    }

    let ready_for_simulator_build = checks
        .iter()
        .all(|check| check.status != DoctorStatus::Failed);
    AppleDoctorReport {
        schema_version: 1,
        ready_for_simulator_build,
        ready_for_simulator_run,
        checks,
        discovery: Some(discovery),
    }
}

fn executable_check(
    checks: &mut Vec<AppleDoctorCheck>,
    id: &str,
    name: &str,
    path: Option<&camino::Utf8PathBuf>,
    fix: &str,
) {
    if let Some(path) = path {
        checks.push(pass(id, name, path.to_string()));
    } else {
        checks.push(fail(id, name, "not found".to_owned(), fix.to_owned()));
    }
}

fn pass(
    id: impl Into<String>,
    name: impl Into<String>,
    detail: impl Into<String>,
) -> AppleDoctorCheck {
    AppleDoctorCheck {
        id: id.into(),
        name: name.into(),
        status: DoctorStatus::Passed,
        detail: detail.into(),
        fix: None,
    }
}

fn warn(
    id: impl Into<String>,
    name: impl Into<String>,
    detail: impl Into<String>,
    fix: Option<String>,
) -> AppleDoctorCheck {
    AppleDoctorCheck {
        id: id.into(),
        name: name.into(),
        status: DoctorStatus::Warning,
        detail: detail.into(),
        fix,
    }
}

fn fail(
    id: impl Into<String>,
    name: impl Into<String>,
    detail: impl Into<String>,
    fix: impl Into<String>,
) -> AppleDoctorCheck {
    AppleDoctorCheck {
        id: id.into(),
        name: name.into(),
        status: DoctorStatus::Failed,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}
