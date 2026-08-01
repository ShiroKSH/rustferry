use std::time::Duration;

use camino::Utf8PathBuf;
use rustferry_core::AndroidConfig;
use serde::{Deserialize, Serialize};

use crate::{
    AndroidDiscovery, CommandSpec, DiscoveryOptions, command::run_probe_command, discover_android,
    signing::default_debug_signing_paths,
};

const DOCTOR_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Severity and result of one doctor check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorStatus {
    /// Required or optional component is available.
    Passed,
    /// Optional component is absent or setup will happen lazily.
    Warning,
    /// Required build component is absent or invalid.
    Failed,
}

/// One stable, machine-readable Android doctor finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoctorCheck {
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

/// Android doctor inputs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DoctorOptions {
    /// Read-only discovery configuration.
    pub discovery: DiscoveryOptions,
    /// Android settings whose target and ABIs should be checked.
    pub android: AndroidConfig,
    /// Override for the machine-local cargo-ferry configuration directory.
    pub config_dir: Option<Utf8PathBuf>,
}

/// Complete Android doctor report. Generating it never installs or changes tools.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Stable report schema version.
    pub schema_version: u32,
    /// Whether every required direct-build check passed.
    pub ready_for_build: bool,
    /// Ordered checks.
    pub checks: Vec<DoctorCheck>,
    /// Raw discovery inventory used to make the report.
    pub discovery: AndroidDiscovery,
}

/// Inspect the host for every direct Android pipeline prerequisite.
pub fn doctor_android(options: &DoctorOptions) -> DoctorReport {
    let discovery = discover_android(&options.discovery);
    let mut checks = Vec::new();

    executable_check(
        &mut checks,
        "rustc",
        "Rust compiler",
        discovery.host_tools.rustc.as_ref(),
        true,
        "Install Rust with rustup.",
    );
    executable_check(
        &mut checks,
        "cargo",
        "Cargo",
        discovery.host_tools.cargo.as_ref(),
        true,
        "Install Rust with rustup.",
    );
    executable_check(
        &mut checks,
        "rustup",
        "rustup",
        discovery.host_tools.rustup.as_ref(),
        true,
        "Install rustup so Android Rust targets can be managed.",
    );
    rust_target_checks(&mut checks, &discovery, &options.android);

    let sdk_root = discovery
        .sdk_roots_searched
        .iter()
        .find(|root| root.is_dir());
    if let Some(root) = sdk_root {
        checks.push(pass("android-sdk", "Android SDK", root.to_string()));
        let platform_tools = root.join("platform-tools");
        if platform_tools.is_dir() {
            checks.push(pass(
                "platform-tools",
                "Android SDK Platform Tools",
                platform_tools.to_string(),
            ));
        } else {
            checks.push(warn(
                "platform-tools",
                "Android SDK Platform Tools",
                "not installed; not required to build",
                Some("Install Platform Tools only for device deployment.".to_owned()),
            ));
        }
    } else {
        checks.push(fail(
            "android-sdk",
            "Android SDK",
            format!("searched {:?}", discovery.sdk_roots_searched),
            "Install the Android SDK or set ANDROID_SDK_ROOT.".to_owned(),
        ));
    }

    let selected_platform = select_doctor_platform(&discovery, &options.android.target_sdk);
    if let Some(platform) = selected_platform {
        checks.push(pass(
            "android-platform",
            "Android platform",
            format!("android-{} ({})", platform.api_level, platform.android_jar),
        ));
    } else {
        checks.push(fail(
            "android-platform",
            "Android platform",
            format!(
                "requested `{}`; searched {:?}",
                options.android.target_sdk, discovery.sdk_roots_searched
            ),
            format!(
                "Install `platforms;android-{}` with sdkmanager.",
                options.android.target_sdk.trim_start_matches("android-")
            ),
        ));
    }

    if let Some(tools) = discovery.build_tools.iter().rev().find(|tools| {
        tools.is_complete()
            && selected_platform.is_none_or(|platform| tools.sdk_root == platform.sdk_root)
    }) {
        checks.push(pass(
            "build-tools",
            "Android SDK Build Tools",
            format!("{} ({})", tools.version, tools.directory),
        ));
        for (id, name, path) in [
            ("aapt2", "aapt2", tools.aapt2.as_ref()),
            ("d8", "d8", tools.d8.as_ref()),
            ("zipalign", "zipalign", tools.zipalign.as_ref()),
            ("apksigner", "apksigner", tools.apksigner.as_ref()),
        ] {
            executable_check(
                &mut checks,
                id,
                name,
                path,
                true,
                "Install a complete Android SDK Build Tools revision.",
            );
        }
    } else {
        checks.push(fail(
            "build-tools",
            "Android SDK Build Tools",
            format!("searched {:?}", discovery.sdk_roots_searched),
            "Install `build-tools;<version>` with sdkmanager.".to_owned(),
        ));
    }

    if let Some(ndk) = discovery
        .ndks
        .iter()
        .rev()
        .find(|ndk| ndk.llvm_prebuilt.is_some())
    {
        checks.push(pass(
            "ndk",
            "Android NDK",
            format!("{} ({})", ndk.version, ndk.root),
        ));
        for abi in &options.android.abis {
            let id = format!("ndk-linker-{}", abi.apk_directory());
            let name = format!("NDK linker ({})", abi.rust_target());
            let linker = ndk.linker_for(*abi, options.android.min_sdk);
            match linker {
                Ok(path) => checks.push(pass(&id, &name, path.to_string())),
                Err(error) => checks.push(fail(
                    &id,
                    &name,
                    error.to_string(),
                    "Install a complete Android NDK and rerun `cargo ferry doctor`.".to_owned(),
                )),
            }
        }
        match ndk.llvm_ar() {
            Ok(path) => checks.push(pass("ndk-llvm-ar", "NDK LLVM archiver", path.to_string())),
            Err(error) => checks.push(fail(
                "ndk-llvm-ar",
                "NDK LLVM archiver",
                error.to_string(),
                "Reinstall the selected Android NDK.".to_owned(),
            )),
        }
    } else {
        checks.push(fail(
            "ndk",
            "Android NDK",
            format!("searched {:?}", discovery.ndk_roots_searched),
            "Install `ndk;<version>` with sdkmanager.".to_owned(),
        ));
    }

    executable_check(
        &mut checks,
        "java",
        "Java runtime",
        discovery.host_tools.java.as_ref(),
        true,
        "Install a JDK and set JAVA_HOME.",
    );
    executable_check(
        &mut checks,
        "javac",
        "Java compiler",
        discovery.host_tools.javac.as_ref(),
        true,
        "Install a JDK and set JAVA_HOME; the generated Android bridge requires javac.",
    );
    executable_check(
        &mut checks,
        "keytool",
        "Debug keystore tool",
        discovery.host_tools.keytool.as_ref(),
        true,
        "Install a JDK and set JAVA_HOME.",
    );
    executable_check(
        &mut checks,
        "sdkmanager",
        "Android SDK manager",
        discovery.host_tools.sdkmanager.as_ref(),
        false,
        "Install Android SDK Command-line Tools to manage missing components.",
    );
    executable_check(
        &mut checks,
        "adb",
        "Android Debug Bridge",
        discovery.host_tools.adb.as_ref(),
        false,
        "Install Android SDK Platform Tools only if install/run commands are needed.",
    );
    executable_check(
        &mut checks,
        "emulator",
        "Android emulator",
        discovery.host_tools.emulator.as_ref(),
        false,
        "Install the Android emulator only for runtime validation; builds do not need it.",
    );

    match default_debug_signing_paths(options.config_dir.as_deref()) {
        Ok(paths) if paths.keystore.is_file() && paths.password_file.is_file() => {
            checks.push(pass(
                "debug-keystore",
                "Persistent debug keystore",
                paths.keystore.to_string(),
            ));
        }
        Ok(paths) => checks.push(warn(
            "debug-keystore",
            "Persistent debug keystore",
            format!("not created yet; build will create {}", paths.keystore),
            None,
        )),
        Err(error) => checks.push(fail(
            "debug-keystore",
            "Persistent debug keystore",
            error.to_string(),
            "Set a writable cargo-ferry config directory.".to_owned(),
        )),
    }

    let ready_for_build = checks
        .iter()
        .all(|check| check.status != DoctorStatus::Failed);
    DoctorReport {
        schema_version: 1,
        ready_for_build,
        checks,
        discovery,
    }
}

fn rust_target_checks(
    checks: &mut Vec<DoctorCheck>,
    discovery: &AndroidDiscovery,
    config: &AndroidConfig,
) {
    let installed = discovery
        .host_tools
        .rustup
        .as_ref()
        .and_then(|rustup| probe_output(rustup, ["target", "list", "--installed"]))
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
    for abi in &config.abis {
        let target = abi.rust_target();
        if installed
            .as_deref()
            .is_some_and(|output| output.lines().any(|line| line.trim() == target))
        {
            checks.push(pass(
                format!("rust-target-{}", abi.apk_directory()),
                format!("Rust target {target}"),
                "installed",
            ));
        } else {
            checks.push(fail(
                format!("rust-target-{}", abi.apk_directory()),
                format!("Rust target {target}"),
                "not installed",
                format!("Run `rustup target add {target}`."),
            ));
        }
    }
}

fn executable_check(
    checks: &mut Vec<DoctorCheck>,
    id: &str,
    name: &str,
    path: Option<&Utf8PathBuf>,
    required: bool,
    fix: &str,
) {
    if let Some(path) = path {
        let detail = probe_version(path).unwrap_or_else(|| path.to_string());
        checks.push(pass(id, name, detail));
    } else if required {
        checks.push(fail(id, name, "not found", fix.to_owned()));
    } else {
        checks.push(warn(id, name, "not found", Some(fix.to_owned())));
    }
}

fn probe_version(path: &Utf8PathBuf) -> Option<String> {
    let output = probe_output(path, ["--version"])?;
    let text = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    let version = String::from_utf8_lossy(text)
        .lines()
        .next()?
        .trim()
        .to_owned();
    (!version.is_empty()).then_some(version)
}

fn probe_output<const N: usize>(
    path: &Utf8PathBuf,
    arguments: [&str; N],
) -> Option<crate::CommandOutput> {
    let current_dir = path.parent().unwrap_or_else(|| camino::Utf8Path::new("."));
    let mut command = CommandSpec::new(
        format!("probe {}", path.file_name().unwrap_or("tool")),
        path,
        current_dir,
    );
    command.args = arguments.into_iter().map(ToOwned::to_owned).collect();
    command.timeout = DOCTOR_PROBE_TIMEOUT;
    run_probe_command(&command).ok()
}

fn select_doctor_platform<'a>(
    discovery: &'a AndroidDiscovery,
    requested: &str,
) -> Option<&'a crate::AndroidPlatform> {
    if requested == "installed" {
        discovery
            .platforms
            .iter()
            .max_by_key(|platform| platform.api_level)
    } else {
        let api = requested
            .trim_start_matches("android-")
            .parse::<u32>()
            .ok()?;
        discovery
            .platforms
            .iter()
            .find(|platform| platform.api_level == api)
    }
}

fn pass(id: impl Into<String>, name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
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
) -> DoctorCheck {
    DoctorCheck {
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
) -> DoctorCheck {
    DoctorCheck {
        id: id.into(),
        name: name.into(),
        status: DoctorStatus::Failed,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_device_tools_do_not_block_build_readiness() {
        let checks = [
            pass("required", "Required", "present"),
            warn("adb", "ADB", "not found", None),
        ];
        assert!(
            checks
                .iter()
                .all(|check| check.status != DoctorStatus::Failed)
        );
    }

    #[test]
    fn mandatory_javac_blocks_build_readiness() {
        let mut checks = Vec::new();
        executable_check(
            &mut checks,
            "javac",
            "Java compiler",
            None,
            true,
            "Install a JDK.",
        );
        assert_eq!(checks[0].status, DoctorStatus::Failed);
    }
}
