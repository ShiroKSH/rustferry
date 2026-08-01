use std::ffi::OsString;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use super::{
    ArtifactKind, CommandExecutor, CommandOutput, DeploymentError, DeploymentResult, Device,
    DeviceKind, DeviceState, MAX_COREDEVICE_JSON_BYTES, ToolCommand, ValidatedArtifact,
    read_bounded_tool_file,
};

/// Explicit Android installation behavior; destructive choices default off.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AndroidInstallOptions {
    /// Replace an already installed application while retaining data.
    pub reinstall: bool,
    /// Permit version-code downgrade.
    pub allow_downgrade: bool,
    /// Grant runtime permissions declared by the APK.
    pub grant_permissions: bool,
    /// Clear this application's data after a successful install.
    pub clear_data: bool,
}

/// Explicit Apple installation behavior.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IosInstallOptions {
    /// Boot a selected shutdown Simulator and wait for boot completion.
    pub boot_on_demand: bool,
}

/// Complete installation request for one already validated artifact and selected device.
#[derive(Clone, Debug)]
pub struct InstallRequest {
    /// Explicit selected device. Call [`select_device`] before constructing in non-interactive use.
    pub device: Device,
    /// Independently validated, structurally rechecked build output.
    pub artifact: ValidatedArtifact,
    /// Android-only install flags.
    pub android: AndroidInstallOptions,
    /// Apple-only install flags.
    pub ios: IosInstallOptions,
    /// Overall platform-tool deadline.
    pub timeout: Duration,
}

impl InstallRequest {
    /// Create a conservative install request with no destructive flags.
    pub fn new(device: Device, artifact: ValidatedArtifact) -> Self {
        Self {
            device,
            artifact,
            android: AndroidInstallOptions::default(),
            ios: IosInstallOptions::default(),
            timeout: Duration::from_mins(2),
        }
    }
}

/// Evidence returned only after the official platform tool reports installation success.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstallOutcome {
    /// Stable selected device ID.
    pub device_id: String,
    /// Installed package/bundle identifier.
    pub application_id: String,
    /// Canonical artifact path.
    pub artifact: Utf8PathBuf,
    /// Whether replace/reinstall semantics were requested or native to the platform command.
    pub replaced: bool,
    /// Whether explicit Android data clearing also succeeded.
    pub data_cleared: bool,
}

/// Deterministically select one compatible device for automation/JSON callers.
///
/// # Errors
///
/// Returns an error for an unknown/wrong-kind/unavailable requested device, no compatible
/// devices, or multiple compatible devices without an explicit stable ID.
pub fn select_device(
    devices: &[Device],
    kind: DeviceKind,
    requested_id: Option<&str>,
    operation: &'static str,
) -> DeploymentResult<Device> {
    if let Some(id) = requested_id {
        let device = devices
            .iter()
            .find(|device| device.id == id)
            .ok_or_else(|| DeploymentError::DeviceNotFound { id: id.to_owned() })?;
        if device.kind != kind {
            return Err(DeploymentError::DeviceKindMismatch {
                id: id.to_owned(),
                expected: kind,
                actual: device.kind,
            });
        }
        validate_device_available(device, operation)?;
        return Ok(device.clone());
    }
    let compatible = devices
        .iter()
        .filter(|device| device.kind == kind && device.capabilities.install)
        .collect::<Vec<_>>();
    match compatible.as_slice() {
        [device] => Ok((*device).clone()),
        [] => Err(DeploymentError::DeviceUnavailable {
            id: "<none>".to_owned(),
            state: DeviceState::Unavailable,
            operation,
            help: format!("Connect or boot one usable {kind:?} device, then retry."),
        }),
        _ => Err(DeploymentError::DeviceSelectionRequired {
            device_ids: compatible.iter().map(|device| device.id.clone()).collect(),
        }),
    }
}

/// Artifact installation through ADB, simctl, or devicectl.
pub struct Installer<E> {
    executor: E,
    current_directory: Utf8PathBuf,
    adb: Utf8PathBuf,
    xcrun: Utf8PathBuf,
}

impl<E: CommandExecutor> Installer<E> {
    /// Create an installer using tools resolved from PATH.
    pub fn new(executor: E, current_directory: impl Into<Utf8PathBuf>) -> Self {
        Self {
            executor,
            current_directory: current_directory.into(),
            adb: Utf8PathBuf::from("adb"),
            xcrun: Utf8PathBuf::from("xcrun"),
        }
    }

    /// Override executable paths for configured SDK/Xcode installations or tests.
    #[must_use]
    pub fn with_tools(
        mut self,
        adb: impl Into<Utf8PathBuf>,
        xcrun: impl Into<Utf8PathBuf>,
    ) -> Self {
        self.adb = adb.into();
        self.xcrun = xcrun.into();
        self
    }

    /// Install one validated artifact with explicit device and safe defaults.
    ///
    /// # Errors
    ///
    /// Returns an error for a device/artifact mismatch, unavailable device, platform-tool
    /// failure, timeout, malformed structured result, or invalid physical signing evidence.
    pub fn install(&self, request: &InstallRequest) -> DeploymentResult<InstallOutcome> {
        validate_device_available(&request.device, "install application")?;
        request.artifact.recheck_integrity()?;
        match (request.device.kind, request.artifact.kind) {
            (
                DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator,
                ArtifactKind::AndroidApk,
            ) => self.install_android(request),
            (DeviceKind::IosSimulator, ArtifactKind::IosSimulatorApp) => {
                self.install_simulator(request)
            }
            (DeviceKind::IosPhysical, ArtifactKind::IosPhysicalApp) => {
                self.install_physical_ios(request)
            }
            (_, artifact_kind) => Err(DeploymentError::PlatformMismatch {
                path: request.artifact.path.clone(),
                artifact_platform: artifact_kind.label(),
                requested_platform: device_label(request.device.kind),
            }),
        }
    }

    fn install_android(&self, request: &InstallRequest) -> DeploymentResult<InstallOutcome> {
        let mut arguments = vec![
            OsString::from("-s"),
            OsString::from(&request.device.id),
            OsString::from("install"),
        ];
        if request.android.reinstall {
            arguments.push(OsString::from("-r"));
        }
        if request.android.allow_downgrade {
            arguments.push(OsString::from("-d"));
        }
        if request.android.grant_permissions {
            arguments.push(OsString::from("-g"));
        }
        arguments.push(OsString::from(request.artifact.path.as_str()));
        request.artifact.recheck_integrity()?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "install Android application",
            )
            .args(arguments)
            .timeout(request.timeout),
        )?;
        ensure_install_success(&self.adb, "install Android application", &output)?;

        let mut data_cleared = false;
        if request.android.clear_data {
            let output = self.executor.execute(
                &ToolCommand::new(
                    &self.adb,
                    &self.current_directory,
                    "clear Android application data",
                )
                .args([
                    OsString::from("-s"),
                    OsString::from(&request.device.id),
                    OsString::from("shell"),
                    OsString::from("pm"),
                    OsString::from("clear"),
                    OsString::from(&request.artifact.application_id),
                ])
                .timeout(request.timeout),
            )?;
            ensure_install_success(&self.adb, "clear Android application data", &output)?;
            data_cleared = true;
        }
        Ok(outcome(request, request.android.reinstall, data_cleared))
    }

    fn install_simulator(&self, request: &InstallRequest) -> DeploymentResult<InstallOutcome> {
        if request.device.state == DeviceState::Shutdown {
            if !request.ios.boot_on_demand {
                return Err(DeploymentError::DeviceUnavailable {
                    id: request.device.id.clone(),
                    state: request.device.state,
                    operation: "install iOS Simulator application",
                    help: "Boot the selected Simulator or pass the explicit boot-on-demand option."
                        .to_owned(),
                });
            }
            let boot = self.executor.execute(
                &ToolCommand::new(&self.xcrun, &self.current_directory, "boot iOS Simulator")
                    .args(["simctl", "boot", &request.device.id])
                    .timeout(request.timeout),
            )?;
            // `simctl boot` reports an already-booted device as an error on some Xcode versions.
            if !boot.status.success()
                && !combined_text(&boot)
                    .to_ascii_lowercase()
                    .contains("current state: booted")
            {
                return Err(command_failure(
                    &self.xcrun,
                    "boot iOS Simulator",
                    &boot,
                    "simulator_boot_failed",
                    "Verify the Simulator runtime is installed and the device is available.",
                ));
            }
            let wait = self.executor.execute(
                &ToolCommand::new(
                    &self.xcrun,
                    &self.current_directory,
                    "wait for iOS Simulator boot",
                )
                .args(["simctl", "bootstatus", &request.device.id, "-b"])
                .timeout(request.timeout),
            )?;
            ensure_install_success(&self.xcrun, "wait for iOS Simulator boot", &wait)?;
        }
        request.artifact.recheck_integrity()?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "install iOS Simulator application",
            )
            .args([
                OsString::from("simctl"),
                OsString::from("install"),
                OsString::from(&request.device.id),
                OsString::from(request.artifact.path.as_str()),
            ])
            .timeout(request.timeout),
        )?;
        ensure_install_success(&self.xcrun, "install iOS Simulator application", &output)?;
        Ok(outcome(request, true, false))
    }

    fn install_physical_ios(&self, request: &InstallRequest) -> DeploymentResult<InstallOutcome> {
        if !request.artifact.signed || request.artifact.team_id.is_none() {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "unsigned or ad-hoc artifacts cannot be installed on physical iOS devices"
                    .to_owned(),
            });
        }
        self.recheck_physical_signature(request)?;
        let json = tempfile::NamedTempFile::new().map_err(|source| DeploymentError::Io {
            action: "create CoreDevice install result",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
        let json_path = Utf8PathBuf::from_path_buf(json.path().to_owned()).map_err(|path| {
            DeploymentError::InvalidToolOutput {
                tool: "devicectl",
                operation: "install physical iOS application",
                message: format!("temporary result path is not UTF-8: {}", path.display()),
            }
        })?;
        request.artifact.recheck_integrity()?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "install physical iOS application",
            )
            .args([
                OsString::from("devicectl"),
                OsString::from("device"),
                OsString::from("install"),
                OsString::from("app"),
                OsString::from("--device"),
                OsString::from(&request.device.id),
                OsString::from("--timeout"),
                OsString::from(request.timeout.as_secs().to_string()),
                OsString::from("--json-output"),
                OsString::from(json_path.as_str()),
                OsString::from(request.artifact.path.as_str()),
            ])
            .timeout(request.timeout + Duration::from_secs(2)),
        )?;
        ensure_install_success(&self.xcrun, "install physical iOS application", &output)?;
        validate_devicectl_result(&json_path, "install physical iOS application")?;
        Ok(outcome(request, true, false))
    }

    fn recheck_physical_signature(&self, request: &InstallRequest) -> DeploymentResult<()> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "recheck physical iOS signature before install",
            )
            .args([
                OsString::from("codesign"),
                OsString::from("--verify"),
                OsString::from("--deep"),
                OsString::from("--strict"),
                OsString::from("--verbose=4"),
                OsString::from(request.artifact.path.as_str()),
            ])
            .timeout(Duration::from_secs(30)),
        )?;
        if !output.status.success() {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message:
                    "strict recursive signature verification failed immediately before install"
                        .to_owned(),
            });
        }
        let display = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "recheck physical iOS signing team before install",
            )
            .args([
                OsString::from("codesign"),
                OsString::from("--display"),
                OsString::from("--verbose=4"),
                OsString::from(request.artifact.path.as_str()),
            ])
            .timeout(Duration::from_secs(30)),
        )?;
        if !display.status.success() {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "code-signing metadata could not be read immediately before install"
                    .to_owned(),
            });
        }
        let metadata = combined_text(&display);
        if metadata
            .lines()
            .any(|line| line.trim() == "Signature=adhoc")
        {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "physical iOS application is ad-hoc signed".to_owned(),
            });
        }
        let expected_team = request.artifact.team_id.as_deref().unwrap_or_default();
        let expected_team_line = format!("TeamIdentifier={expected_team}");
        if !metadata
            .lines()
            .any(|line| line.trim() == expected_team_line)
        {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "physical iOS signature team changed after artifact validation".to_owned(),
            });
        }
        if !request
            .artifact
            .path
            .join("embedded.mobileprovision")
            .is_file()
        {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "embedded provisioning profile is missing immediately before install"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_device_available(device: &Device, operation: &'static str) -> DeploymentResult<()> {
    if !device.capabilities.install
        || matches!(
            device.state,
            DeviceState::Offline
                | DeviceState::Unauthorized
                | DeviceState::Unavailable
                | DeviceState::Disconnected
                | DeviceState::Unknown
        )
    {
        let help = match device.state {
            DeviceState::Unauthorized => {
                "Unlock and trust this computer on the device, then retry."
            }
            DeviceState::Offline | DeviceState::Disconnected => {
                "Reconnect the device transport, then refresh devices."
            }
            _ => "Refresh devices and select one that supports installation.",
        };
        return Err(DeploymentError::DeviceUnavailable {
            id: device.id.clone(),
            state: device.state,
            operation,
            help: help.to_owned(),
        });
    }
    Ok(())
}

fn validate_devicectl_result(path: &Utf8Path, operation: &'static str) -> DeploymentResult<()> {
    let bytes = read_bounded_tool_file(
        path,
        "devicectl",
        operation,
        "read CoreDevice result",
        MAX_COREDEVICE_JSON_BYTES,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| DeploymentError::InvalidToolOutput {
            tool: "devicectl",
            operation,
            message: error.to_string(),
        })?;
    if value
        .pointer("/info/outcome")
        .and_then(|value| value.as_str())
        != Some("success")
    {
        return Err(DeploymentError::InvalidToolOutput {
            tool: "devicectl",
            operation,
            message: "versioned result did not report `info.outcome=success`".to_owned(),
        });
    }
    Ok(())
}

fn ensure_install_success(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let message = combined_text(output);
    let lower = message.to_ascii_lowercase();
    let (category, help) = if lower.contains("install_failed_update_incompatible")
        || lower.contains("signature")
    {
        (
            "signature_mismatch",
            "The installed app uses a different signature. Explicitly uninstall it only if losing its app data is acceptable.",
        )
    } else if lower.contains("insufficient_storage") || lower.contains("not enough") {
        ("insufficient_storage", "Free device storage, then retry.")
    } else if lower.contains("no matching abis") || lower.contains("incompatible architecture") {
        (
            "incompatible_architecture",
            "Build an artifact containing an architecture supported by the selected device.",
        )
    } else if lower.contains("older sdk") || lower.contains("min sdk") {
        (
            "minimum_os_unsupported",
            "Select a newer device or lower the configured minimum OS version and rebuild.",
        )
    } else if lower.contains("unauthorized") || lower.contains("not trusted") {
        (
            "device_unauthorized",
            "Unlock the device and trust this computer, then retry.",
        )
    } else if lower.contains("developer mode") {
        (
            "developer_mode_disabled",
            "Enable Developer Mode on the physical iOS device, then retry.",
        )
    } else {
        (
            "install_failed",
            "Inspect the bounded platform diagnostic and run the platform doctor.",
        )
    };
    Err(command_failure(tool, operation, output, category, help))
}

fn command_failure(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
    category: &'static str,
    help: &str,
) -> DeploymentError {
    let mut message = combined_text(output).trim().replace(['\r', '\n'], " ");
    if message.len() > 2_048 {
        message.truncate(2_048);
        message.push('…');
    }
    if message.is_empty() {
        "tool returned failure without diagnostics".clone_into(&mut message);
    }
    DeploymentError::CommandFailed {
        tool: tool.to_string(),
        operation,
        status: output.status.code(),
        message,
        category,
        help: help.to_owned(),
    }
}

fn combined_text(output: &CommandOutput) -> String {
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.stdout.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    text
}

fn outcome(request: &InstallRequest, replaced: bool, data_cleared: bool) -> InstallOutcome {
    InstallOutcome {
        device_id: request.device.id.clone(),
        application_id: request.artifact.application_id.clone(),
        artifact: request.artifact.path.clone(),
        replaced,
        data_cleared,
    }
}

const fn device_label(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator => "android",
        DeviceKind::IosSimulator => "ios-simulator",
        DeviceKind::IosPhysical => "ios-device",
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    struct RecordingExecutor {
        commands: RefCell<Vec<ToolCommand>>,
    }

    impl CommandExecutor for RecordingExecutor {
        fn execute(&self, command: &ToolCommand) -> DeploymentResult<CommandOutput> {
            self.commands.borrow_mut().push(command.clone());
            Ok(CommandOutput {
                status: std::process::ExitStatus::from_raw(0),
                stdout: b"Success\n".to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            })
        }
    }

    struct MutatingSimulatorExecutor {
        commands: RefCell<Vec<ToolCommand>>,
        executable: Utf8PathBuf,
    }

    impl CommandExecutor for MutatingSimulatorExecutor {
        fn execute(&self, command: &ToolCommand) -> DeploymentResult<CommandOutput> {
            self.commands.borrow_mut().push(command.clone());
            if command.operation == "wait for iOS Simulator boot" {
                fs::write(&self.executable, b"replaced executable")
                    .expect("replace executable during boot");
            }
            Ok(CommandOutput {
                status: std::process::ExitStatus::from_raw(0),
                stdout: b"Success\n".to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            })
        }
    }

    fn android_device() -> Device {
        Device {
            id: "serial-1".to_owned(),
            name: "Phone".to_owned(),
            platform: super::super::DevicePlatform::Android,
            kind: DeviceKind::AndroidPhysical,
            state: DeviceState::Online,
            os_version: None,
            architecture: None,
            transport: Some("usb".to_owned()),
            paired: true,
            trusted: true,
            capabilities: super::super::DeviceCapabilities {
                build: true,
                install: true,
                launch: true,
                logs: true,
            },
            details: BTreeMap::default(),
        }
    }

    #[test]
    fn android_install_always_uses_serial_and_never_uninstalls_implicitly() {
        let mut apk = tempfile::Builder::new()
            .suffix(".apk")
            .tempfile()
            .expect("APK");
        apk.write_all(b"PK\x03\x04payload").expect("write");
        let path = Utf8PathBuf::from_path_buf(apk.path().to_owned()).expect("UTF-8");
        let digest =
            rustferry_core::digest_artifact(&path, rustferry_core::ArtifactDigestKind::AndroidApk)
                .expect("artifact digest");
        let artifact = super::super::inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "example.Activity",
            &digest,
            true,
            None,
        )
        .expect("artifact");
        let executor = RecordingExecutor {
            commands: RefCell::new(Vec::new()),
        };
        let installer = Installer::new(executor, ".");
        let mut request = InstallRequest::new(android_device(), artifact);
        request.android.reinstall = true;
        installer.install(&request).expect("install");
        let command = installer.executor.commands.borrow()[0].clone();
        let arguments = command
            .arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(&arguments[..4], ["-s", "serial-1", "install", "-r"]);
        assert!(!arguments.iter().any(|argument| argument == "uninstall"));
    }

    #[test]
    fn multiple_devices_require_explicit_selection() {
        let devices = vec![
            android_device(),
            Device {
                id: "serial-2".to_owned(),
                ..android_device()
            },
        ];
        let error = select_device(&devices, DeviceKind::AndroidPhysical, None, "install")
            .expect_err("selection");
        assert_eq!(error.code(), "device_selection_required");
    }

    #[test]
    fn simulator_install_rechecks_artifact_after_boot_wait() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let app = Utf8PathBuf::from_path_buf(directory.path().join("Example.app"))
            .expect("UTF-8 app path");
        fs::create_dir(&app).expect("create app bundle");
        fs::write(app.join("Info.plist"), b"plist").expect("write Info.plist");
        let executable = app.join("Example");
        fs::write(&executable, b"validated executable").expect("write executable");
        let digest = rustferry_core::digest_artifact(
            &app,
            rustferry_core::ArtifactDigestKind::IosSimulatorApp,
        )
        .expect("artifact digest");
        let artifact = super::super::inspect_artifact(
            &app,
            ArtifactKind::IosSimulatorApp,
            "com.example.app",
            "Example",
            &digest,
            true,
            None,
        )
        .expect("artifact");
        let device = Device {
            id: "simulator-1".to_owned(),
            name: "iPhone".to_owned(),
            platform: super::super::DevicePlatform::Ios,
            kind: DeviceKind::IosSimulator,
            state: DeviceState::Shutdown,
            os_version: None,
            architecture: None,
            transport: Some("coresimulator".to_owned()),
            paired: true,
            trusted: true,
            capabilities: super::super::DeviceCapabilities {
                build: true,
                install: true,
                launch: true,
                logs: true,
            },
            details: BTreeMap::default(),
        };
        let executor = MutatingSimulatorExecutor {
            commands: RefCell::new(Vec::new()),
            executable,
        };
        let installer = Installer::new(executor, ".");
        let mut request = InstallRequest::new(device, artifact);
        request.ios.boot_on_demand = true;

        let error = installer
            .install(&request)
            .expect_err("mutated artifact must not be installed");

        assert_eq!(error.code(), "invalid_artifact");
        let commands = installer.executor.commands.borrow();
        assert_eq!(commands.len(), 2);
        assert!(
            commands
                .iter()
                .all(|command| command.operation != "install iOS Simulator application")
        );
    }
}
