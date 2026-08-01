use std::ffi::OsString;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ArtifactKind, CommandExecutor, CommandOutput, DeploymentError, DeploymentResult, Device,
    DeviceKind, DeviceState, MAX_COREDEVICE_JSON_BYTES, ToolCommand, ValidatedArtifact,
    read_bounded_tool_file,
};

/// Explicit application-launch request after build/install orchestration.
#[derive(Clone, Debug)]
pub struct LaunchRequest {
    /// Explicit selected device.
    pub device: Device,
    /// Validated artifact supplying exact package/bundle and launcher metadata.
    pub artifact: ValidatedArtifact,
    /// Boot a shutdown Simulator and wait before launching.
    pub boot_on_demand: bool,
    /// Explicitly terminate an existing app process before launch.
    pub terminate_existing: bool,
    /// Overall platform-tool deadline.
    pub timeout: Duration,
}

impl LaunchRequest {
    /// Create a conservative launch request without boot or termination side effects.
    pub fn new(device: Device, artifact: ValidatedArtifact) -> Self {
        Self {
            device,
            artifact,
            boot_on_demand: false,
            terminate_existing: false,
            timeout: Duration::from_mins(1),
        }
    }
}

/// Evidence returned after a platform tool reports application startup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaunchOutcome {
    /// Stable selected device ID.
    pub device_id: String,
    /// Exact package or bundle identifier launched.
    pub application_id: String,
    /// Process identifier when the platform exposes one.
    pub process_id: Option<u64>,
    /// Whether an existing process was explicitly terminated first.
    pub terminated_existing: bool,
}

/// Application launcher using ADB, simctl, or devicectl.
pub struct Launcher<E> {
    executor: E,
    current_directory: Utf8PathBuf,
    adb: Utf8PathBuf,
    xcrun: Utf8PathBuf,
}

impl<E: CommandExecutor> Launcher<E> {
    /// Create a launcher using tools resolved from PATH.
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

    /// Launch an installed application using exact metadata from the validated artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable devices, artifact mismatch, platform-tool failure,
    /// malformed `devicectl` output, or missing development-signing evidence.
    pub fn launch(&self, request: &LaunchRequest) -> DeploymentResult<LaunchOutcome> {
        validate_launch_device(&request.device)?;
        match (request.device.kind, request.artifact.kind) {
            (
                DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator,
                ArtifactKind::AndroidApk,
            ) => self.launch_android(request),
            (DeviceKind::IosSimulator, ArtifactKind::IosSimulatorApp) => {
                self.launch_simulator(request)
            }
            (DeviceKind::IosPhysical, ArtifactKind::IosPhysicalApp) => {
                self.launch_physical_ios(request)
            }
            (_, kind) => Err(DeploymentError::PlatformMismatch {
                path: request.artifact.path.clone(),
                artifact_platform: kind.label(),
                requested_platform: device_label(request.device.kind),
            }),
        }
    }

    fn launch_android(&self, request: &LaunchRequest) -> DeploymentResult<LaunchOutcome> {
        let component = format!(
            "{}/{}",
            request.artifact.application_id, request.artifact.launch_target
        );
        let mut arguments = vec![
            OsString::from("-s"),
            OsString::from(&request.device.id),
            OsString::from("shell"),
            OsString::from("am"),
            OsString::from("start"),
            OsString::from("-W"),
        ];
        if request.terminate_existing {
            arguments.push(OsString::from("-S"));
        }
        arguments.extend([OsString::from("-n"), OsString::from(component)]);
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "launch Android application",
            )
            .args(arguments)
            .timeout(request.timeout),
        )?;
        ensure_launch_success(&self.adb, "launch Android application", &output)?;
        let text = combined_text(&output);
        if text.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("error:")
                || line.starts_with("failure")
                || line.contains("status: error")
        }) {
            return Err(command_failure(
                &self.adb,
                "launch Android application",
                &output,
                "application_start_failed",
                "Verify the validated launcher activity and inspect Android package state.",
            ));
        }
        let pid = self.android_pid(request);
        Ok(outcome(request, pid))
    }

    fn android_pid(&self, request: &LaunchRequest) -> Option<u64> {
        let output = self
            .executor
            .execute(
                &ToolCommand::new(
                    &self.adb,
                    &self.current_directory,
                    "query Android process ID",
                )
                .args([
                    OsString::from("-s"),
                    OsString::from(&request.device.id),
                    OsString::from("shell"),
                    OsString::from("pidof"),
                    OsString::from(&request.artifact.application_id),
                ])
                .timeout(Duration::from_secs(10)),
            )
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout)
            .ok()?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    fn launch_simulator(&self, request: &LaunchRequest) -> DeploymentResult<LaunchOutcome> {
        if request.device.state == DeviceState::Shutdown {
            if !request.boot_on_demand {
                return Err(DeploymentError::DeviceUnavailable {
                    id: request.device.id.clone(),
                    state: request.device.state,
                    operation: "launch iOS Simulator application",
                    help: "Boot the selected Simulator or pass the explicit boot-on-demand option."
                        .to_owned(),
                });
            }
            let boot = self.executor.execute(
                &ToolCommand::new(&self.xcrun, &self.current_directory, "boot iOS Simulator")
                    .args(["simctl", "boot", &request.device.id])
                    .timeout(request.timeout),
            )?;
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
                    "Verify the selected Simulator and runtime are available.",
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
            ensure_launch_success(&self.xcrun, "wait for iOS Simulator boot", &wait)?;
        }
        let mut arguments = vec![OsString::from("simctl"), OsString::from("launch")];
        if request.terminate_existing {
            arguments.push(OsString::from("--terminate-running-process"));
        }
        arguments.extend([
            OsString::from(&request.device.id),
            OsString::from(&request.artifact.application_id),
        ]);
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "launch iOS Simulator application",
            )
            .args(arguments)
            .timeout(request.timeout),
        )?;
        ensure_launch_success(&self.xcrun, "launch iOS Simulator application", &output)?;
        let pid = String::from_utf8_lossy(&output.stdout)
            .split_once(':')
            .and_then(|(_, value)| value.trim().parse().ok());
        Ok(outcome(request, pid))
    }

    fn launch_physical_ios(&self, request: &LaunchRequest) -> DeploymentResult<LaunchOutcome> {
        if !request.artifact.signed || request.artifact.team_id.is_none() {
            return Err(DeploymentError::InvalidSigning {
                path: request.artifact.path.clone(),
                message: "physical launch requires a verified Apple Development signature"
                    .to_owned(),
            });
        }
        let json = tempfile::NamedTempFile::new().map_err(|source| DeploymentError::Io {
            action: "create CoreDevice launch result",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
        let json_path = Utf8PathBuf::from_path_buf(json.path().to_owned()).map_err(|path| {
            DeploymentError::InvalidToolOutput {
                tool: "devicectl",
                operation: "launch physical iOS application",
                message: format!("temporary result path is not UTF-8: {}", path.display()),
            }
        })?;
        let mut arguments = vec![
            OsString::from("devicectl"),
            OsString::from("device"),
            OsString::from("process"),
            OsString::from("launch"),
            OsString::from("--device"),
            OsString::from(&request.device.id),
        ];
        if request.terminate_existing {
            arguments.push(OsString::from("--terminate-existing"));
        }
        arguments.extend([
            OsString::from("--timeout"),
            OsString::from(request.timeout.as_secs().to_string()),
            OsString::from("--json-output"),
            OsString::from(json_path.as_str()),
            OsString::from(&request.artifact.application_id),
        ]);
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "launch physical iOS application",
            )
            .args(arguments)
            .timeout(request.timeout + Duration::from_secs(2)),
        )?;
        ensure_launch_success(&self.xcrun, "launch physical iOS application", &output)?;
        let bytes = read_bounded_tool_file(
            &json_path,
            "devicectl",
            "launch physical iOS application",
            "read CoreDevice launch result",
            MAX_COREDEVICE_JSON_BYTES,
        )?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|error| DeploymentError::InvalidToolOutput {
                tool: "devicectl",
                operation: "launch physical iOS application",
                message: error.to_string(),
            })?;
        if value.pointer("/info/outcome").and_then(Value::as_str) != Some("success") {
            return Err(DeploymentError::InvalidToolOutput {
                tool: "devicectl",
                operation: "launch physical iOS application",
                message: "versioned result did not report `info.outcome=success`".to_owned(),
            });
        }
        Ok(outcome(request, find_pid(&value)))
    }
}

fn validate_launch_device(device: &Device) -> DeploymentResult<()> {
    if !device.capabilities.launch
        || matches!(
            device.state,
            DeviceState::Offline
                | DeviceState::Unauthorized
                | DeviceState::Unavailable
                | DeviceState::Disconnected
                | DeviceState::Unknown
        )
    {
        return Err(DeploymentError::DeviceUnavailable {
            id: device.id.clone(),
            state: device.state,
            operation: "launch application",
            help: "Select a connected, trusted device that supports application launch.".to_owned(),
        });
    }
    Ok(())
}

fn ensure_launch_success(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let lower = combined_text(output).to_ascii_lowercase();
    let (category, help) = if lower.contains("unable to find")
        || lower.contains("not found")
        || lower.contains("unknown package")
    {
        (
            "application_not_installed",
            "Install the validated artifact on this exact device before launching.",
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
            "application_start_failed",
            "Inspect the bounded platform diagnostic and verify the installed application identity.",
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

fn outcome(request: &LaunchRequest, process_id: Option<u64>) -> LaunchOutcome {
    LaunchOutcome {
        device_id: request.device.id.clone(),
        application_id: request.artifact.application_id.clone(),
        process_id,
        terminated_existing: request.terminate_existing,
    }
}

fn find_pid(value: &Value) -> Option<u64> {
    match value {
        Value::Object(object) => {
            for key in ["processIdentifier", "processID", "pid"] {
                if let Some(pid) = object.get(key).and_then(Value::as_u64) {
                    return Some(pid);
                }
            }
            object.values().find_map(find_pid)
        }
        Value::Array(values) => values.iter().find_map(find_pid),
        _ => None,
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
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;
    use crate::deployment::{DeviceCapabilities, DevicePlatform, inspect_artifact};

    struct FakeExecutor {
        commands: RefCell<Vec<ToolCommand>>,
        outputs: RefCell<Vec<CommandOutput>>,
    }

    impl CommandExecutor for FakeExecutor {
        fn execute(&self, command: &ToolCommand) -> DeploymentResult<CommandOutput> {
            self.commands.borrow_mut().push(command.clone());
            Ok(self.outputs.borrow_mut().remove(0))
        }
    }

    fn output(stdout: &[u8]) -> CommandOutput {
        CommandOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn android_launch_uses_validated_exact_component_and_selected_serial() {
        use std::io::Write as _;
        let mut apk = tempfile::Builder::new()
            .suffix(".apk")
            .tempfile()
            .expect("APK");
        apk.write_all(b"PK\x03\x04payload").expect("write");
        let path = Utf8PathBuf::from_path_buf(apk.path().to_owned()).expect("UTF-8");
        let digest =
            rustferry_core::digest_artifact(&path, rustferry_core::ArtifactDigestKind::AndroidApk)
                .expect("artifact digest");
        let artifact = inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "org.rustferry.FerryActivity",
            &digest,
            true,
            None,
        )
        .expect("artifact");
        let device = Device {
            id: "serial".to_owned(),
            name: "Phone".to_owned(),
            platform: DevicePlatform::Android,
            kind: DeviceKind::AndroidPhysical,
            state: DeviceState::Online,
            os_version: None,
            architecture: None,
            transport: None,
            paired: true,
            trusted: true,
            capabilities: DeviceCapabilities {
                build: true,
                install: true,
                launch: true,
                logs: true,
            },
            details: BTreeMap::default(),
        };
        let executor = FakeExecutor {
            commands: RefCell::new(Vec::new()),
            outputs: RefCell::new(vec![output(b"Status: ok\n"), output(b"42\n")]),
        };
        let launcher = Launcher::new(executor, ".");
        let result = launcher
            .launch(&LaunchRequest::new(device, artifact))
            .expect("launch");
        assert_eq!(result.process_id, Some(42));
        let command = &launcher.executor.commands.borrow()[0];
        let arguments = command
            .arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(arguments[0..2], ["-s", "serial"]);
        assert!(arguments.contains(&"com.example.app/org.rustferry.FerryActivity".into()));
    }

    #[test]
    fn finds_nested_devicectl_pid() {
        let value = serde_json::json!({"result":{"process":{"processIdentifier":1234}}});
        assert_eq!(find_pid(&value), Some(1234));
    }
}
