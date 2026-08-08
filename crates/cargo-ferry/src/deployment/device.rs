use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    CommandExecutor, CommandOutput, DeploymentError, DeploymentResult, MAX_COREDEVICE_JSON_BYTES,
    ToolCommand, read_bounded_tool_file,
};

/// Mobile operating-system family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    /// Android device or emulator.
    Android,
    /// Apple iOS device or Simulator.
    Ios,
}

/// Concrete device family and transport semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// USB or wireless Android hardware.
    AndroidPhysical,
    /// Android Emulator instance.
    AndroidEmulator,
    /// `CoreSimulator` virtual device.
    IosSimulator,
    /// Paired physical iPhone or iPad surfaced by `CoreDevice`.
    IosPhysical,
}

impl DeviceKind {
    /// Operating-system family for this device kind.
    pub const fn platform(self) -> DevicePlatform {
        match self {
            Self::AndroidPhysical | Self::AndroidEmulator => DevicePlatform::Android,
            Self::IosSimulator | Self::IosPhysical => DevicePlatform::Ios,
        }
    }
}

/// Normalized device connection/runtime state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Connected and available for ordinary Android operations.
    Online,
    /// Apple Simulator is booted.
    Booted,
    /// Apple Simulator exists but is shut down.
    Shutdown,
    /// Android bridge reports an offline transport.
    Offline,
    /// Android hardware has not authorized this host.
    Unauthorized,
    /// Tooling knows the device but cannot currently use it.
    Unavailable,
    /// Previously paired physical device is disconnected.
    Disconnected,
    /// Tool returned an unrecognized state.
    Unknown,
}

/// Operations supported for a device in its reported state/toolchain.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DeviceCapabilities {
    /// Build output can target this device family.
    pub build: bool,
    /// An artifact can be installed.
    pub install: bool,
    /// An installed application can be launched.
    pub launch: bool,
    /// A standalone, application-filtered log command is available.
    pub logs: bool,
}

/// Stable, cross-tool device representation used by CLI and IDE protocol.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Device {
    /// ADB serial, Simulator UDID, or `CoreDevice` identifier.
    pub id: String,
    /// Human-readable device name; never used as the stable selector.
    pub name: String,
    /// Mobile operating-system family.
    pub platform: DevicePlatform,
    /// Concrete physical/simulator family.
    pub kind: DeviceKind,
    /// Normalized availability state.
    pub state: DeviceState,
    /// Reported operating-system version.
    pub os_version: Option<String>,
    /// Reported CPU architecture or ABI.
    pub architecture: Option<String>,
    /// USB, network, emulator, or `CoreSimulator` transport label.
    pub transport: Option<String>,
    /// Whether official Apple tooling reports the device paired.
    pub paired: bool,
    /// Whether the host/device trust relationship is usable.
    pub trusted: bool,
    /// State- and tooling-aware operation support.
    pub capabilities: DeviceCapabilities,
    /// Bounded extra structured fields useful for diagnostics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

/// Restrict one discovery snapshot to an operating-system family.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceFilter {
    /// Discover every supported device family.
    #[default]
    All,
    /// Discover Android devices and emulators only.
    Android,
    /// Discover Apple Simulators and physical devices only.
    Ios,
}

/// Official `CoreDevice` capabilities detected from the installed Xcode version.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DevicectlCapabilities {
    /// `xcrun devicectl` can be invoked.
    pub available: bool,
    /// Versioned JSON-file output is advertised.
    pub json_output: bool,
    /// Physical application installation is advertised.
    pub install: bool,
    /// Physical application launch is advertised.
    pub launch: bool,
    /// Application console attachment is advertised.
    pub logs: bool,
}

/// Non-fatal platform discovery failure; other device families remain usable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryWarning {
    /// Stable deployment error code.
    pub code: String,
    /// Affected discovery source.
    pub source: String,
    /// Bounded actionable summary.
    pub message: String,
}

/// One normalized device inventory.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DeviceSnapshot {
    /// Devices sorted by platform, kind, and stable ID.
    pub devices: Vec<Device>,
    /// Independent platform failures that did not abort other discovery.
    pub warnings: Vec<DiscoveryWarning>,
    /// Installed `CoreDevice` feature support.
    pub devicectl: DevicectlCapabilities,
}

impl DeviceSnapshot {
    /// Compute debounced added/changed/removed events against an older snapshot.
    pub fn changes_since(&self, previous: &Self) -> Vec<DeviceDelta> {
        let old = previous
            .devices
            .iter()
            .map(|device| (device_key(device), device))
            .collect::<BTreeMap<_, _>>();
        let new = self
            .devices
            .iter()
            .map(|device| (device_key(device), device))
            .collect::<BTreeMap<_, _>>();
        let mut changes = Vec::new();
        for (key, device) in &new {
            match old.get(key) {
                None => changes.push(DeviceDelta {
                    kind: DeviceDeltaKind::Added,
                    device: (*device).clone(),
                }),
                Some(old_device) if *old_device != *device => changes.push(DeviceDelta {
                    kind: DeviceDeltaKind::Changed,
                    device: (*device).clone(),
                }),
                Some(_) => {}
            }
        }
        for (key, device) in old {
            if !new.contains_key(&key) {
                changes.push(DeviceDelta {
                    kind: DeviceDeltaKind::Removed,
                    device: device.clone(),
                });
            }
        }
        changes
    }
}

/// Watch-mode inventory event.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceDelta {
    /// Type of snapshot change.
    pub kind: DeviceDeltaKind,
    /// Current device value, or last value for a removal.
    pub device: Device,
}

/// Watch-mode change type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceDeltaKind {
    /// Newly discovered stable ID.
    Added,
    /// Existing stable ID changed state or metadata.
    Changed,
    /// Stable ID disappeared.
    Removed,
}

/// Read-only discovery service for ADB, `CoreSimulator`, and `CoreDevice`.
pub struct DeviceService<E> {
    executor: E,
    current_directory: Utf8PathBuf,
    adb: Utf8PathBuf,
    xcrun: Utf8PathBuf,
    timeout: Duration,
    devicectl_probe: OnceLock<Result<DevicectlCapabilities, DiscoveryWarning>>,
}

impl<E: CommandExecutor> DeviceService<E> {
    /// Create a service using tools resolved from PATH.
    pub fn new(executor: E, current_directory: impl Into<Utf8PathBuf>) -> Self {
        Self {
            executor,
            current_directory: current_directory.into(),
            adb: Utf8PathBuf::from("adb"),
            xcrun: Utf8PathBuf::from("xcrun"),
            timeout: Duration::from_secs(15),
            devicectl_probe: OnceLock::new(),
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

    /// Discover requested device families without allowing one missing tool to mask another.
    pub fn discover(&self, filter: DeviceFilter) -> DeviceSnapshot {
        let mut snapshot = DeviceSnapshot::default();
        if matches!(filter, DeviceFilter::All | DeviceFilter::Android) {
            match self.discover_android() {
                Ok(mut devices) => snapshot.devices.append(&mut devices),
                Err(error) => snapshot.warnings.push(warning("adb", &error)),
            }
        }
        if matches!(filter, DeviceFilter::All | DeviceFilter::Ios) {
            match self.discover_simulators() {
                Ok(mut devices) => snapshot.devices.append(&mut devices),
                Err(error) => snapshot.warnings.push(warning("simctl", &error)),
            }
            match self
                .devicectl_probe
                .get_or_init(|| {
                    self.detect_devicectl()
                        .map_err(|error| warning("devicectl", &error))
                })
                .clone()
            {
                Ok(capabilities) => {
                    snapshot.devicectl = capabilities;
                    if capabilities.available && capabilities.json_output {
                        match self.discover_physical_ios(capabilities) {
                            Ok(mut devices) => snapshot.devices.append(&mut devices),
                            Err(error) => {
                                snapshot.warnings.push(warning("devicectl", &error));
                            }
                        }
                    }
                }
                Err(warning) => snapshot.warnings.push(warning),
            }
        }
        snapshot.devices.sort_by_key(device_key);
        snapshot
    }

    fn discover_android(&self) -> DeploymentResult<Vec<Device>> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "discover Android devices",
            )
            .args(["devices", "-l"])
            .timeout(self.timeout),
        )?;
        ensure_success(&self.adb, "discover Android devices", &output)?;
        let source = String::from_utf8(output.stdout).map_err(|error| {
            DeploymentError::InvalidToolOutput {
                tool: "adb",
                operation: "discover Android devices",
                message: format!("output was not UTF-8: {error}"),
            }
        })?;
        let mut devices = parse_adb_devices(&source)?;
        for device in devices
            .iter_mut()
            .filter(|device| device.state == DeviceState::Online)
        {
            let output = self.executor.execute(
                &ToolCommand::new(&self.adb, &self.current_directory, "inspect Android device")
                    .args([
                        OsString::from("-s"),
                        OsString::from(&device.id),
                        OsString::from("shell"),
                        OsString::from("getprop"),
                    ])
                    .timeout(self.timeout),
            );
            if let Ok(output) = output
                && output.status.success()
                && let Ok(properties) = String::from_utf8(output.stdout)
            {
                enrich_android_device(device, &properties);
            }
        }
        Ok(devices)
    }

    fn discover_simulators(&self) -> DeploymentResult<Vec<Device>> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "discover iOS Simulators",
            )
            .args(["simctl", "list", "devices", "--json"])
            .timeout(self.timeout),
        )?;
        ensure_success(&self.xcrun, "discover iOS Simulators", &output)?;
        parse_simctl_devices(&output.stdout)
    }

    fn detect_devicectl(&self) -> DeploymentResult<DevicectlCapabilities> {
        let general = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "detect CoreDevice tooling",
            )
            .args(["devicectl", "help"])
            .timeout(self.timeout),
        )?;
        if !general.status.success() {
            return Ok(DevicectlCapabilities::default());
        }
        let general_help = combined_text(&general);
        let mut capabilities = DevicectlCapabilities {
            available: true,
            json_output: general_help.contains("--json-output"),
            ..DevicectlCapabilities::default()
        };
        capabilities.install =
            self.help_supports(&["devicectl", "help", "device", "install", "app"])?;
        capabilities.launch =
            self.help_supports(&["devicectl", "help", "device", "process", "launch"])?;
        if capabilities.launch {
            let launch = self.executor.execute(
                &ToolCommand::new(
                    &self.xcrun,
                    &self.current_directory,
                    "detect physical iOS logs",
                )
                .args(["devicectl", "help", "device", "process", "launch"])
                .timeout(self.timeout),
            )?;
            capabilities.logs =
                launch.status.success() && combined_text(&launch).contains("--console");
        }
        Ok(capabilities)
    }

    fn help_supports(&self, arguments: &[&str]) -> DeploymentResult<bool> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "detect CoreDevice capability",
            )
            .args(arguments.iter().copied())
            .timeout(self.timeout),
        )?;
        Ok(output.status.success())
    }

    fn discover_physical_ios(
        &self,
        capabilities: DevicectlCapabilities,
    ) -> DeploymentResult<Vec<Device>> {
        let file = tempfile::NamedTempFile::new().map_err(|source| DeploymentError::Io {
            action: "create CoreDevice JSON output",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
        let path = Utf8PathBuf::from_path_buf(file.path().to_owned()).map_err(|path| {
            DeploymentError::InvalidToolOutput {
                tool: "devicectl",
                operation: "discover physical iOS devices",
                message: format!("temporary path is not UTF-8: {}", path.display()),
            }
        })?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "discover physical iOS devices",
            )
            .args([
                OsString::from("devicectl"),
                OsString::from("list"),
                OsString::from("devices"),
                OsString::from("--timeout"),
                OsString::from(self.timeout.as_secs().to_string()),
                OsString::from("--json-output"),
                OsString::from(path.as_str()),
            ])
            .timeout(self.timeout + Duration::from_secs(2)),
        )?;
        ensure_success(&self.xcrun, "discover physical iOS devices", &output)?;
        let bytes = read_bounded_tool_file(
            &path,
            "devicectl",
            "discover physical iOS devices",
            "read CoreDevice JSON output",
            MAX_COREDEVICE_JSON_BYTES,
        )?;
        parse_devicectl_devices(&bytes, capabilities)
    }
}

/// Parse stable `adb devices -l` output, retaining offline and unauthorized devices.
///
/// # Errors
///
/// Returns an error when a non-diagnostic row lacks a serial and device state.
pub fn parse_adb_devices(source: &str) -> DeploymentResult<Vec<Device>> {
    let mut devices = Vec::new();
    let mut identifiers = BTreeSet::new();
    for raw in source.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with("List of devices attached")
            || line.starts_with('*')
            || line.starts_with("adb server")
        {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 {
            return Err(DeploymentError::InvalidToolOutput {
                tool: "adb",
                operation: "discover Android devices",
                message: format!("malformed device row with {} fields", fields.len()),
            });
        }
        let id = fields[0].to_owned();
        if !identifiers.insert(id.clone()) {
            continue;
        }
        let state = match fields[1] {
            "device" => DeviceState::Online,
            "offline" => DeviceState::Offline,
            "unauthorized" => DeviceState::Unauthorized,
            "no" if fields.get(2) == Some(&"permissions") => DeviceState::Unavailable,
            _ => DeviceState::Unknown,
        };
        let attributes = fields
            .iter()
            .skip(2)
            .filter_map(|field| field.split_once(':'))
            .collect::<BTreeMap<_, _>>();
        let kind = if id.starts_with("emulator-")
            || attributes
                .get("product")
                .is_some_and(|value| value.contains("sdk"))
        {
            DeviceKind::AndroidEmulator
        } else {
            DeviceKind::AndroidPhysical
        };
        let name = attributes
            .get("model")
            .map_or_else(|| id.clone(), |value| value.replace('_', " "));
        let transport = if kind == DeviceKind::AndroidEmulator {
            "emulator"
        } else if id.contains(':') || id.contains("_adb-tls-connect._tcp") {
            "wireless"
        } else {
            "usb"
        };
        let available = state == DeviceState::Online;
        let mut details = BTreeMap::new();
        for key in ["product", "device", "transport_id"] {
            if let Some(value) = attributes.get(key) {
                details.insert(key.to_owned(), Value::String((*value).to_owned()));
            }
        }
        devices.push(Device {
            id,
            name,
            platform: DevicePlatform::Android,
            kind,
            state,
            os_version: None,
            architecture: None,
            transport: Some(transport.to_owned()),
            paired: true,
            trusted: state != DeviceState::Unauthorized,
            capabilities: DeviceCapabilities {
                build: true,
                install: available,
                launch: available,
                logs: available,
            },
            details,
        });
    }
    Ok(devices)
}

/// Parse versioned `CoreSimulator` JSON rather than localized table output.
///
/// # Errors
///
/// Returns an error when the JSON is malformed or lacks its top-level device inventory.
pub fn parse_simctl_devices(source: &[u8]) -> DeploymentResult<Vec<Device>> {
    let value: Value =
        serde_json::from_slice(source).map_err(|error| DeploymentError::InvalidToolOutput {
            tool: "simctl",
            operation: "discover iOS Simulators",
            message: error.to_string(),
        })?;
    let runtimes = value
        .get("devices")
        .and_then(Value::as_object)
        .ok_or_else(|| DeploymentError::InvalidToolOutput {
            tool: "simctl",
            operation: "discover iOS Simulators",
            message: "top-level `devices` object is missing".to_owned(),
        })?;
    let mut devices = Vec::new();
    for (runtime, entries) in runtimes {
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for entry in entries {
            let Some(id) = string_at(entry, &["udid"]) else {
                continue;
            };
            let name = string_at(entry, &["name"]).unwrap_or_else(|| id.clone());
            let available = entry
                .get("isAvailable")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| {
                    string_at(entry, &["availability"])
                        .is_none_or(|value| !value.contains("unavailable"))
                });
            let state = if available {
                match string_at(entry, &["state"]).as_deref() {
                    Some("Booted") => DeviceState::Booted,
                    Some("Shutdown") => DeviceState::Shutdown,
                    _ => DeviceState::Unknown,
                }
            } else {
                DeviceState::Unavailable
            };
            let usable = available && matches!(state, DeviceState::Booted | DeviceState::Shutdown);
            let mut details = BTreeMap::new();
            details.insert("runtime".to_owned(), Value::String(runtime.clone()));
            if let Some(device_type) = string_at(entry, &["deviceTypeIdentifier"]) {
                details.insert("device_type".to_owned(), Value::String(device_type));
            }
            devices.push(Device {
                id,
                name,
                platform: DevicePlatform::Ios,
                kind: DeviceKind::IosSimulator,
                state,
                os_version: runtime_version(runtime),
                architecture: None,
                transport: Some("coresimulator".to_owned()),
                paired: true,
                trusted: true,
                capabilities: DeviceCapabilities {
                    build: available,
                    install: usable,
                    launch: usable,
                    logs: usable,
                },
                details,
            });
        }
    }
    Ok(devices)
}

/// Parse the versioned JSON file produced by `xcrun devicectl list devices`.
///
/// # Errors
///
/// Returns an error when the versioned result is malformed or lacks `result.devices`.
pub fn parse_devicectl_devices(
    source: &[u8],
    tool: DevicectlCapabilities,
) -> DeploymentResult<Vec<Device>> {
    let value: Value =
        serde_json::from_slice(source).map_err(|error| DeploymentError::InvalidToolOutput {
            tool: "devicectl",
            operation: "discover physical iOS devices",
            message: error.to_string(),
        })?;
    let entries = value
        .pointer("/result/devices")
        .and_then(Value::as_array)
        .ok_or_else(|| DeploymentError::InvalidToolOutput {
            tool: "devicectl",
            operation: "discover physical iOS devices",
            message: "`result.devices` array is missing".to_owned(),
        })?;
    let mut devices = Vec::new();
    for entry in entries {
        let platform = string_at(entry, &["hardwareProperties", "platform"])
            .or_else(|| string_at(entry, &["deviceProperties", "platform"]));
        if platform
            .as_deref()
            .is_some_and(|value| !value.to_ascii_lowercase().contains("ios"))
        {
            continue;
        }
        let Some(id) = string_at(entry, &["hardwareProperties", "udid"])
            .or_else(|| string_at(entry, &["identifier"]))
        else {
            continue;
        };
        let core_device_identifier = string_at(entry, &["identifier"]);
        let name = string_at(entry, &["deviceProperties", "name"])
            .or_else(|| string_at(entry, &["hardwareProperties", "marketingName"]))
            .unwrap_or_else(|| id.clone());
        let pairing = string_at(entry, &["deviceProperties", "pairingState"])
            .unwrap_or_default()
            .to_ascii_lowercase();
        let developer_mode = string_at(entry, &["deviceProperties", "developerModeStatus"])
            .unwrap_or_default()
            .to_ascii_lowercase();
        let transport = string_at(entry, &["connectionProperties", "transportType"])
            .or_else(|| string_at(entry, &["connectionProperties", "tunnelTransportProtocol"]));
        let connected = string_at(entry, &["connectionProperties", "tunnelState"])
            .is_some_and(|state| state.eq_ignore_ascii_case("connected"))
            || bool_at(entry, &["deviceProperties", "ddiServicesAvailable"]).unwrap_or(false);
        let paired = pairing.is_empty()
            || (pairing.contains("paired")
                && !pairing.contains("unpaired")
                && !pairing.contains("pending"));
        let trusted = paired && !developer_mode.contains("disabled");
        let state = if !paired {
            DeviceState::Unauthorized
        } else if connected {
            DeviceState::Online
        } else {
            DeviceState::Disconnected
        };
        let available = state == DeviceState::Online && trusted;
        let mut details = BTreeMap::new();
        if !pairing.is_empty() {
            details.insert("pairing_state".to_owned(), Value::String(pairing));
        }
        if !developer_mode.is_empty() {
            details.insert("developer_mode".to_owned(), Value::String(developer_mode));
        }
        if let Some(identifier) = core_device_identifier.filter(|identifier| identifier != &id) {
            details.insert(
                "core_device_identifier".to_owned(),
                Value::String(identifier),
            );
        }
        devices.push(Device {
            id,
            name,
            platform: DevicePlatform::Ios,
            kind: DeviceKind::IosPhysical,
            state,
            os_version: string_at(entry, &["deviceProperties", "osVersionNumber"])
                .or_else(|| string_at(entry, &["deviceProperties", "osVersion"])),
            architecture: string_at(entry, &["hardwareProperties", "cpuType"])
                .or_else(|| string_at(entry, &["hardwareProperties", "architecture"])),
            transport,
            paired,
            trusted,
            capabilities: DeviceCapabilities {
                build: available,
                install: available && tool.install,
                launch: available && tool.launch,
                // `devicectl --console` is a launch attachment, not the bounded standalone log
                // contract represented by this capability.
                logs: false,
            },
            details,
        });
    }
    Ok(devices)
}

fn enrich_android_device(device: &mut Device, properties: &str) {
    let properties = properties
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once("]: [")?;
            Some((key.trim_start_matches('['), value.trim_end_matches(']')))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(model) = properties
        .get("ro.product.model")
        .filter(|value| !value.is_empty())
    {
        (*model).clone_into(&mut device.name);
    }
    device.os_version = properties
        .get("ro.build.version.release")
        .filter(|value| !value.is_empty())
        .map(|value| (*value).to_owned());
    device.architecture = properties
        .get("ro.product.cpu.abi")
        .filter(|value| !value.is_empty())
        .map(|value| (*value).to_owned());
    if let Some(sdk) = properties.get("ro.build.version.sdk") {
        device
            .details
            .insert("sdk".to_owned(), Value::String((*sdk).to_owned()));
    }
}

fn ensure_success(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let message = bounded_message(&combined_text(output));
    let lowercase = message.to_ascii_lowercase();
    let (category, help) = if lowercase.contains("unauthorized") {
        (
            "device_unauthorized",
            "Unlock the device and approve this computer, then retry.",
        )
    } else if lowercase.contains("offline") {
        (
            "device_offline",
            "Reconnect or restart the affected device transport, then retry.",
        )
    } else if lowercase.contains("developer mode") {
        (
            "developer_mode_disabled",
            "Enable Developer Mode on the device and reconnect it.",
        )
    } else {
        (
            "device_discovery_failed",
            "Run the platform doctor and verify the installed SDK/Xcode tools.",
        )
    };
    Err(DeploymentError::CommandFailed {
        tool: tool.to_string(),
        operation,
        status: output.status.code(),
        message,
        category,
        help: help.to_owned(),
    })
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

fn bounded_message(source: &str) -> String {
    let mut message = source.trim().replace(['\r', '\n'], " ");
    if message.len() > 1_024 {
        message.truncate(1_024);
        message.push('…');
    }
    if message.is_empty() {
        "tool returned a non-success status without diagnostics".to_owned()
    } else {
        message
    }
}

fn warning(source: &str, error: &DeploymentError) -> DiscoveryWarning {
    DiscoveryWarning {
        code: error.code().to_owned(),
        source: source.to_owned(),
        message: bounded_message(&error.to_string()),
    }
}

fn device_key(device: &Device) -> (DevicePlatform, DeviceKind, String) {
    (device.platform, device.kind, device.id.clone())
}

fn runtime_version(runtime: &str) -> Option<String> {
    let suffix = runtime
        .rsplit(".iOS-")
        .next()
        .filter(|value| *value != runtime)?;
    Some(suffix.replace('-', "."))
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |cursor, key| cursor.get(*key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    path.iter()
        .try_fold(value, |cursor, key| cursor.get(*key))
        .and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_parser_keeps_non_ready_devices_and_stable_serials() {
        let devices = parse_adb_devices(include_str!(
            "../../tests/fixtures/deployment/adb-devices.txt"
        ))
        .expect("parse adb");
        assert_eq!(devices.len(), 4);
        assert_eq!(devices[0].id, "R58M123");
        assert_eq!(devices[0].name, "Galaxy S24");
        assert_eq!(devices[1].kind, DeviceKind::AndroidEmulator);
        assert_eq!(devices[1].state, DeviceState::Offline);
        assert_eq!(devices[2].state, DeviceState::Unauthorized);
        assert_eq!(devices[2].transport.as_deref(), Some("wireless"));
        assert!(!devices[2].capabilities.install);
        assert_eq!(devices[3].state, DeviceState::Unavailable);
    }

    #[test]
    fn simctl_parser_uses_json_runtime_and_availability() {
        let devices = parse_simctl_devices(include_bytes!(
            "../../tests/fixtures/deployment/simctl-devices.json"
        ))
        .expect("parse simctl");
        assert_eq!(devices[0].os_version.as_deref(), Some("18.5"));
        assert_eq!(devices[0].state, DeviceState::Booted);
        assert_eq!(devices[1].state, DeviceState::Unavailable);
    }

    #[test]
    fn devicectl_parser_normalizes_trust_and_capabilities() {
        let source = include_bytes!("../../tests/fixtures/deployment/devicectl-devices.json");
        let devices = parse_devicectl_devices(
            source,
            DevicectlCapabilities {
                available: true,
                json_output: true,
                install: true,
                launch: true,
                logs: true,
            },
        )
        .expect("parse CoreDevice");
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].id, "udid");
        assert_eq!(devices[0].details["core_device_identifier"], "core-id");
        assert_eq!(devices[0].state, DeviceState::Online);
        assert!(devices[0].trusted);
        assert!(devices[0].capabilities.launch);
        assert!(!devices[0].capabilities.logs);
        assert_eq!(devices[1].state, DeviceState::Unauthorized);
        assert!(!devices[1].trusted);
    }

    #[test]
    fn snapshot_changes_are_debounced_by_stable_id() {
        let device = parse_adb_devices("List of devices attached\nserial device model:Phone\n")
            .expect("device")
            .remove(0);
        let previous = DeviceSnapshot {
            devices: vec![device.clone()],
            ..DeviceSnapshot::default()
        };
        assert!(previous.changes_since(&previous).is_empty());
        let mut changed = device;
        changed.state = DeviceState::Offline;
        let next = DeviceSnapshot {
            devices: vec![changed],
            ..DeviceSnapshot::default()
        };
        assert_eq!(
            next.changes_since(&previous)[0].kind,
            DeviceDeltaKind::Changed
        );
    }
}
