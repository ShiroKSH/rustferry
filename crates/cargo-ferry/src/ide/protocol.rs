//! Rust source of truth for the stable editor protocol.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::Map;
use serde_json::Value;
use thiserror::Error;

/// Current IDE protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Protocol versions accepted by this executable, oldest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [u32; 1] = [PROTOCOL_VERSION];

/// Stable event names emitted by protocol v1.
pub const SUPPORTED_EVENT_TYPES: [&str; 15] = [
    "operation_started",
    "phase_started",
    "progress",
    "command_started",
    "diagnostic",
    "device",
    "artifact",
    "application_started",
    "log",
    "warning",
    "fix",
    "phase_finished",
    "operation_finished",
    "operation_cancelled",
    "device_removed",
];

/// Every top-level document described by the checked-in protocol schema.
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ProtocolMessage {
    /// Version negotiation response.
    Handshake(HandshakeResponse),
    /// Resolved project model.
    Project(ProjectResponse),
    /// Configuration diagnostics.
    Validation(ValidationResponse),
    /// Host toolchain report.
    Doctor(DoctorResponse),
    /// One device inventory.
    Devices(DeviceSnapshotResponse),
    /// Usable Apple Development teams.
    SigningTeams(SigningTeamsResponse),
    /// Unary protocol failure.
    Error(ProtocolErrorResponse),
    /// One newline-delimited streaming event.
    Event(StreamEvent),
}

/// Version negotiation result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct HandshakeResponse {
    /// Negotiated protocol version.
    pub protocol_version: u32,
    /// Executable identity.
    pub tool: ToolInfo,
    /// Extension-host environment.
    pub host: HostInfo,
    /// Versions accepted by this executable.
    pub supported_protocol_versions: Vec<u32>,
    /// Platform identifiers accepted by build operations.
    pub supported_platforms: Vec<String>,
    /// Available IDE subcommands.
    pub supported_commands: Vec<String>,
    /// Event names a v1 client can consume.
    pub supported_event_types: Vec<String>,
    /// Feature availability, never inferred by the client from the host OS.
    pub features: FeatureFlags,
    /// Reproducible executable metadata.
    pub build: BuildMetadata,
    /// Runtime crate resolution status for project generation.
    pub runtime_dependency: RuntimeDependencyStatus,
    /// Project templates provided by the Rust generator.
    pub templates: Vec<TemplateMetadata>,
}

/// Executable name and package version.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ToolInfo {
    /// Cargo package name.
    pub name: String,
    /// Cargo package version.
    pub version: String,
}

/// Operating system and architecture of the extension host.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct HostInfo {
    /// Rust target OS identifier.
    pub os: String,
    /// Rust target architecture identifier.
    pub arch: String,
}

/// IDE-visible feature switches.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureFlags {
    /// Android artifact builds are implemented.
    pub android_build: bool,
    /// iOS Simulator artifact builds are implemented.
    pub ios_simulator_build: bool,
    /// Structured device discovery is implemented.
    pub devices: bool,
    /// Structured installation is implemented.
    pub install: bool,
    /// Structured launch is implemented.
    pub run: bool,
    /// Application-specific log streaming is implemented.
    pub logs: bool,
    /// Official physical-iOS build and deployment is implemented.
    pub physical_ios: bool,
    /// Process-tree cancellation is implemented.
    pub cancellation: bool,
}

/// Apple Development identities available to editor signing UI.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningTeamsResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Installed usable identities grouped by Team ID.
    pub teams: Vec<SigningTeam>,
}

/// Non-secret Apple Development identity metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningTeam {
    /// Apple Development Team identifier.
    pub team_id: String,
    /// Human-readable Keychain identity label.
    pub identity: String,
    /// Public certificate fingerprint.
    pub certificate_fingerprint: String,
}

/// Static information about this executable build.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct BuildMetadata {
    /// Cargo profile used for this executable.
    pub profile: String,
    /// Host target expressed as `os-arch`.
    pub target: String,
    /// True for non-release builds.
    pub development: bool,
    /// Optional commit injected by release automation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

/// Project-generator runtime dependency state.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RuntimeDependencyStatus {
    /// Whether the configured resolver is usable.
    pub usable: bool,
    /// `registry` for release mode or `path` for explicit monorepo mode.
    pub source: String,
}

/// Generator-owned project template metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct TemplateMetadata {
    /// Stable CLI value.
    pub id: String,
    /// Short purpose shown by editor pickers.
    pub description: String,
}

/// Resolved project response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProjectResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Resolved project metadata.
    pub project: ProjectModel,
    /// Generator-owned templates for new-project UI.
    pub templates: Vec<TemplateMetadata>,
}

/// IDE-safe project metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProjectModel {
    /// Canonical absolute project root.
    pub root: String,
    /// Absolute configuration path.
    pub config_path: String,
    /// Absolute generated-output boundary.
    pub target_directory: String,
    /// Human-facing application name.
    pub display_name: String,
    /// Cargo package name.
    pub crate_name: String,
    /// Android package and Apple bundle identifier.
    pub identifier: String,
    /// Semantic application version.
    pub version: String,
    /// Platform-facing display version.
    pub display_version: String,
    /// Enabled target platforms.
    pub platforms: Vec<String>,
    /// Enabled runtime and extension capabilities.
    pub capabilities: Vec<String>,
    /// Resolved Android configuration.
    pub android: Value,
    /// Resolved Apple configuration.
    pub ios: Value,
}

/// Configuration validation result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ValidationResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// True when no error diagnostics exist.
    pub valid: bool,
    /// Stable, sorted diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Host toolchain report returned by the shared doctor service.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct DoctorResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Existing typed doctor result serialized without parsing human output.
    pub report: Value,
}

/// Unary device discovery result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct DeviceSnapshotResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Stable, sorted device records.
    pub devices: Vec<Device>,
    /// Independent platform discovery failures.
    pub warnings: Vec<DeviceDiscoveryWarning>,
    /// Detected physical-iOS tool capabilities.
    pub devicectl: DevicectlCapabilities,
}

/// Non-fatal device discovery failure.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DeviceDiscoveryWarning {
    /// Stable code.
    pub code: String,
    /// ADB, `CoreSimulator`, or `CoreDevice` source.
    pub source: String,
    /// Bounded actionable summary.
    pub message: String,
}

/// Physical Apple tooling detected from installed Xcode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DevicectlCapabilities {
    /// `xcrun devicectl` exists.
    pub available: bool,
    /// Structured JSON output is supported.
    pub json_output: bool,
    /// Physical install is supported.
    pub install: bool,
    /// Physical launch is supported.
    pub launch: bool,
    /// Physical application logs are supported.
    pub logs: bool,
}

/// A source position using zero-based line and UTF-16 character offsets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Position {
    /// Zero-based line.
    pub line: u32,
    /// Zero-based UTF-16 code-unit offset.
    pub character: u32,
}

/// Half-open source range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SourceRange {
    /// Inclusive start.
    pub start: Position,
    /// Exclusive end.
    pub end: Position,
}

/// Diagnostic severity understood by VS Code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Build or configuration failure.
    Error,
    /// Actionable warning.
    Warning,
    /// Informational note.
    Information,
    /// Low-priority hint.
    Hint,
}

/// File diagnostic produced by Rust validation or a platform build.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Diagnostic {
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Stable namespaced code.
    pub code: String,
    /// User-facing summary without ANSI escapes.
    pub message: String,
    /// Absolute UTF-8 file path.
    pub file: String,
    /// Zero-based half-open range.
    pub range: SourceRange,
    /// Concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Documentation URL when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    /// Safe edits or commands explicitly supplied by Rust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<StructuredFix>,
}

/// Kind of safe fix returned by Rust.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixKind {
    /// Apply one exact text replacement.
    TextEdit,
    /// Invoke a registered editor command.
    Command,
    /// Open documentation.
    Documentation,
}

/// Safe editor action.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct StructuredFix {
    /// Picker title.
    pub title: String,
    /// Action category.
    pub kind: FixKind,
    /// Exact text replacement, only for `text_edit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit: Option<TextEdit>,
    /// Stable command ID, only for `command`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// One exact, file-bound replacement.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct TextEdit {
    /// Absolute file path.
    pub file: String,
    /// Text to replace.
    pub range: SourceRange,
    /// Replacement UTF-8 text.
    pub new_text: String,
}

/// Unary machine failure.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolErrorResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Typed failure.
    pub error: ProtocolError,
}

/// Typed, redacted protocol failure.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolError {
    /// Stable snake-case code.
    pub code: String,
    /// Safe summary.
    pub message: String,
    /// Concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Additional redacted details.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// One complete newline-delimited event.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct StreamEvent {
    /// Protocol version.
    pub protocol_version: u32,
    /// Opaque ID shared by every event in this operation.
    pub operation_id: String,
    /// Optional enclosing operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    /// Milliseconds since Unix epoch in UTC.
    pub timestamp_ms: u64,
    /// Event-specific fields.
    #[serde(flatten)]
    pub body: EventBody,
}

/// Versioned streaming payloads.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventBody {
    /// Operation boundary opened.
    OperationStarted {
        /// Stable command name.
        command: String,
        /// Canonical workspace, absent for host-only operations.
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace: Option<String>,
    },
    /// Named phase opened.
    PhaseStarted {
        /// Stable phase identifier.
        phase: String,
        /// Optional UI text.
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Bounded progress update.
    Progress {
        /// Stable phase identifier.
        phase: String,
        /// Human-readable progress summary.
        message: String,
        /// Completed unit count.
        #[serde(skip_serializing_if = "Option::is_none")]
        current: Option<u64>,
        /// Total unit count, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    /// Sanitized external command boundary.
    CommandStarted {
        /// Executable name, not a shell string.
        tool: String,
        /// Redacted argument array.
        arguments: Vec<String>,
    },
    /// File-bound diagnostic.
    Diagnostic {
        /// Diagnostic payload.
        diagnostic: Diagnostic,
    },
    /// Added or changed device.
    Device {
        /// Deployment service model.
        device: Device,
    },
    /// Validated build artifact.
    Artifact {
        /// Artifact payload.
        artifact: Artifact,
    },
    /// Application launch confirmation.
    ApplicationStarted {
        /// Platform identifier.
        platform: String,
        /// Stable target device ID.
        device_id: String,
        /// Package or bundle identifier.
        identifier: String,
        /// Process identifier when the platform reports one.
        #[serde(skip_serializing_if = "Option::is_none")]
        process_id: Option<u64>,
    },
    /// One bounded application log record.
    Log {
        /// Platform-provided timestamp, when available.
        #[serde(skip_serializing_if = "Option::is_none")]
        source_timestamp: Option<String>,
        /// Normalized severity.
        level: String,
        /// Process, package, or subsystem.
        target: String,
        /// Sanitized UTF-8 message.
        message: String,
    },
    /// Non-fatal warning.
    Warning {
        /// Stable namespaced code.
        code: String,
        /// Safe summary.
        message: String,
        /// Concrete remediation.
        #[serde(skip_serializing_if = "Option::is_none")]
        help: Option<String>,
    },
    /// Standalone safe fix.
    Fix {
        /// Fix payload.
        fix: StructuredFix,
    },
    /// Named phase closed.
    PhaseFinished {
        /// Stable phase identifier.
        phase: String,
        /// Whether the phase completed successfully.
        success: bool,
        /// Monotonic phase duration.
        duration_ms: u64,
    },
    /// Operation closed normally, including typed failures.
    OperationFinished {
        /// Whether every required phase succeeded.
        success: bool,
        /// Monotonic operation duration.
        duration_ms: u64,
        /// Typed failure when `success` is false.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProtocolError>,
    },
    /// Operation stopped after cancellation.
    OperationCancelled {
        /// Stable cancellation reason.
        reason: String,
        /// Monotonic operation duration.
        duration_ms: u64,
    },
    /// Device disappeared from a watched snapshot.
    DeviceRemoved {
        /// Stable device ID.
        device_id: String,
    },
}

/// Validated artifact metadata consumed by the Artifacts view.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Artifact {
    /// Platform identifier.
    pub platform: String,
    /// Artifact kind such as `apk` or `app`.
    pub kind: String,
    /// Absolute artifact path.
    pub path: String,
    /// Package or bundle identifier.
    pub package_identifier: String,
    /// Included native architectures.
    pub architectures: Vec<String>,
    /// `debug` or `release`.
    pub profile: String,
    /// Deterministically ordered validation statuses.
    pub validation: BTreeMap<String, String>,
}

/// Mobile operating-system family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    /// Android device or emulator.
    Android,
    /// Apple iOS device or Simulator.
    Ios,
}

/// Concrete mobile device family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// USB or wireless Android hardware.
    AndroidPhysical,
    /// Android Emulator instance.
    AndroidEmulator,
    /// `CoreSimulator` virtual device.
    IosSimulator,
    /// Paired physical Apple device.
    IosPhysical,
}

/// Normalized connection and runtime state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Connected and available.
    Online,
    /// Simulator is booted.
    Booted,
    /// Simulator is shut down.
    Shutdown,
    /// Transport is offline.
    Offline,
    /// Host has not been authorized.
    Unauthorized,
    /// Known but currently unusable.
    Unavailable,
    /// Paired device is disconnected.
    Disconnected,
    /// Tool returned an unrecognized state.
    Unknown,
}

/// Operations available for one device.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DeviceCapabilities {
    /// Builds may target this family.
    pub build: bool,
    /// Installation is available.
    pub install: bool,
    /// Launch is available.
    pub launch: bool,
    /// Application logs are available.
    pub logs: bool,
}

/// Stable device record used by snapshots and stream events.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Device {
    /// ADB serial, Simulator UDID, or `CoreDevice` identifier.
    pub id: String,
    /// Display name, never used for selection.
    pub name: String,
    /// Mobile platform.
    pub platform: DevicePlatform,
    /// Device family.
    pub kind: DeviceKind,
    /// Current state.
    pub state: DeviceState,
    /// Operating-system version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Architecture or ABI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// USB, network, emulator, or `CoreSimulator` transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Official Apple pairing status.
    pub paired: bool,
    /// Host/device trust status.
    pub trusted: bool,
    /// State-aware operation support.
    pub capabilities: DeviceCapabilities,
    /// Bounded extra structured details.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

/// Streaming writer with stable operation metadata.
#[derive(Debug)]
pub struct EventEmitter {
    operation_id: String,
    parent_operation_id: Option<String>,
    started: Instant,
}

impl EventEmitter {
    /// Create an emitter after validating caller-owned opaque IDs.
    pub fn new(
        operation_id: Option<String>,
        parent_operation_id: Option<String>,
    ) -> Result<Self, ProtocolDecodeError> {
        let operation_id = operation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        validate_operation_id(&operation_id)?;
        if let Some(parent) = &parent_operation_id {
            validate_operation_id(parent)?;
        }
        Ok(Self {
            operation_id,
            parent_operation_id,
            started: Instant::now(),
        })
    }

    /// Monotonic elapsed milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Write one complete compact JSON object followed by `\n`.
    pub fn emit(&self, body: EventBody) -> std::io::Result<()> {
        self.emit_at(body, unix_timestamp_ms())
    }

    fn emit_at(&self, body: EventBody, timestamp_ms: u64) -> std::io::Result<()> {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: self.operation_id.clone(),
            parent_operation_id: self.parent_operation_id.clone(),
            timestamp_ms,
            body,
        };
        write_compact(&event)
    }
}

/// Parsed event that preserves forward-compatible unknown event types.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub enum ParsedEvent {
    /// Event understood by this executable.
    Known(StreamEvent),
    /// Future event retained as raw JSON and safe to ignore.
    Unknown {
        /// Unknown event discriminator.
        event: String,
        /// Raw object.
        value: Map<String, Value>,
    },
}

/// Protocol framing or compatibility failure.
#[derive(Debug, Error, PartialEq)]
#[allow(dead_code)]
pub enum ProtocolDecodeError {
    /// Stream ended between JSON objects.
    #[error("stream ended with a partial JSON line")]
    TruncatedStream,
    /// Bytes were not valid UTF-8.
    #[error("protocol stream is not valid UTF-8")]
    InvalidUtf8,
    /// JSON object was malformed or omitted a required field.
    #[error("invalid protocol event: {0}")]
    InvalidEvent(String),
    /// Peer protocol is not compatible with this executable.
    #[error("protocol version {found} is incompatible; supported versions: {supported:?}")]
    IncompatibleVersion {
        /// Version found in input.
        found: u32,
        /// Supported versions.
        supported: Vec<u32>,
    },
    /// Caller-supplied operation identifier is unsafe or ambiguous.
    #[error("operation ID must be 1-128 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidOperationId,
}

/// Parse a complete newline-delimited stream. A missing final newline is truncated.
#[cfg(test)]
pub fn parse_ndjson(bytes: &[u8]) -> Result<Vec<ParsedEvent>, ProtocolDecodeError> {
    let source = std::str::from_utf8(bytes).map_err(|_| ProtocolDecodeError::InvalidUtf8)?;
    if !source.is_empty() && !source.ends_with('\n') {
        return Err(ProtocolDecodeError::TruncatedStream);
    }
    source
        .split_terminator('\n')
        .filter(|line| !line.is_empty())
        .map(parse_event_line)
        .collect()
}

/// Parse one complete event line while accepting unknown event types and fields.
#[cfg(test)]
pub fn parse_event_line(line: &str) -> Result<ParsedEvent, ProtocolDecodeError> {
    let value = serde_json::from_str::<Value>(line)
        .map_err(|error| ProtocolDecodeError::InvalidEvent(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolDecodeError::InvalidEvent("event must be an object".to_owned()))?;
    let version = object
        .get("protocol_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            ProtocolDecodeError::InvalidEvent("protocol_version is required".to_owned())
        })?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolDecodeError::IncompatibleVersion {
            found: version,
            supported: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
        });
    }
    for field in ["operation_id", "timestamp_ms", "event"] {
        if !object.contains_key(field) {
            return Err(ProtocolDecodeError::InvalidEvent(format!(
                "{field} is required"
            )));
        }
    }
    let event = object
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolDecodeError::InvalidEvent("event must be a string".to_owned()))?;
    if SUPPORTED_EVENT_TYPES.contains(&event) {
        serde_json::from_value::<StreamEvent>(value)
            .map(ParsedEvent::Known)
            .map_err(|error| ProtocolDecodeError::InvalidEvent(error.to_string()))
    } else {
        Ok(ParsedEvent::Unknown {
            event: event.to_owned(),
            value: object.clone(),
        })
    }
}

/// Generate the canonical JSON Schema from Rust protocol structs.
pub fn schema_value() -> Result<Value, serde_json::Error> {
    serde_json::to_value(schema_for!(ProtocolMessage))
}

/// Write one unary response as compact UTF-8 JSON followed by `\n`.
pub fn write_compact<T: Serialize>(value: &T) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value).map_err(std::io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()
}

/// Convert an internal error to a stable, redacted protocol error.
pub fn protocol_error(error: &crate::error::CliError) -> ProtocolError {
    ProtocolError {
        code: error.code().to_owned(),
        message: redact_text(&error.to_string()),
        help: error.help().map(|value| redact_text(&value)),
        details: error
            .details()
            .into_iter()
            .map(|value| redact_text(&value))
            .collect(),
    }
}

/// Remove common credential assignments from diagnostic text.
pub fn redact_text(source: &str) -> String {
    let sanitized = strip_terminal_controls(source);
    let mut words = sanitized
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for word in &mut words {
        redact_url_userinfo(word);
    }
    let mut redact_next = false;
    let mut index = 0;
    while index < words.len() {
        if redact_next {
            if matches!(words[index].as_str(), "=" | ":") {
                index += 1;
                continue;
            }
            if words[index].starts_with(['=', ':']) {
                words[index].truncate(1);
                words[index].push_str("<redacted>");
            } else {
                "<redacted>".clone_into(&mut words[index]);
            }
            redact_next = false;
            index += 1;
            continue;
        }

        if is_authorization_marker(&words[index]) {
            index = redact_authorization_value(&mut words, index);
            continue;
        }

        if is_multiword_key_marker(&words, index) {
            redact_next = redact_marker_value(&mut words[index + 1]);
            index += 2;
            continue;
        }

        if is_sensitive_marker(&words[index]) {
            redact_next = redact_marker_value(&mut words[index]);
        }
        index += 1;
    }
    words.join(" ")
}

fn is_authorization_marker(word: &str) -> bool {
    matches!(
        marker_name(word).as_str(),
        "authorization" | "proxy-authorization"
    )
}

fn redact_authorization_value(words: &mut [String], marker_index: usize) -> usize {
    let marker = &mut words[marker_index];
    if let Some(separator) = marker.find(['=', ':'])
        && separator + 1 < marker.len()
    {
        if is_authorization_scheme(&marker[separator + 1..]) {
            return redact_authorization_token(words, marker_index + 1);
        }
        marker.truncate(separator + 1);
        marker.push_str("<redacted>");
        return marker_index + 1;
    }

    let mut value_index = marker_index + 1;
    while words
        .get(value_index)
        .is_some_and(|word| matches!(word.as_str(), "=" | ":"))
    {
        value_index += 1;
    }
    if let Some(value) = words.get_mut(value_index)
        && value.starts_with(['=', ':'])
    {
        if is_authorization_scheme(&value[1..]) {
            return redact_authorization_token(words, value_index + 1);
        }
        value.truncate(1);
        value.push_str("<redacted>");
        return value_index + 1;
    }
    if words
        .get(value_index)
        .is_some_and(|word| is_authorization_scheme(word))
    {
        value_index += 1;
    }
    redact_authorization_token(words, value_index)
}

fn redact_authorization_token(words: &mut [String], mut value_index: usize) -> usize {
    if let Some(value) = words.get_mut(value_index) {
        "<redacted>".clone_into(value);
        value_index += 1;
    }
    value_index
}

fn is_authorization_scheme(value: &str) -> bool {
    matches!(
        value
            .trim_matches(|character: char| !character.is_ascii_alphanumeric())
            .to_ascii_lowercase()
            .as_str(),
        "bearer" | "basic" | "digest" | "negotiate"
    )
}

fn redact_url_userinfo(word: &mut String) {
    let Some(scheme) = word.find("://") else {
        return;
    };
    let authority_start = scheme + 3;
    let Some(relative_at) = word[authority_start..].find('@') else {
        return;
    };
    let at = authority_start + relative_at;
    let authority_prefix = &word[authority_start..at];
    if authority_prefix.is_empty() || authority_prefix.contains(['/', '?', '#']) {
        return;
    }
    word.replace_range(authority_start..at, "<redacted>");
}

fn is_multiword_key_marker(words: &[String], index: usize) -> bool {
    let Some(key) = words.get(index + 1) else {
        return false;
    };
    let first = marker_name(&words[index]);
    let second = marker_name(key);
    let is_key_phrase = matches!(first.as_str(), "api" | "private") && second == "key";
    is_key_phrase
        && (key.contains(['=', ':'])
            || words
                .get(index + 2)
                .is_some_and(|word| word.starts_with(['=', ':'])))
}

fn is_sensitive_marker(word: &str) -> bool {
    sensitive_assignment_separator(word).is_some() || is_sensitive_name(&marker_name(word))
}

fn is_sensitive_name(name: &str) -> bool {
    matches!(
        name,
        "password" | "passphrase" | "token" | "secret" | "key-pass" | "ks-pass"
    ) || name
        .split('-')
        .any(|component| matches!(component, "password" | "passphrase" | "token" | "secret"))
        || matches!(name, "api-key" | "private-key")
}

fn marker_name(word: &str) -> String {
    let end = word.find(['=', ':']).unwrap_or(word.len());
    marker_name_before(word, end)
}

fn marker_name_before(word: &str, end: usize) -> String {
    word[..end]
        .rsplit(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        })
        .find(|part| !part.is_empty())
        .unwrap_or_default()
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn sensitive_assignment_separator(word: &str) -> Option<usize> {
    word.char_indices()
        .filter(|(_, character)| matches!(character, '=' | ':'))
        .map(|(index, _)| index)
        .find(|index| is_sensitive_name(&marker_name_before(word, *index)))
}

fn redact_marker_value(word: &mut String) -> bool {
    let Some(separator) = sensitive_assignment_separator(word).or_else(|| word.find(['=', ':']))
    else {
        return true;
    };
    if separator + 1 == word.len() {
        return true;
    }
    word.truncate(separator + 1);
    word.push_str("<redacted>");
    false
}

fn strip_terminal_controls(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\u{1b}' => match characters.next() {
                Some('[') => {
                    for sequence_character in characters.by_ref() {
                        if ('@'..='~').contains(&sequence_character) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(sequence_character) = characters.next() {
                        if sequence_character == '\u{7}' {
                            break;
                        }
                        if sequence_character == '\u{1b}' && characters.next_if_eq(&'\\').is_some()
                        {
                            break;
                        }
                    }
                }
                Some(_) | None => {}
            },
            '\u{9b}' => {
                for sequence_character in characters.by_ref() {
                    if ('@'..='~').contains(&sequence_character) {
                        break;
                    }
                }
            }
            whitespace if whitespace.is_whitespace() => output.push(' '),
            control if control.is_control() => {}
            printable => output.push(printable),
        }
    }
    output
}

fn validate_operation_id(value: &str) -> Result<(), ProtocolDecodeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ProtocolDecodeError::InvalidOperationId);
    }
    Ok(())
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started_event() -> StreamEvent {
        StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "op-1".to_owned(),
            parent_operation_id: Some("parent-1".to_owned()),
            timestamp_ms: 1_700_000_000_000,
            body: EventBody::OperationStarted {
                command: "build".to_owned(),
                workspace: Some("C:\\Users\\Zoë Doe\\Ferry App".to_owned()),
            },
        }
    }

    #[test]
    fn rust_event_round_trips_unicode_windows_and_space_paths() {
        let encoded = serde_json::to_string(&started_event()).unwrap();
        let decoded = parse_event_line(&encoded).unwrap();
        assert_eq!(decoded, ParsedEvent::Known(started_event()));
    }

    #[test]
    fn typescript_fixture_deserializes_in_rust() {
        let source =
            include_str!("../../tests/fixtures/ide-protocol-v1/event-from-typescript.json");
        assert!(matches!(
            parse_event_line(source.trim()).unwrap(),
            ParsedEvent::Known(StreamEvent {
                body: EventBody::Diagnostic { .. },
                ..
            })
        ));
    }

    #[test]
    fn rust_serialization_matches_typescript_fixture() {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "rust:artifact-1".to_owned(),
            parent_operation_id: None,
            timestamp_ms: 1_700_000_000_000,
            body: EventBody::Artifact {
                artifact: Artifact {
                    platform: "android".to_owned(),
                    kind: "apk".to_owned(),
                    path: "/tmp/Ferry App 🚢/target/ferry/android/debug/app.apk".to_owned(),
                    package_identifier: "com.example.ferry".to_owned(),
                    architectures: vec!["arm64-v8a".to_owned()],
                    profile: "debug".to_owned(),
                    validation: BTreeMap::from([
                        ("alignment".to_owned(), "verified".to_owned()),
                        ("signature".to_owned(), "verified".to_owned()),
                    ]),
                },
            },
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            include_str!("../../tests/fixtures/ide-protocol-v1/event-from-rust.json").trim()
        );
    }

    #[test]
    fn cancellation_fixture_has_complete_operation_boundary() {
        let source = include_bytes!("../../tests/fixtures/ide-protocol-v1/cancellation.ndjson");
        let events = parse_ndjson(source).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[1],
            ParsedEvent::Known(StreamEvent {
                body: EventBody::OperationCancelled { .. },
                ..
            })
        ));
    }

    #[test]
    fn accepts_unknown_optional_fields() {
        let mut value = serde_json::to_value(started_event()).unwrap();
        value["future_optional"] = Value::Bool(true);
        assert!(matches!(
            parse_event_line(&value.to_string()).unwrap(),
            ParsedEvent::Known(_)
        ));
    }

    #[test]
    fn preserves_unknown_event_for_forward_compatibility() {
        let source = r#"{"protocol_version":1,"operation_id":"op","timestamp_ms":1,"event":"future_event","payload":"ok"}"#;
        assert!(matches!(
            parse_event_line(source).unwrap(),
            ParsedEvent::Unknown { event, .. } if event == "future_event"
        ));
    }

    #[test]
    fn rejects_missing_required_field_and_incompatible_version() {
        let missing = r#"{"protocol_version":1,"operation_id":"op","event":"operation_started"}"#;
        assert!(matches!(
            parse_event_line(missing),
            Err(ProtocolDecodeError::InvalidEvent(_))
        ));
        let incompatible =
            r#"{"protocol_version":2,"operation_id":"op","timestamp_ms":1,"event":"future"}"#;
        assert!(matches!(
            parse_event_line(incompatible),
            Err(ProtocolDecodeError::IncompatibleVersion { found: 2, .. })
        ));
    }

    #[test]
    fn detects_truncated_stream_and_invalid_utf8_after_child_crash() {
        assert_eq!(
            parse_ndjson(br#"{"protocol_version":1"#),
            Err(ProtocolDecodeError::TruncatedStream)
        );
        assert_eq!(
            parse_ndjson(&[0xff, b'\n']),
            Err(ProtocolDecodeError::InvalidUtf8)
        );
    }

    #[test]
    fn cancellation_event_is_typed() {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "cancel-me".to_owned(),
            parent_operation_id: None,
            timestamp_ms: 42,
            body: EventBody::OperationCancelled {
                reason: "requested".to_owned(),
                duration_ms: 7,
            },
        };
        let line = format!("{}\n", serde_json::to_string(&event).unwrap());
        assert_eq!(
            parse_ndjson(line.as_bytes()).unwrap(),
            vec![ParsedEvent::Known(event)]
        );
    }

    #[test]
    fn redacts_secret_assignments_and_argument_values() {
        let text = redact_text("--token abc password=hunter2 harmless");
        assert_eq!(text, "--token <redacted> password=<redacted> harmless");
        assert!(!text.contains("hunter2"));

        let spaced =
            redact_text("token: abc api-key = def private-key:ghi passphrase = jkl harmless");
        assert_eq!(
            spaced,
            "token: <redacted> api-key = <redacted> private-key:<redacted> passphrase = <redacted> harmless"
        );
        assert!(
            !["abc", "def", "ghi", "jkl"]
                .iter()
                .any(|secret| spaced.contains(secret))
        );

        let multiword = redact_text(
            "API key: alpha private key = beta API key=gamma private key:delta harmless",
        );
        assert_eq!(
            multiword,
            "API key: <redacted> private key = <redacted> API key=<redacted> private key:<redacted> harmless"
        );
        assert!(
            !["alpha", "beta", "gamma", "delta"]
                .iter()
                .any(|secret| multiword.contains(secret))
        );

        assert_eq!(
            redact_text("tokenizer stayed secretive; private keyboard works API key rotation"),
            "tokenizer stayed secretive; private keyboard works API key rotation"
        );

        assert_eq!(
            redact_text("request https://example.test/?api_key=url-secret failed"),
            "request https://example.test/?api_key=<redacted> failed"
        );

        let authorization =
            redact_text("Authorization: Bearer top-secret Proxy-Authorization: Basic dXNlcjpwYXNz");
        assert_eq!(
            authorization,
            "Authorization: Bearer <redacted> Proxy-Authorization: Basic <redacted>"
        );
        assert!(!authorization.contains("top-secret"));
        assert!(!authorization.contains("dXNlcjpwYXNz"));

        let inline_authorization =
            redact_text("Authorization:Bearer top-secret Proxy-Authorization:Basic dXNlcjpwYXNz");
        assert_eq!(
            inline_authorization,
            "Authorization:Bearer <redacted> Proxy-Authorization:Basic <redacted>"
        );
        assert!(!inline_authorization.contains("top-secret"));
        assert!(!inline_authorization.contains("dXNlcjpwYXNz"));

        assert_eq!(
            redact_text("Authorization :Bearer top-secret harmless"),
            "Authorization :Bearer <redacted> harmless"
        );

        assert_eq!(
            redact_text("GET https://alice:password@example.test/path?token=query-secret"),
            "GET https://<redacted>@example.test/path?token=<redacted>"
        );

        let terminal = redact_text(
            "\u{1b}[31mto\u{1b}[0mken: visible\nAPI \u{1b}[32mkey:\u{1b}[0m hidden\u{7} message",
        );
        assert_eq!(terminal, "token: <redacted> API key: <redacted> message");
        assert!(!terminal.chars().any(char::is_control));
        assert!(!terminal.contains("visible"));
        assert!(!terminal.contains("hidden"));
    }

    #[test]
    fn operation_ids_are_bounded_and_header_safe() {
        assert!(EventEmitter::new(Some("vscode:build-42".to_owned()), None).is_ok());
        assert!(EventEmitter::new(Some("bad id\n".to_owned()), None).is_err());
    }

    #[test]
    fn checked_in_schema_matches_rust_source_of_truth() {
        let checked = serde_json::from_str::<Value>(include_str!(
            "../../tests/fixtures/ide-protocol-v1/schema.json"
        ))
        .unwrap();
        assert_eq!(schema_value().unwrap(), checked);
    }
}
