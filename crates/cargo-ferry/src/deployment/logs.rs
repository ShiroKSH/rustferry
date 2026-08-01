use std::collections::VecDeque;
use std::ffi::OsString;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::executor::stream_command_lines;
use super::{
    CommandExecutor, CommandOutput, DeploymentError, DeploymentResult, Device, DeviceKind,
    DeviceState, SystemExecutor, ToolCommand,
};

const MAX_STREAM_LINE_BYTES: usize = 256 * 1024;
const MAX_PENDING_STREAM_LINES: usize = 1_024;

/// Normalized application log severity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Verbose/debug diagnostic.
    Debug,
    /// Ordinary application information.
    #[default]
    Info,
    /// Potential problem.
    Warning,
    /// Operation failure.
    Error,
    /// Fatal process failure.
    Fatal,
    /// Platform level could not be normalized.
    Unknown,
}

/// One bounded, application-filtered platform log entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogEntry {
    /// Platform timestamp preserved without locale-dependent reinterpretation.
    pub timestamp: String,
    /// Normalized severity.
    pub level: LogLevel,
    /// Android tag or Apple subsystem/process target.
    pub target: String,
    /// Log message.
    pub message: String,
    /// Process identifier when provided by the platform.
    pub process_id: Option<u64>,
}

/// Fixed-entry/fixed-byte log ring; oldest entries are evicted first.
#[derive(Clone, Debug)]
pub struct BoundedLogBuffer {
    entries: VecDeque<LogEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl BoundedLogBuffer {
    /// Create a buffer with non-zero entry and UTF-8 byte limits.
    ///
    /// # Errors
    ///
    /// Returns an error when either bound is zero.
    pub fn new(max_entries: usize, max_bytes: usize) -> DeploymentResult<Self> {
        if max_entries == 0 || max_bytes == 0 {
            return Err(DeploymentError::Unsupported {
                message: "log buffer bounds must be non-zero".to_owned(),
                help: "Set both maximum entries and maximum bytes to positive values.".to_owned(),
            });
        }
        Ok(Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        })
    }

    /// Add an entry, evicting oldest entries until both limits hold.
    pub fn push(&mut self, mut entry: LogEntry) {
        if entry.message.len() > self.max_bytes {
            let mut boundary = self.max_bytes;
            while !entry.message.is_char_boundary(boundary) {
                boundary = boundary.saturating_sub(1);
            }
            entry.message.truncate(boundary);
        }
        let size = entry_size(&entry);
        self.entries.push_back(entry);
        self.bytes = self.bytes.saturating_add(size);
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            if let Some(removed) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(entry_size(&removed));
            } else {
                break;
            }
        }
    }

    /// Consume the ring into chronological entries.
    pub fn into_entries(self) -> Vec<LogEntry> {
        self.entries.into_iter().collect()
    }

    /// Current retained UTF-8 payload size.
    pub const fn retained_bytes(&self) -> usize {
        self.bytes
    }
}

/// One bounded application-log snapshot request.
#[derive(Clone, Debug)]
pub struct LogRequest {
    /// Explicit selected device.
    pub device: Device,
    /// Exact Android package or Apple bundle identifier.
    pub application_id: String,
    /// Exact executable/process name used for Apple process filtering.
    pub process_name: String,
    /// Requested recent history window.
    pub since: Duration,
    /// Lowest retained severity.
    pub minimum_level: LogLevel,
    /// Maximum retained entries.
    pub max_entries: usize,
    /// Maximum retained UTF-8 bytes.
    pub max_bytes: usize,
    /// Overall platform-tool deadline.
    pub timeout: Duration,
}

/// Summary returned when a live application-log tool exits normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogStreamOutcome {
    /// Application-filtered records delivered incrementally to the consumer.
    pub entries: u64,
}

impl LogRequest {
    /// Create a conservative five-minute, 2,000-entry, 2 MiB snapshot request.
    pub fn new(
        device: Device,
        application_id: impl Into<String>,
        process_name: impl Into<String>,
    ) -> Self {
        Self {
            device,
            application_id: application_id.into(),
            process_name: process_name.into(),
            since: Duration::from_mins(5),
            minimum_level: LogLevel::Info,
            max_entries: 2_000,
            max_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Bounded application-log collection through ADB or Simulator unified logging.
pub struct LogService<E> {
    executor: E,
    current_directory: Utf8PathBuf,
    adb: Utf8PathBuf,
    xcrun: Utf8PathBuf,
}

impl<E: CommandExecutor> LogService<E> {
    /// Create a service using tools resolved from PATH.
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

    /// Collect a finite, process-filtered snapshot without clearing global device logs.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable device, invalid bounds/filter metadata, platform-tool
    /// failure, missing Android process, or malformed Apple JSON.
    pub fn collect_snapshot(&self, request: &LogRequest) -> DeploymentResult<Vec<LogEntry>> {
        validate_request(request)?;
        let entries = match request.device.kind {
            DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator => {
                self.collect_android(request)?
            }
            DeviceKind::IosSimulator => self.collect_simulator(request)?,
            DeviceKind::IosPhysical => {
                return Err(DeploymentError::Unsupported {
                    message: "the installed Xcode CoreDevice API has no standalone, application-filtered historical log command".to_owned(),
                    help: "Launch with explicit console attachment when devicectl advertises `--console`; cargo-ferry will not emit the entire device system log.".to_owned(),
                });
            }
        };
        let mut buffer = BoundedLogBuffer::new(request.max_entries, request.max_bytes)?;
        for entry in entries.into_iter().filter(|entry| {
            entry.level >= request.minimum_level || entry.level == LogLevel::Unknown
        }) {
            buffer.push(entry);
        }
        Ok(buffer.into_entries())
    }

    /// Build a continuous process-filtered command for the live streaming service.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid filters, unavailable tooling, or a missing Android process.
    pub fn stream_command(&self, request: &LogRequest) -> DeploymentResult<ToolCommand> {
        validate_request(request)?;
        match request.device.kind {
            DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator => {
                let pid = self.android_pid(request)?;
                Ok(ToolCommand::new(
                    &self.adb,
                    &self.current_directory,
                    "stream Android application logs",
                )
                .args([
                    OsString::from("-s"),
                    OsString::from(&request.device.id),
                    OsString::from("logcat"),
                    OsString::from("-v"),
                    OsString::from("epoch"),
                    OsString::from("--pid"),
                    OsString::from(pid.to_string()),
                ])
                .output_limit(request.max_bytes))
            }
            DeviceKind::IosSimulator => Ok(ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "stream iOS Simulator application logs",
            )
            .args([
                OsString::from("simctl"),
                OsString::from("spawn"),
                OsString::from(&request.device.id),
                OsString::from("log"),
                OsString::from("stream"),
                OsString::from("--style"),
                OsString::from("ndjson"),
                OsString::from("--predicate"),
                OsString::from(apple_predicate(request)),
            ])
            .output_limit(request.max_bytes)),
            DeviceKind::IosPhysical => Err(DeploymentError::Unsupported {
                message: "standalone physical iOS log streaming is unavailable".to_owned(),
                help: "Use explicit launch console attachment when supported by the installed devicectl."
                    .to_owned(),
            }),
        }
    }

    fn collect_android(&self, request: &LogRequest) -> DeploymentResult<Vec<LogEntry>> {
        let pid = self.android_pid(request)?;
        let device_now = self.android_epoch_seconds(request)?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "collect Android application logs",
            )
            .args([
                OsString::from("-s"),
                OsString::from(&request.device.id),
                OsString::from("logcat"),
                OsString::from("-d"),
                OsString::from("-v"),
                OsString::from("epoch"),
                OsString::from("--pid"),
                OsString::from(pid.to_string()),
                OsString::from("-t"),
                OsString::from(request.max_entries.to_string()),
            ])
            .timeout(request.timeout)
            .output_limit(request.max_bytes),
        )?;
        ensure_log_success(&self.adb, "collect Android application logs", &output)?;
        let source = String::from_utf8(output.stdout).map_err(|error| {
            DeploymentError::InvalidToolOutput {
                tool: "adb logcat",
                operation: "collect Android application logs",
                message: format!("log output was not UTF-8: {error}"),
            }
        })?;
        let cutoff = device_now.saturating_sub(request.since.as_secs());
        Ok(parse_android_logs(&source)
            .into_iter()
            .filter(|entry| {
                android_epoch_seconds(&entry.timestamp).is_some_and(|value| value >= cutoff)
            })
            .collect())
    }

    fn android_pid(&self, request: &LogRequest) -> DeploymentResult<u64> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "find Android application process",
            )
            .args([
                OsString::from("-s"),
                OsString::from(&request.device.id),
                OsString::from("shell"),
                OsString::from("pidof"),
                OsString::from(&request.application_id),
            ])
            .timeout(Duration::from_secs(10)),
        )?;
        ensure_log_success(&self.adb, "find Android application process", &output)?;
        String::from_utf8(output.stdout)
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse().ok())
            .ok_or_else(|| DeploymentError::CommandFailed {
                tool: self.adb.to_string(),
                operation: "find Android application process",
                status: output.status.code(),
                message: format!("package `{}` is not running", request.application_id),
                category: "application_not_running",
                help: "Launch the application before attaching logs.".to_owned(),
            })
    }

    fn android_epoch_seconds(&self, request: &LogRequest) -> DeploymentResult<u64> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.adb,
                &self.current_directory,
                "read Android device time",
            )
            .args([
                OsString::from("-s"),
                OsString::from(&request.device.id),
                OsString::from("shell"),
                OsString::from("date"),
                OsString::from("+%s"),
            ])
            .timeout(Duration::from_secs(10)),
        )?;
        ensure_log_success(&self.adb, "read Android device time", &output)?;
        String::from_utf8(output.stdout)
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse().ok())
            .ok_or_else(|| DeploymentError::InvalidToolOutput {
                tool: "adb date",
                operation: "read Android device time",
                message: "device epoch output was not an unsigned integer".to_owned(),
            })
    }

    fn collect_simulator(&self, request: &LogRequest) -> DeploymentResult<Vec<LogEntry>> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                &self.current_directory,
                "collect iOS Simulator application logs",
            )
            .args([
                OsString::from("simctl"),
                OsString::from("spawn"),
                OsString::from(&request.device.id),
                OsString::from("log"),
                OsString::from("show"),
                OsString::from("--style"),
                OsString::from("ndjson"),
                OsString::from("--last"),
                OsString::from(since_argument(request.since)),
                OsString::from("--predicate"),
                OsString::from(apple_predicate(request)),
            ])
            .timeout(request.timeout)
            .output_limit(request.max_bytes),
        )?;
        ensure_log_success(
            &self.xcrun,
            "collect iOS Simulator application logs",
            &output,
        )?;
        let source = String::from_utf8(output.stdout).map_err(|error| {
            DeploymentError::InvalidToolOutput {
                tool: "simctl log",
                operation: "collect iOS Simulator application logs",
                message: format!("log output was not UTF-8: {error}"),
            }
        })?;
        parse_apple_logs(&source)
    }
}

impl LogService<SystemExecutor> {
    /// Stream application-filtered records until cancellation or platform-tool exit.
    ///
    /// Records are decoded one bounded line at a time and are not retained by this service. Ctrl+C
    /// cancels the operation and terminates the complete platform-tool process tree.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid filters, unavailable tools/devices, malformed or oversized
    /// output, consumer failure, cancellation, or a non-success platform-tool exit.
    pub fn stream<OnEntry>(
        &self,
        request: &LogRequest,
        on_entry: OnEntry,
    ) -> DeploymentResult<LogStreamOutcome>
    where
        OnEntry: FnMut(LogEntry) -> DeploymentResult<()>,
    {
        self.stream_with_control(
            request,
            rustferry_core::process_control::interrupt_requested,
            on_entry,
        )
    }

    fn stream_with_control<IsCancelled, OnEntry>(
        &self,
        request: &LogRequest,
        is_cancelled: IsCancelled,
        mut on_entry: OnEntry,
    ) -> DeploymentResult<LogStreamOutcome>
    where
        IsCancelled: Fn() -> bool,
        OnEntry: FnMut(LogEntry) -> DeploymentResult<()>,
    {
        let command = self.stream_command(request)?;
        let mut entries = 0_u64;
        let mut source_line = 0_usize;
        let output = stream_command_lines(
            &command,
            request.max_bytes.min(MAX_STREAM_LINE_BYTES),
            request.max_entries.min(MAX_PENDING_STREAM_LINES),
            is_cancelled,
            |bytes| {
                source_line = source_line.saturating_add(1);
                let line = std::str::from_utf8(bytes).map_err(|error| {
                    DeploymentError::InvalidToolOutput {
                        tool: "platform log stream",
                        operation: command.operation,
                        message: format!("line {source_line} was not UTF-8: {error}"),
                    }
                })?;
                let entry = match request.device.kind {
                    DeviceKind::AndroidPhysical | DeviceKind::AndroidEmulator => {
                        parse_android_log_line(line)
                    }
                    DeviceKind::IosSimulator => parse_apple_log_line(line, source_line)?,
                    DeviceKind::IosPhysical => None,
                };
                if let Some(entry) = entry
                    && (entry.level >= request.minimum_level || entry.level == LogLevel::Unknown)
                {
                    on_entry(entry)?;
                    entries = entries.saturating_add(1);
                }
                Ok(())
            },
        )?;
        ensure_log_success(&command.program, command.operation, &output)?;
        Ok(LogStreamOutcome { entries })
    }
}

/// Parse `adb logcat -v epoch` lines. Malformed lines are retained as unknown entries.
pub fn parse_android_logs(source: &str) -> Vec<LogEntry> {
    source.lines().filter_map(parse_android_log_line).collect()
}

fn parse_android_log_line(line: &str) -> Option<LogEntry> {
    if line.trim().is_empty() || line.starts_with("--------- beginning of") {
        return None;
    }
    let mut fields = line.split_whitespace();
    let parsed = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    );
    let (Some(timestamp), Some(pid), Some(_thread), Some(level), Some(target)) = parsed else {
        return Some(LogEntry {
            timestamp: String::new(),
            level: LogLevel::Unknown,
            target: "android".to_owned(),
            message: line.to_owned(),
            process_id: None,
        });
    };
    Some(LogEntry {
        timestamp: timestamp.to_owned(),
        level: android_level(level),
        target: target.trim_end_matches(':').to_owned(),
        message: fields.collect::<Vec<_>>().join(" "),
        process_id: pid.parse().ok(),
    })
}

fn android_epoch_seconds(value: &str) -> Option<u64> {
    value.split('.').next()?.parse().ok()
}

/// Parse newline-delimited unified-log JSON from Simulator tooling.
///
/// # Errors
///
/// Returns an error when any non-empty log line is not valid JSON.
pub fn parse_apple_logs(source: &str) -> DeploymentResult<Vec<LogEntry>> {
    let mut entries = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if let Some(entry) = parse_apple_log_line(line, index + 1)? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_apple_log_line(line: &str, line_number: usize) -> DeploymentResult<Option<LogEntry>> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    let value: Value =
        serde_json::from_str(line).map_err(|error| DeploymentError::InvalidToolOutput {
            tool: "simctl log",
            operation: "parse iOS application logs",
            message: format!("line {line_number} is not JSON: {error}"),
        })?;
    let timestamp = json_string(&value, &["timestamp"])
        .or_else(|| json_string(&value, &["time"]))
        .unwrap_or_default();
    let message = json_string(&value, &["eventMessage"])
        .or_else(|| json_string(&value, &["message"]))
        .unwrap_or_default();
    let target = json_string(&value, &["subsystem"])
        .or_else(|| json_string(&value, &["processImagePath"]))
        .or_else(|| json_string(&value, &["process"]))
        .unwrap_or_else(|| "ios".to_owned());
    let level = json_string(&value, &["messageType"])
        .or_else(|| json_string(&value, &["level"]))
        .map_or(LogLevel::Unknown, |value| apple_level(&value));
    let process_id = value
        .get("processID")
        .or_else(|| value.get("processIdentifier"))
        .and_then(Value::as_u64);
    Ok(Some(LogEntry {
        timestamp,
        level,
        target,
        message,
        process_id,
    }))
}

fn validate_request(request: &LogRequest) -> DeploymentResult<()> {
    if request.application_id.trim().is_empty() || request.process_name.trim().is_empty() {
        return Err(DeploymentError::Unsupported {
            message: "application ID and process name are required for filtered logs".to_owned(),
            help: "Use identity metadata from a validated artifact.".to_owned(),
        });
    }
    if !request.device.capabilities.logs
        || matches!(
            request.device.state,
            DeviceState::Offline
                | DeviceState::Unauthorized
                | DeviceState::Unavailable
                | DeviceState::Disconnected
                | DeviceState::Unknown
        )
    {
        return Err(DeploymentError::DeviceUnavailable {
            id: request.device.id.clone(),
            state: request.device.state,
            operation: "collect application logs",
            help: "Select a connected device whose installed tooling supports application logs."
                .to_owned(),
        });
    }
    if request.max_entries == 0 || request.max_bytes == 0 {
        return Err(DeploymentError::Unsupported {
            message: "log collection bounds must be non-zero".to_owned(),
            help: "Set positive maximum entries and bytes.".to_owned(),
        });
    }
    Ok(())
}

fn ensure_log_success(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let mut message = combined_text(output).trim().replace(['\r', '\n'], " ");
    if message.len() > 2_048 {
        message.truncate(2_048);
        message.push('…');
    }
    Err(DeploymentError::CommandFailed {
        tool: tool.to_string(),
        operation,
        status: output.status.code(),
        message,
        category: "log_collection_failed",
        help: "Verify the application is running and the selected device remains connected."
            .to_owned(),
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

fn apple_predicate(request: &LogRequest) -> String {
    // The complete predicate is one argument consumed by Apple's log tool, not a shell string.
    let process = predicate_literal(&request.process_name);
    let bundle = predicate_literal(&request.application_id);
    format!("process == {process} OR subsystem BEGINSWITH {bundle}")
}

fn predicate_literal(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn since_argument(duration: Duration) -> String {
    if duration.as_secs().is_multiple_of(3_600) && duration.as_secs() >= 3_600 {
        format!("{}h", duration.as_secs() / 3_600)
    } else if duration.as_secs().is_multiple_of(60) && duration.as_secs() >= 60 {
        format!("{}m", duration.as_secs() / 60)
    } else {
        format!("{}s", duration.as_secs().max(1))
    }
}

fn android_level(value: &str) -> LogLevel {
    match value {
        "V" | "D" => LogLevel::Debug,
        "I" => LogLevel::Info,
        "W" => LogLevel::Warning,
        "E" => LogLevel::Error,
        "F" | "A" => LogLevel::Fatal,
        _ => LogLevel::Unknown,
    }
}

fn apple_level(value: &str) -> LogLevel {
    match value.to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "default" | "info" | "notice" => LogLevel::Info,
        "warning" | "warn" => LogLevel::Warning,
        "error" => LogLevel::Error,
        "fault" | "fatal" => LogLevel::Fatal,
        _ => LogLevel::Unknown,
    }
}

fn json_string(value: &Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |cursor, key| cursor.get(*key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn entry_size(entry: &LogEntry) -> usize {
    entry.timestamp.len() + entry.target.len() + entry.message.len() + 32
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use super::*;
    use crate::deployment::{DeviceCapabilities, DevicePlatform};

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

    fn android_device() -> Device {
        Device {
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
        }
    }

    fn simulator_device() -> Device {
        Device {
            id: "simulator-id".to_owned(),
            name: "iPhone".to_owned(),
            platform: DevicePlatform::Ios,
            kind: DeviceKind::IosSimulator,
            state: DeviceState::Booted,
            os_version: None,
            architecture: None,
            transport: Some("coresimulator".to_owned()),
            paired: true,
            trusted: true,
            capabilities: DeviceCapabilities {
                build: true,
                install: true,
                launch: true,
                logs: true,
            },
            details: BTreeMap::default(),
        }
    }

    fn fake_log_tool() -> (tempfile::TempDir, Utf8PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = Utf8PathBuf::from_path_buf(temporary.path().join("fake-log-tool"))
            .expect("UTF-8 fake tool path");
        fs::write(
            &path,
            include_bytes!("../../tests/fixtures/deployment/fake-log-tool.sh"),
        )
        .expect("write fake log tool");
        let mut permissions = fs::metadata(&path)
            .expect("fake tool metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("make fake tool executable");
        (temporary, path)
    }

    #[test]
    fn android_collection_filters_by_pid_time_window_without_global_clear() {
        let executor = FakeExecutor {
            commands: RefCell::new(Vec::new()),
            outputs: RefCell::new(vec![
                output(b"123\n"),
                output(b"1754050000\n"),
                output(
                    b"1754049000.000 123 124 I Ferry: stale\n1754049999.500 123 124 I Ferry: started\n",
                ),
            ]),
        };
        let service = LogService::new(executor, ".");
        let entries = service
            .collect_snapshot(&LogRequest::new(android_device(), "com.example.app", "app"))
            .expect("logs");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "started");
        let commands = service.executor.commands.borrow();
        let time_arguments = commands[1]
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(time_arguments, ["-s", "serial", "shell", "date", "+%s"]);
        let command = &commands[2];
        let arguments = command
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|values| values == ["--pid", "123"])
        );
        assert!(!arguments.iter().any(|argument| argument == "-c"));
    }

    #[test]
    fn android_stream_uses_exact_pid_filter_without_global_log_operations() {
        let executor = FakeExecutor {
            commands: RefCell::new(Vec::new()),
            outputs: RefCell::new(vec![output(b"4242\n")]),
        };
        let service = LogService::new(executor, ".");
        let command = service
            .stream_command(&LogRequest::new(android_device(), "com.example.app", "app"))
            .expect("stream command");
        let arguments = command
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            ["-s", "serial", "logcat", "-v", "epoch", "--pid", "4242"]
        );
        assert!(!arguments.iter().any(|argument| argument == "-c"));
        assert!(!arguments.iter().any(|argument| argument == "-d"));
    }

    #[test]
    fn simulator_stream_uses_ndjson_and_exact_application_predicate() {
        let service = LogService::new(
            FakeExecutor {
                commands: RefCell::new(Vec::new()),
                outputs: RefCell::new(Vec::new()),
            },
            ".",
        );
        let command = service
            .stream_command(&LogRequest::new(
                simulator_device(),
                "com.example.app",
                "Ferry App",
            ))
            .expect("stream command");
        let arguments = command
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            &arguments[..7],
            [
                "simctl",
                "spawn",
                "simulator-id",
                "log",
                "stream",
                "--style",
                "ndjson"
            ]
        );
        assert_eq!(arguments[7], "--predicate");
        assert_eq!(
            arguments[8],
            "process == \"Ferry App\" OR subsystem BEGINSWITH \"com.example.app\""
        );
        assert!(!arguments.iter().any(|argument| argument == "show"));
    }

    #[test]
    fn system_stream_delivers_android_and_simulator_entries_incrementally() {
        let (_temporary_android, android_tool) = fake_log_tool();
        let android = LogService::new(SystemExecutor, ".").with_tools(&android_tool, &android_tool);
        let mut android_entries = Vec::new();
        let outcome = android
            .stream(
                &LogRequest::new(android_device(), "com.example.app", "app"),
                |entry| {
                    android_entries.push(entry);
                    Ok(())
                },
            )
            .expect("Android stream");
        assert_eq!(outcome.entries, 1);
        assert_eq!(android_entries[0].message, "android ready");

        let (_temporary_simulator, simulator_tool) = fake_log_tool();
        let simulator =
            LogService::new(SystemExecutor, ".").with_tools(&simulator_tool, &simulator_tool);
        let mut simulator_entries = Vec::new();
        let outcome = simulator
            .stream(
                &LogRequest::new(simulator_device(), "com.example.app", "Ferry App"),
                |entry| {
                    simulator_entries.push(entry);
                    Ok(())
                },
            )
            .expect("Simulator stream");
        assert_eq!(outcome.entries, 1);
        assert_eq!(simulator_entries[0].message, "ios ready");
    }

    #[test]
    fn cancellation_terminates_the_complete_fake_tool_process_group() {
        let (temporary, tool) = fake_log_tool();
        let descendant = Utf8PathBuf::from_path_buf(temporary.path().join("descendant.pid"))
            .expect("UTF-8 descendant path");
        let cancelled = AtomicBool::new(false);
        let command = ToolCommand::new(&tool, ".", "test cancellable log stream")
            .arg("logcat")
            .env("RUSTFERRY_FAKE_HOLD", "1")
            .env("RUSTFERRY_FAKE_DESCENDANT_PID", descendant.as_str())
            .output_limit(1_024);
        let error = stream_command_lines(
            &command,
            1_024,
            4,
            || cancelled.load(Ordering::SeqCst),
            |_| {
                cancelled.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("stream cancellation");
        assert!(matches!(error, DeploymentError::Cancelled { .. }));

        let process_id = fs::read_to_string(&descendant)
            .expect("descendant PID")
            .trim()
            .parse::<u32>()
            .expect("numeric descendant PID");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let alive = Command::new("/bin/kill")
                .args(["-0", &process_id.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant")
                .success();
            if !alive {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fake-tool descendant survived stream cancellation"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn bounded_buffer_evicts_old_entries_by_count_and_bytes() {
        let mut buffer = BoundedLogBuffer::new(2, 128).expect("buffer");
        for message in ["one", "two", "three"] {
            buffer.push(LogEntry {
                timestamp: "1".to_owned(),
                level: LogLevel::Info,
                target: "app".to_owned(),
                message: message.to_owned(),
                process_id: Some(1),
            });
        }
        let entries = buffer.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "two");
    }

    #[test]
    fn apple_ndjson_parser_normalizes_fields() {
        let entries = parse_apple_logs(
            "{\"timestamp\":\"2026-08-01T12:00:00Z\",\"messageType\":\"Error\",\"subsystem\":\"com.example\",\"eventMessage\":\"boom\",\"processID\":9}\n",
        )
        .expect("parse");
        assert_eq!(entries[0].level, LogLevel::Error);
        assert_eq!(entries[0].process_id, Some(9));
    }
}
