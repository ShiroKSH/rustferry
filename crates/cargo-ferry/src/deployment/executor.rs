use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};

use super::{DeploymentError, DeploymentResult};

const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(20);
const STREAM_DRAIN_GRACE: Duration = Duration::from_secs(1);
type ReaderResult = Result<(Vec<u8>, bool), std::io::Error>;

#[derive(Debug)]
enum LineReaderEvent {
    Line(Vec<u8>),
    LineLimitExceeded,
    Finished,
    Failed(std::io::Error),
}

/// External platform command with argument boundaries preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCommand {
    /// Executable name or absolute path. PATH lookup is allowed for a bare name.
    pub program: Utf8PathBuf,
    /// Argument array; never interpreted by a shell.
    pub arguments: Vec<OsString>,
    /// Existing working directory.
    pub current_directory: Utf8PathBuf,
    /// Non-secret environment overrides required by an installed toolchain.
    pub environment: BTreeMap<String, OsString>,
    /// Overall child-process deadline.
    pub timeout: Duration,
    /// Per-stream capture limit.
    pub output_limit: usize,
    /// Stable operation name used in diagnostics.
    pub operation: &'static str,
}

impl ToolCommand {
    /// Construct a command with a 30-second deadline and bounded output.
    pub fn new(
        program: impl Into<Utf8PathBuf>,
        current_directory: impl Into<Utf8PathBuf>,
        operation: &'static str,
    ) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: current_directory.into(),
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(30),
            output_limit: DEFAULT_OUTPUT_LIMIT,
            operation,
        }
    }

    /// Append one argument without shell parsing.
    #[must_use]
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Append arguments without shell parsing.
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    /// Override a non-secret environment value.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set the command deadline.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum bytes retained from each output stream.
    #[must_use]
    pub const fn output_limit(mut self, output_limit: usize) -> Self {
        self.output_limit = output_limit;
        self
    }
}

/// Bounded result of one external command.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    /// Process exit status.
    pub status: ExitStatus,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Whether stdout exceeded the configured capture limit.
    pub stdout_truncated: bool,
    /// Whether stderr exceeded the configured capture limit.
    pub stderr_truncated: bool,
}

/// Injectable command boundary used by deployment services and deterministic tests.
pub trait CommandExecutor {
    /// Execute one array-based command with bounded output and cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for missing tools, process I/O, timeout, or cancellation.
    fn execute(&self, command: &ToolCommand) -> DeploymentResult<CommandOutput>;
}

/// Real process executor using an isolated child process group/job.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemExecutor;

impl CommandExecutor for SystemExecutor {
    #[allow(clippy::too_many_lines)]
    fn execute(&self, spec: &ToolCommand) -> DeploymentResult<CommandOutput> {
        if !spec.current_directory.is_dir() {
            return Err(DeploymentError::Io {
                action: "use command working directory",
                path: spec.current_directory.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "working directory does not exist",
                ),
            });
        }
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.arguments)
            .current_dir(&spec.current_directory)
            .envs(&spec.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        let mut child = command.spawn().map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                DeploymentError::ToolMissing {
                    tool: spec.program.to_string(),
                    help: tool_help(&spec.program),
                }
            } else {
                DeploymentError::Io {
                    action: "start deployment tool",
                    path: spec.program.clone(),
                    source,
                }
            }
        })?;
        let process_group = child.id();
        let guard = rustferry_core::process_control::track_child(&child).map_err(|source| {
            terminate_process_tree(&mut child, process_group);
            DeploymentError::Io {
                action: "contain deployment process tree",
                path: spec.program.clone(),
                source,
            }
        })?;
        let stdout = child.stdout.take().ok_or_else(|| DeploymentError::Io {
            action: "capture deployment stdout",
            path: spec.program.clone(),
            source: std::io::Error::other("child stdout was not piped"),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| DeploymentError::Io {
            action: "capture deployment stderr",
            path: spec.program.clone(),
            source: std::io::Error::other("child stderr was not piped"),
        })?;
        let stdout_reader = spawn_reader(stdout, spec.output_limit);
        let stderr_reader = spawn_reader(stderr, spec.output_limit);
        let started = Instant::now();
        let status = loop {
            if rustferry_core::process_control::interrupt_requested() {
                terminate_process_tree(&mut child, process_group);
                return Err(DeploymentError::Cancelled {
                    tool: spec.program.to_string(),
                    operation: spec.operation,
                });
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < spec.timeout => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    terminate_process_tree(&mut child, process_group);
                    return Err(DeploymentError::CommandTimedOut {
                        tool: spec.program.to_string(),
                        operation: spec.operation,
                        timeout_seconds: spec.timeout.as_secs(),
                    });
                }
                Err(source) => {
                    terminate_process_tree(&mut child, process_group);
                    return Err(DeploymentError::Io {
                        action: "wait for deployment tool",
                        path: spec.program.clone(),
                        source,
                    });
                }
            }
        };
        let stdout_result = receive_reader(
            &stdout_reader,
            started,
            spec.timeout,
            &spec.program,
            "read deployment stdout",
        );
        let (stdout, stdout_truncated) = match stdout_result {
            Ok(output) => output,
            Err(error) => {
                terminate_process_tree(&mut child, process_group);
                drop(guard);
                return Err(error);
            }
        };
        let stderr_result = receive_reader(
            &stderr_reader,
            started,
            spec.timeout,
            &spec.program,
            "read deployment stderr",
        );
        let (stderr, stderr_truncated) = match stderr_result {
            Ok(output) => output,
            Err(error) => {
                terminate_process_tree(&mut child, process_group);
                drop(guard);
                return Err(error);
            }
        };
        drop(guard);
        Ok(CommandOutput {
            status,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

pub(crate) fn stream_command_lines<OnLine, IsCancelled>(
    spec: &ToolCommand,
    max_line_bytes: usize,
    max_pending_lines: usize,
    is_cancelled: IsCancelled,
    mut on_line: OnLine,
) -> DeploymentResult<CommandOutput>
where
    OnLine: FnMut(&[u8]) -> DeploymentResult<()>,
    IsCancelled: Fn() -> bool,
{
    validate_stream_bounds(spec, max_line_bytes, max_pending_lines)?;
    let mut stream = start_line_stream(spec, max_line_bytes, max_pending_lines)?;
    let (status, stderr, stderr_truncated) = supervise_line_stream(
        spec,
        max_line_bytes,
        &mut stream,
        &is_cancelled,
        &mut on_line,
    )?;
    stream.child.complete();
    Ok(CommandOutput {
        status,
        stdout: Vec::new(),
        stderr,
        stdout_truncated: false,
        stderr_truncated,
    })
}

struct ActiveLineStream {
    child: ActiveStreamChild,
    lines: Receiver<LineReaderEvent>,
    stderr: Receiver<ReaderResult>,
}

#[derive(Default)]
struct LineStreamState {
    status: Option<ExitStatus>,
    exited_at: Option<Instant>,
    stdout_finished: bool,
    stderr_output: Option<(Vec<u8>, bool)>,
}

fn validate_stream_bounds(
    spec: &ToolCommand,
    max_line_bytes: usize,
    max_pending_lines: usize,
) -> DeploymentResult<()> {
    if !spec.current_directory.is_dir() {
        return Err(DeploymentError::Io {
            action: "use command working directory",
            path: spec.current_directory.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "working directory does not exist",
            ),
        });
    }
    if max_line_bytes == 0 || max_pending_lines == 0 {
        return Err(DeploymentError::Unsupported {
            message: "streaming output bounds must be non-zero".to_owned(),
            help: "Set positive line-size and pending-line limits.".to_owned(),
        });
    }
    Ok(())
}

fn start_line_stream(
    spec: &ToolCommand,
    max_line_bytes: usize,
    max_pending_lines: usize,
) -> DeploymentResult<ActiveLineStream> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.arguments)
        .current_dir(&spec.current_directory)
        .envs(&spec.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let child = command.spawn().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            DeploymentError::ToolMissing {
                tool: spec.program.to_string(),
                help: tool_help(&spec.program),
            }
        } else {
            DeploymentError::Io {
                action: "start deployment tool",
                path: spec.program.clone(),
                source,
            }
        }
    })?;
    let mut child = ActiveStreamChild::new(child, &spec.program)?;
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| DeploymentError::Io {
            action: "capture streamed deployment stdout",
            path: spec.program.clone(),
            source: std::io::Error::other("child stdout was not piped"),
        })?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or_else(|| DeploymentError::Io {
            action: "capture streamed deployment stderr",
            path: spec.program.clone(),
            source: std::io::Error::other("child stderr was not piped"),
        })?;
    let lines = spawn_line_reader(stdout, max_line_bytes, max_pending_lines).map_err(|source| {
        DeploymentError::Io {
            action: "start streamed deployment stdout reader",
            path: spec.program.clone(),
            source,
        }
    })?;
    Ok(ActiveLineStream {
        child,
        lines,
        stderr: spawn_reader(stderr, spec.output_limit),
    })
}

fn supervise_line_stream<OnLine, IsCancelled>(
    spec: &ToolCommand,
    max_line_bytes: usize,
    stream: &mut ActiveLineStream,
    is_cancelled: &IsCancelled,
    on_line: &mut OnLine,
) -> DeploymentResult<(ExitStatus, Vec<u8>, bool)>
where
    OnLine: FnMut(&[u8]) -> DeploymentResult<()>,
    IsCancelled: Fn() -> bool,
{
    let mut state = LineStreamState::default();
    loop {
        if is_cancelled() {
            return Err(DeploymentError::Cancelled {
                tool: spec.program.to_string(),
                operation: spec.operation,
            });
        }
        poll_stream_line(spec, max_line_bytes, stream, &mut state, on_line)?;
        poll_stream_stderr(spec, stream, &mut state)?;
        poll_stream_child(spec, stream, &mut state)?;
        if state.status.is_some() && state.stdout_finished && state.stderr_output.is_some() {
            let status = state
                .status
                .take()
                .expect("completed stream has an exit status");
            let (stderr, truncated) = state
                .stderr_output
                .take()
                .expect("completed stream has stderr output");
            return Ok((status, stderr, truncated));
        }
        if state
            .exited_at
            .is_some_and(|exit| exit.elapsed() >= STREAM_DRAIN_GRACE)
        {
            return Err(DeploymentError::CommandTimedOut {
                tool: spec.program.to_string(),
                operation: "drain streamed deployment tool output",
                timeout_seconds: STREAM_DRAIN_GRACE.as_secs(),
            });
        }
    }
}

fn poll_stream_line<OnLine>(
    spec: &ToolCommand,
    max_line_bytes: usize,
    stream: &ActiveLineStream,
    state: &mut LineStreamState,
    on_line: &mut OnLine,
) -> DeploymentResult<()>
where
    OnLine: FnMut(&[u8]) -> DeploymentResult<()>,
{
    match stream.lines.recv_timeout(STREAM_POLL_INTERVAL) {
        Ok(event) => handle_line_reader_event(spec, max_line_bytes, event, state, on_line),
        Err(RecvTimeoutError::Timeout) => Ok(()),
        Err(RecvTimeoutError::Disconnected) if state.stdout_finished => Ok(()),
        Err(RecvTimeoutError::Disconnected) => Err(DeploymentError::Io {
            action: "read streamed deployment stdout",
            path: spec.program.clone(),
            source: std::io::Error::other("stream reader disconnected before EOF"),
        }),
    }
}

fn handle_line_reader_event<OnLine>(
    spec: &ToolCommand,
    max_line_bytes: usize,
    event: LineReaderEvent,
    state: &mut LineStreamState,
    on_line: &mut OnLine,
) -> DeploymentResult<()>
where
    OnLine: FnMut(&[u8]) -> DeploymentResult<()>,
{
    match event {
        LineReaderEvent::Line(line) => on_line(&line),
        LineReaderEvent::LineLimitExceeded => Err(DeploymentError::InvalidToolOutput {
            tool: "platform log stream",
            operation: spec.operation,
            message: format!("one output line exceeded the {max_line_bytes}-byte limit"),
        }),
        LineReaderEvent::Finished => {
            state.stdout_finished = true;
            Ok(())
        }
        LineReaderEvent::Failed(source) => Err(DeploymentError::Io {
            action: "read streamed deployment stdout",
            path: spec.program.clone(),
            source,
        }),
    }
}

fn poll_stream_stderr(
    spec: &ToolCommand,
    stream: &ActiveLineStream,
    state: &mut LineStreamState,
) -> DeploymentResult<()> {
    if state.stderr_output.is_some() {
        return Ok(());
    }
    match stream.stderr.try_recv() {
        Ok(Ok(output)) => state.stderr_output = Some(output),
        Ok(Err(source)) => {
            return Err(DeploymentError::Io {
                action: "read streamed deployment stderr",
                path: spec.program.clone(),
                source,
            });
        }
        Err(TryRecvError::Empty) => {}
        Err(TryRecvError::Disconnected) => {
            return Err(DeploymentError::Io {
                action: "read streamed deployment stderr",
                path: spec.program.clone(),
                source: std::io::Error::other("stderr reader disconnected before EOF"),
            });
        }
    }
    Ok(())
}

fn poll_stream_child(
    spec: &ToolCommand,
    stream: &mut ActiveLineStream,
    state: &mut LineStreamState,
) -> DeploymentResult<()> {
    if state.status.is_some() {
        return Ok(());
    }
    match stream.child.child.try_wait() {
        Ok(Some(status)) => {
            state.status = Some(status);
            state.exited_at = Some(Instant::now());
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(source) => Err(DeploymentError::Io {
            action: "wait for streamed deployment tool",
            path: spec.program.clone(),
            source,
        }),
    }
}

struct ActiveStreamChild {
    child: Child,
    process_group: u32,
    containment: Option<rustferry_core::process_control::ProcessGroupGuard>,
    armed: bool,
}

impl ActiveStreamChild {
    fn new(mut child: Child, program: &Utf8Path) -> DeploymentResult<Self> {
        let process_group = child.id();
        let containment =
            rustferry_core::process_control::track_child(&child).map_err(|source| {
                terminate_process_tree(&mut child, process_group);
                DeploymentError::Io {
                    action: "contain streamed deployment process tree",
                    path: program.to_owned(),
                    source,
                }
            })?;
        Ok(Self {
            child,
            process_group,
            containment: Some(containment),
            armed: true,
        })
    }

    fn complete(&mut self) {
        #[cfg(unix)]
        terminate_unix_process_group(self.process_group);
        self.armed = false;
        self.containment.take();
    }
}

impl Drop for ActiveStreamChild {
    fn drop(&mut self) {
        if self.armed {
            terminate_process_tree(&mut self.child, self.process_group);
        }
        self.containment.take();
    }
}

fn spawn_line_reader(
    mut reader: impl Read + Send + 'static,
    max_line_bytes: usize,
    max_pending_lines: usize,
) -> std::io::Result<Receiver<LineReaderEvent>> {
    let (sender, receiver) = mpsc::sync_channel(max_pending_lines);
    thread::Builder::new()
        .name("rustferry-stdout-lines".to_owned())
        .spawn(move || {
            let mut pending = Vec::new();
            let mut chunk = [0_u8; 16 * 1024];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        if !pending.is_empty() && !send_line(&sender, &mut pending) {
                            return;
                        }
                        let _ = sender.send(LineReaderEvent::Finished);
                        return;
                    }
                    Ok(read) => {
                        for &byte in &chunk[..read] {
                            if byte == b'\n' {
                                if !send_line(&sender, &mut pending) {
                                    return;
                                }
                            } else {
                                if pending.len() == max_line_bytes {
                                    let _ = sender.send(LineReaderEvent::LineLimitExceeded);
                                    return;
                                }
                                pending.push(byte);
                            }
                        }
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(source) => {
                        let _ = sender.send(LineReaderEvent::Failed(source));
                        return;
                    }
                }
            }
        })
        .map(|_| receiver)
}

fn send_line(sender: &mpsc::SyncSender<LineReaderEvent>, pending: &mut Vec<u8>) -> bool {
    if pending.last() == Some(&b'\r') {
        pending.pop();
    }
    let line = std::mem::take(pending);
    sender.send(LineReaderEvent::Line(line)).is_ok()
}

fn spawn_reader(mut reader: impl Read + Send + 'static, limit: usize) -> Receiver<ReaderResult> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut truncated = false;
        let mut chunk = [0_u8; 16 * 1024];
        let result = loop {
            match reader.read(&mut chunk) {
                Ok(0) => break Ok((bytes, truncated)),
                Ok(read) => {
                    let remaining = limit.saturating_sub(bytes.len());
                    let retained = read.min(remaining);
                    bytes.extend_from_slice(&chunk[..retained]);
                    truncated |= retained < read;
                }
                Err(source) => break Err(source),
            }
        };
        let _ = sender.send(result);
    });
    receiver
}

fn receive_reader(
    receiver: &Receiver<ReaderResult>,
    started: Instant,
    timeout: Duration,
    program: &Utf8Path,
    action: &'static str,
) -> DeploymentResult<(Vec<u8>, bool)> {
    loop {
        if rustferry_core::process_control::interrupt_requested() {
            return Err(DeploymentError::Cancelled {
                tool: program.to_string(),
                operation: "drain deployment tool output",
            });
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(DeploymentError::CommandTimedOut {
                tool: program.to_string(),
                operation: "drain deployment tool output",
                timeout_seconds: timeout.as_secs(),
            });
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(Ok(output)) => return Ok(output),
            Ok(Err(source)) => {
                return Err(DeploymentError::Io {
                    action,
                    path: program.to_owned(),
                    source,
                });
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(DeploymentError::Io {
                    action,
                    path: program.to_owned(),
                    source: std::io::Error::other("output reader disconnected"),
                });
            }
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn terminate_process_tree(child: &mut Child, process_group: u32) {
    #[cfg(unix)]
    terminate_unix_process_group(process_group);
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill.exe")
            .args(["/PID", &process_group.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_unix_process_group(process_group: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{process_group}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn tool_help(program: &Utf8Path) -> String {
    match program.file_name().unwrap_or_default() {
        "adb" | "adb.exe" => {
            "Install Android SDK Platform-Tools and add its platform-tools directory to PATH."
                .to_owned()
        }
        "xcrun" => "Install full Xcode and select its developer directory.".to_owned(),
        "security" => "Use macOS with an installed Apple development certificate.".to_owned(),
        _ => format!("Install `{program}` or configure its absolute path."),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn command_builder_preserves_argument_boundaries() {
        let command = ToolCommand::new("adb", ".", "test")
            .args(["-s", "serial with spaces", "shell"])
            .arg("echo;not-a-shell");
        assert_eq!(command.arguments.len(), 4);
        assert_eq!(command.arguments[1], "serial with spaces");
        assert_eq!(command.arguments[3], "echo;not-a-shell");
    }

    #[test]
    fn bounded_line_reader_reports_the_limit_before_disconnect_repeatedly() {
        for iteration in 0..64 {
            let events = spawn_line_reader(Cursor::new(b"0123456789\n"), 8, 1)
                .expect("spawn bounded line reader");
            let event = events
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("reader iteration {iteration} failed: {error}"));
            assert!(
                matches!(event, LineReaderEvent::LineLimitExceeded),
                "reader iteration {iteration} returned {event:?}"
            );
        }
    }

    #[test]
    fn line_limit_event_maps_to_invalid_tool_output() {
        let spec = ToolCommand::new("fake-log-tool", ".", "test bounded log stream");
        let mut state = LineStreamState::default();
        let error = handle_line_reader_event(
            &spec,
            8,
            LineReaderEvent::LineLimitExceeded,
            &mut state,
            &mut |_| panic!("line callback must not run for an oversized line"),
        )
        .expect_err("oversized line event must be rejected");
        assert!(matches!(
            error,
            DeploymentError::InvalidToolOutput {
                tool: "platform log stream",
                operation: "test bounded log stream",
                ref message,
            } if message == "one output line exceeded the 8-byte limit"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn output_drain_timeout_terminates_the_child_process_group() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let directory = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).expect("UTF-8");
        let script = directory.join("holds-output-open.sh");
        let pid_file = directory.join("descendant.pid");
        fs::write(
            &script,
            "#!/bin/sh\n(while :; do sleep 10; done) &\nprintf '%s\\n' \"$!\" > \"$RUSTFERRY_TEST_DESCENDANT_PID\"\nexit 0\n",
        )
        .expect("write helper script");
        let mut permissions = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("make helper executable");

        let error = SystemExecutor
            .execute(
                &ToolCommand::new(&script, &directory, "test output drain")
                    .env("RUSTFERRY_TEST_DESCENDANT_PID", pid_file.as_str())
                    .timeout(Duration::from_secs(3)),
            )
            .expect_err("inherited output pipe must hit the bounded drain timeout");
        assert!(matches!(error, DeploymentError::CommandTimedOut { .. }));

        let process_id = fs::read_to_string(&pid_file)
            .expect("descendant PID")
            .trim()
            .parse::<u32>()
            .expect("numeric PID");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let exists = Command::new("/bin/kill")
                .arg("-0")
                .arg(process_id.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant")
                .success();
            if !exists || process_is_zombie(process_id) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "descendant remained alive after output-drain timeout"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    fn process_is_zombie(process_id: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{process_id}/status"))
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.strip_prefix("State:")
                    .is_some_and(|state| state.trim_start().starts_with('Z'))
            })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    const fn process_is_zombie(_: u32) -> bool {
        false
    }
}
