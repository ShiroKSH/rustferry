use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::process_control::{
    BoundedOutputCapture, DEFAULT_PROCESS_OUTPUT_LIMIT, OutputCaptureStatus,
};
use rustferry_remote::CancellationToken;
use serde::{Deserialize, Serialize};

use crate::{AppleError, error::io_error};

/// Default deadline for one external Apple build-tool invocation.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_mins(30);
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(1);

thread_local! {
    static COMMAND_CANCELLATION: RefCell<Option<CancellationToken>> = const { RefCell::new(None) };
}

struct CommandCancellationBinding {
    previous: Option<CancellationToken>,
}

impl Drop for CommandCancellationBinding {
    fn drop(&mut self) {
        COMMAND_CANCELLATION.with(|binding| {
            binding.replace(self.previous.take());
        });
    }
}

/// Run a closure with cooperative cancellation enabled for Apple commands on this thread.
///
/// Nested bindings restore the previous token, including when the closure unwinds. Bindings on
/// other threads are independent.
pub fn with_command_cancellation<T>(
    cancellation: &CancellationToken,
    operation: impl FnOnce() -> T,
) -> T {
    let previous = COMMAND_CANCELLATION.with(|binding| binding.replace(Some(cancellation.clone())));
    let _binding = CommandCancellationBinding { previous };
    operation()
}

fn command_cancellation_requested() -> bool {
    COMMAND_CANCELLATION.with(|binding| {
        binding
            .borrow()
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    })
}

/// One safely tokenized external command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// Human-readable build stage.
    pub stage: String,
    /// Executable path; never a shell expression.
    pub program: Utf8PathBuf,
    /// Individual process arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub current_dir: Utf8PathBuf,
    /// Additional environment variables.
    pub environment: BTreeMap<String, String>,
    /// Argument positions hidden from rendered plans and logs.
    pub redacted_args: BTreeSet<usize>,
    /// Environment names hidden from rendered plans and logs.
    pub redacted_environment: BTreeSet<String>,
    /// Maximum runtime in seconds.
    pub timeout_seconds: u64,
}

impl CommandSpec {
    /// Construct a command with no arguments or environment overrides.
    pub fn new(
        stage: impl Into<String>,
        program: impl Into<Utf8PathBuf>,
        current_dir: impl Into<Utf8PathBuf>,
    ) -> Self {
        Self {
            stage: stage.into(),
            program: program.into(),
            args: Vec::new(),
            current_dir: current_dir.into(),
            environment: BTreeMap::new(),
            redacted_args: BTreeSet::new(),
            redacted_environment: BTreeSet::new(),
            timeout_seconds: DEFAULT_COMMAND_TIMEOUT.as_secs(),
        }
    }

    /// Return the executable and arguments with sensitive values removed.
    pub fn redacted_argv(&self) -> Vec<String> {
        std::iter::once(self.program.to_string())
            .chain(self.args.iter().enumerate().map(|(index, argument)| {
                if self.redacted_args.contains(&index) {
                    "<redacted>".to_owned()
                } else {
                    argument.clone()
                }
            }))
            .collect()
    }

    /// Return environment overrides with sensitive values removed.
    pub fn redacted_environment(&self) -> BTreeMap<String, String> {
        self.environment
            .iter()
            .map(|(name, value)| {
                let rendered = if self.redacted_environment.contains(name) {
                    "<redacted>".to_owned()
                } else {
                    value.clone()
                };
                (name.clone(), rendered)
            })
            .collect()
    }
}

/// Captured output from a successful external command.
#[derive(Debug)]
pub struct CommandOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit status.
    pub status: ExitStatus,
}

/// Run one command without a shell, capture both streams, enforce a timeout, and optionally log it.
///
/// # Errors
///
/// Returns [`AppleError`] when the command cannot start, times out, exits
/// unsuccessfully, its output cannot be read, or its redacted log cannot be written.
pub fn run_command(
    spec: &CommandSpec,
    log_path: Option<&Utf8Path>,
) -> Result<CommandOutput, AppleError> {
    run_command_with_output_limit(spec, log_path, DEFAULT_PROCESS_OUTPUT_LIMIT)
}

#[allow(clippy::too_many_lines)]
fn run_command_with_output_limit(
    spec: &CommandSpec,
    log_path: Option<&Utf8Path>,
    output_limit: usize,
) -> Result<CommandOutput, AppleError> {
    if let Some(path) = log_path
        && let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create command log directory", parent, source))?;
    }

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.current_dir)
        .envs(&spec.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);

    let mut child = command.spawn().map_err(|source| AppleError::CommandSpawn {
        stage: spec.stage.clone(),
        program: spec.program.clone(),
        source,
    })?;
    let process_group = child.id();
    let _process_group_guard = match rustferry_core::process_control::track_child(&child) {
        Ok(guard) => guard,
        Err(source) => {
            terminate_process_tree(&mut child, process_group);
            return Err(AppleError::CommandSpawn {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
                source,
            });
        }
    };
    let mut capture = match capture_output(&mut child, spec, output_limit) {
        Ok(capture) => capture,
        Err(error) => {
            terminate_process_tree(&mut child, process_group);
            return Err(error);
        }
    };

    let started = Instant::now();
    let timeout = Duration::from_secs(spec.timeout_seconds.max(1));
    let mut status = None;
    loop {
        if rustferry_core::process_control::interrupt_requested()
            || command_cancellation_requested()
        {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            return Err(AppleError::CommandInterrupted {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
            });
        }
        let capture_status = match capture.poll() {
            Ok(capture_status) => capture_status,
            Err(source) => {
                terminate_process_tree(&mut child, process_group);
                return Err(reader_error("read command output", log_path, source));
            }
        };
        if let OutputCaptureStatus::LimitExceeded(stream) = capture_status {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            let output = capture.into_partial_output();
            if let Some(path) = log_path {
                write_log(spec, path, &output.stdout, &output.stderr)?;
            }
            return Err(AppleError::ProcessOutputTooLarge {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
                stream: stream.to_string(),
                limit_bytes: output_limit,
                log: log_path.map(Utf8Path::to_owned),
            });
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit_status)) => status = Some(exit_status),
                Ok(None) => {}
                Err(source) => {
                    terminate_process_tree(&mut child, process_group);
                    return Err(AppleError::CommandSpawn {
                        stage: spec.stage.clone(),
                        program: spec.program.clone(),
                        source,
                    });
                }
            }
        }
        if status.is_some() && capture.is_complete() {
            break;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            let output = capture.into_partial_output();
            if let Some(path) = log_path {
                write_log(spec, path, &output.stdout, &output.stderr)?;
            }
            return Err(AppleError::CommandTimedOut {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
                log: log_path.map(Utf8Path::to_owned),
            });
        }
        if capture.is_complete() {
            thread::sleep(remaining.min(OUTPUT_POLL_INTERVAL));
        } else if let Err(source) = capture.wait_timeout(remaining.min(OUTPUT_POLL_INTERVAL)) {
            terminate_process_tree(&mut child, process_group);
            return Err(reader_error("read command output", log_path, source));
        }
    }

    let output = capture.into_partial_output();
    if let Some(path) = log_path {
        write_log(spec, path, &output.stdout, &output.stderr)?;
    }
    let status = status.expect("completed capture requires a reaped child");
    if !status.success() {
        return Err(AppleError::CommandFailed {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            status: status.code().map_or_else(
                || "terminated by signal".to_owned(),
                |code| code.to_string(),
            ),
            summary: command_summary(&output.stdout, &output.stderr),
            log: log_path.map(|path| Box::new(path.to_owned())),
        });
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        status,
    })
}

fn capture_output(
    child: &mut Child,
    spec: &CommandSpec,
    output_limit: usize,
) -> Result<BoundedOutputCapture, AppleError> {
    let stdout = child.stdout.take().ok_or_else(|| {
        io_error(
            "capture command stdout",
            &spec.program,
            std::io::Error::other("spawned process has no piped stdout"),
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        io_error(
            "capture command stderr",
            &spec.program,
            std::io::Error::other("spawned process has no piped stderr"),
        )
    })?;
    BoundedOutputCapture::spawn(stdout, stderr, output_limit)
        .map_err(|source| io_error("start command output readers", &spec.program, source))
}

fn drain_after_termination(capture: &mut BoundedOutputCapture) {
    let started = Instant::now();
    while !capture.is_complete() {
        let remaining = OUTPUT_DRAIN_GRACE.saturating_sub(started.elapsed());
        if remaining.is_zero()
            || capture
                .wait_timeout(remaining.min(OUTPUT_POLL_INTERVAL))
                .is_err()
        {
            break;
        }
    }
}

fn reader_error(
    operation: &'static str,
    log_path: Option<&Utf8Path>,
    source: std::io::Error,
) -> AppleError {
    let error_path =
        log_path.map_or_else(|| Utf8PathBuf::from("<command-output>"), Utf8Path::to_owned);
    io_error(operation, error_path, source)
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
    {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &format!("-{process_group}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
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

fn write_log(
    spec: &CommandSpec,
    path: &Utf8Path,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), AppleError> {
    let argv = spec
        .redacted_argv()
        .into_iter()
        .map(|argument| format!("{argument:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    let environment = spec
        .redacted_environment()
        .into_iter()
        .map(|(name, value)| format!("{name}={value:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let contents = format!(
        "stage: {}\ncwd: {}\ncommand: {}\nenvironment:\n{}\n\n[stdout]\n{}\n\n[stderr]\n{}\n",
        spec.stage,
        spec.current_dir,
        argv,
        environment,
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    fs::write(path, contents).map_err(|source| io_error("write command log", path, source))
}

fn command_summary(stdout: &[u8], stderr: &[u8]) -> String {
    let preferred = if stderr.is_empty() { stdout } else { stderr };
    let text = String::from_utf8_lossy(preferred);
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(4)
        .collect::<Vec<_>>();
    let mut summary = lines.into_iter().rev().collect::<Vec<_>>().join(" | ");
    if summary.len() > 800 {
        summary.truncate(800);
        summary.push('…');
    }
    if summary.is_empty() {
        "the tool produced no diagnostic output".to_owned()
    } else {
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const TEST_OUTPUT_LIMIT: usize = 64 * 1024;

    #[test]
    fn rendered_command_redacts_arguments_and_environment() {
        let mut command = CommandSpec::new("sign", "/usr/bin/codesign", "/project");
        command.args = vec!["--sign".into(), "secret-identity".into(), "App.app".into()];
        command.redacted_args.insert(1);
        command.environment.insert("TOKEN".into(), "secret".into());
        command.redacted_environment.insert("TOKEN".into());
        assert_eq!(
            command.redacted_argv(),
            ["/usr/bin/codesign", "--sign", "<redacted>", "App.app"]
        );
        assert_eq!(command.redacted_environment()["TOKEN"], "<redacted>");
    }

    #[cfg(unix)]
    #[test]
    fn timeout_is_not_held_open_by_descendant_pipes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let mut command = CommandSpec::new("descendant timeout", "/bin/sh", &root);
        command.args = vec!["-c".into(), "sleep 10 & exit 0".into()];
        command.timeout_seconds = 1;
        let started = Instant::now();
        let error = run_command(&command, Some(&root.join("command.log"))).unwrap_err();
        assert!(matches!(error, AppleError::CommandTimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_stops_subprocess_group_within_a_bounded_time() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let log_path = root.join("command.log");
        let mut command = CommandSpec::new("cancel subprocess", "/bin/sh", &root);
        command.args = vec!["-c".into(), "sleep 10 & wait".into()];
        command.timeout_seconds = 10;
        let cancellation = CancellationToken::new();
        let cancellation_request = cancellation.clone();
        let request = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancellation_request.cancel();
        });

        let started = Instant::now();
        let error =
            with_command_cancellation(&cancellation, || run_command(&command, Some(&log_path)))
                .unwrap_err();
        request.join().unwrap();

        assert!(matches!(error, AppleError::CommandInterrupted { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(!log_path.exists());
    }

    #[test]
    fn cancellation_scope_restores_nested_binding_after_unwind() {
        let outer = CancellationToken::new();
        outer.cancel();
        let inner = CancellationToken::new();

        assert!(!command_cancellation_requested());
        with_command_cancellation(&outer, || {
            assert!(command_cancellation_requested());
            assert!(
                !thread::spawn(command_cancellation_requested)
                    .join()
                    .unwrap()
            );
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_command_cancellation(&inner, || {
                    assert!(!command_cancellation_requested());
                    panic!("exercise cancellation binding unwind");
                });
            }));
            assert!(unwind.is_err());
            assert!(command_cancellation_requested());
        });
        assert!(!command_cancellation_requested());
    }

    #[cfg(unix)]
    #[test]
    fn oversized_stderr_is_typed_and_log_is_bounded() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let log_path = root.join("command.log");
        let mut command = CommandSpec::new("oversized stderr", "/bin/sh", &root);
        command.args = vec!["-c".into(), "exec /usr/bin/yes overflow >&2".into()];
        command.timeout_seconds = 5;
        let started = Instant::now();
        let error = run_command_with_output_limit(&command, Some(&log_path), TEST_OUTPUT_LIMIT)
            .unwrap_err();
        assert!(matches!(
            error,
            AppleError::ProcessOutputTooLarge {
                ref stream,
                limit_bytes: TEST_OUTPUT_LIMIT,
                ..
            } if stream == "stderr"
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(fs::metadata(log_path).unwrap().len() <= (TEST_OUTPUT_LIMIT + 4096) as u64);
    }
}
