//! Bounded subprocess execution for the worker's fixed Apple tools.

#[cfg(unix)]
use std::ffi::OsStr;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Read,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

const MIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_TIMEOUT: Duration = Duration::from_hours(1);
const MIN_OUTPUT_BYTES: usize = 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Absolute, allowlisted executables used by the signing worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerProgram {
    /// Apple code-signing tool.
    Codesign,
    /// Apple Security framework command-line adapter.
    Security,
    /// Xcode build and archive exporter.
    Xcodebuild,
    /// Apple plist utility.
    Plutil,
    /// Apple archive utility.
    Ditto,
    /// Xcode tool dispatcher used for fixed inspection commands.
    Xcrun,
}

impl WorkerProgram {
    /// Fixed absolute executable path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Codesign => "/usr/bin/codesign",
            Self::Security => "/usr/bin/security",
            Self::Xcodebuild => "/usr/bin/xcodebuild",
            Self::Plutil => "/usr/bin/plutil",
            Self::Ditto => "/usr/bin/ditto",
            Self::Xcrun => "/usr/bin/xcrun",
        }
    }
}

/// Resource bounds for one subprocess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandPolicy {
    /// Wall-clock deadline.
    pub timeout: Duration,
    /// Combined per-stream capture limit.
    pub max_output_bytes: usize,
    /// Start from an empty environment before applying explicit variables.
    pub clear_environment: bool,
}

impl CommandPolicy {
    /// Validate explicit bounds.
    ///
    /// # Errors
    ///
    /// Rejects ineffective or unbounded limits.
    pub fn new(
        timeout: Duration,
        max_output_bytes: usize,
        clear_environment: bool,
    ) -> Result<Self, WorkerCommandError> {
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&timeout) {
            return Err(WorkerCommandError::InvalidPolicy);
        }
        if !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&max_output_bytes) {
            return Err(WorkerCommandError::InvalidPolicy);
        }
        Ok(Self {
            timeout,
            max_output_bytes,
            clear_environment,
        })
    }
}

impl Default for CommandPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_mins(10),
            max_output_bytes: 2 * 1024 * 1024,
            clear_environment: true,
        }
    }
}

/// Captured successful output. Contents are never included in errors.
pub struct WorkerCommandOutput {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// Successful exit status.
    pub status: ExitStatus,
}

impl Drop for WorkerCommandOutput {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
    }
}

/// Secret-free subprocess failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerCommandError {
    /// Policy bounds are unsafe.
    InvalidPolicy,
    /// Executable could not be started.
    Spawn {
        /// Portable I/O category.
        kind: std::io::ErrorKind,
    },
    /// Process exceeded its deadline.
    TimedOut,
    /// One captured stream exceeded its byte limit.
    OutputTooLarge,
    /// Captured output could not be read.
    OutputRead {
        /// Portable I/O category.
        kind: std::io::ErrorKind,
    },
    /// Process returned a failure status.
    Failed {
        /// Exit code, absent when terminated by a signal.
        exit_code: Option<i32>,
    },
}

impl std::fmt::Display for WorkerCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("worker command policy is invalid"),
            Self::Spawn { kind } => write!(formatter, "worker command could not start: {kind}"),
            Self::TimedOut => formatter.write_str("worker command timed out"),
            Self::OutputTooLarge => formatter.write_str("worker command output exceeded its limit"),
            Self::OutputRead { kind } => write!(formatter, "worker command output failed: {kind}"),
            Self::Failed {
                exit_code: Some(code),
            } => {
                write!(formatter, "worker command failed with exit code {code}")
            }
            Self::Failed { exit_code: None } => {
                formatter.write_str("worker command terminated by a signal")
            }
        }
    }
}

impl std::error::Error for WorkerCommandError {}

/// Execute one allowlisted program without a shell or argument rendering.
///
/// `args` and output bytes are deliberately absent from the error type. Callers
/// must centrally redact output before persisting or displaying it.
///
/// # Errors
///
/// Returns a bounded, secret-free process error.
pub fn run_worker_command(
    program: WorkerProgram,
    args: &[OsString],
    current_dir: &Path,
    environment: &BTreeMap<OsString, OsString>,
    policy: CommandPolicy,
) -> Result<WorkerCommandOutput, WorkerCommandError> {
    CommandPolicy::new(
        policy.timeout,
        policy.max_output_bytes,
        policy.clear_environment,
    )?;

    let mut command = Command::new(program.path());
    if policy.clear_environment {
        command.env_clear();
    }
    command
        .args(args)
        .current_dir(current_dir)
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);

    let mut child = command
        .spawn()
        .map_err(|source| WorkerCommandError::Spawn {
            kind: source.kind(),
        })?;
    let process_group = child.id();
    let stdout = child.stdout.take().ok_or(WorkerCommandError::OutputRead {
        kind: std::io::ErrorKind::BrokenPipe,
    })?;
    let stderr = child.stderr.take().ok_or(WorkerCommandError::OutputRead {
        kind: std::io::ErrorKind::BrokenPipe,
    })?;
    let stdout_rx = bounded_reader(stdout, policy.max_output_bytes);
    let stderr_rx = bounded_reader(stderr, policy.max_output_bytes);

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < policy.timeout => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                terminate_process_group(&mut child, process_group);
                drain_reader(&stdout_rx, Duration::from_secs(1));
                drain_reader(&stderr_rx, Duration::from_secs(1));
                return Err(WorkerCommandError::TimedOut);
            }
            Err(source) => {
                terminate_process_group(&mut child, process_group);
                return Err(WorkerCommandError::Spawn {
                    kind: source.kind(),
                });
            }
        }
    };

    let remaining = policy.timeout.saturating_sub(started.elapsed());
    let stdout = receive_reader(&stdout_rx, remaining)?;
    let stderr = receive_reader(&stderr_rx, remaining)?;
    if !status.success() {
        return Err(WorkerCommandError::Failed {
            exit_code: status.code(),
        });
    }
    Ok(WorkerCommandOutput {
        stdout,
        stderr,
        status,
    })
}

fn bounded_reader(
    stream: impl Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stream
            .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if bytes.len() > limit {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "output limit exceeded",
                    ))
                } else {
                    Ok(bytes)
                }
            });
        let _ = sender.send(result);
    });
    receiver
}

fn receive_reader(
    receiver: &mpsc::Receiver<std::io::Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<Vec<u8>, WorkerCommandError> {
    match receiver.recv_timeout(timeout.max(Duration::from_millis(1))) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(source)) if source.kind() == std::io::ErrorKind::FileTooLarge => {
            Err(WorkerCommandError::OutputTooLarge)
        }
        Ok(Err(source)) => Err(WorkerCommandError::OutputRead {
            kind: source.kind(),
        }),
        Err(RecvTimeoutError::Timeout) => Err(WorkerCommandError::TimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(WorkerCommandError::OutputRead {
            kind: std::io::ErrorKind::BrokenPipe,
        }),
    }
}

fn drain_reader(receiver: &mpsc::Receiver<std::io::Result<Vec<u8>>>, timeout: Duration) {
    let _ = receiver.recv_timeout(timeout);
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn terminate_process_group(child: &mut Child, process_group: u32) {
    #[cfg(unix)]
    {
        let group = format!("-{process_group}");
        let _ = Command::new("/bin/kill")
            .args([OsStr::new("-TERM"), OsStr::new(&group)])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let grace_started = Instant::now();
        while grace_started.elapsed() < Duration::from_millis(500) {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = Command::new("/bin/kill")
            .args([OsStr::new("-KILL"), OsStr::new(&group)])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = child.kill();
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    {
        let _ = process_group;
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CommandPolicy, WorkerCommandError};

    #[test]
    fn command_policy_rejects_unbounded_values() {
        assert_eq!(
            CommandPolicy::new(Duration::ZERO, 1024, true),
            Err(WorkerCommandError::InvalidPolicy)
        );
        assert_eq!(
            CommandPolicy::new(Duration::from_secs(1), usize::MAX, true),
            Err(WorkerCommandError::InvalidPolicy)
        );
    }
}
