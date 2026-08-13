use std::{
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

use crate::{AndroidError, error::io_error};

/// Default deadline for one external build-tool invocation.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_mins(30);
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// One safely tokenized external command.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Maximum runtime.
    pub timeout: Duration,
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
            timeout: DEFAULT_COMMAND_TIMEOUT,
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
}

/// Captured output from a successful external command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit status.
    pub status: ExitStatus,
}

/// Run one command, capture both streams without pipe deadlock, and save a redacted log.
///
/// # Errors
///
/// Returns an error when spawning, stream capture, logging, timeout handling, or exit status
/// indicates failure.
pub fn run_command(spec: &CommandSpec, log_path: &Utf8Path) -> Result<CommandOutput, AndroidError> {
    run_command_inner(spec, Some(log_path))
}

pub(crate) fn run_probe_command(spec: &CommandSpec) -> Result<CommandOutput, AndroidError> {
    run_command_inner(spec, None)
}

#[allow(clippy::too_many_lines)]
fn run_command_inner(
    spec: &CommandSpec,
    log_path: Option<&Utf8Path>,
) -> Result<CommandOutput, AndroidError> {
    run_command_with_output_limit(spec, log_path, DEFAULT_PROCESS_OUTPUT_LIMIT)
}

#[allow(clippy::too_many_lines)]
fn run_command_with_output_limit(
    spec: &CommandSpec,
    log_path: Option<&Utf8Path>,
    output_limit: usize,
) -> Result<CommandOutput, AndroidError> {
    if rustferry_core::process_control::interrupt_requested() {
        return Err(AndroidError::CommandInterrupted {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
        });
    }
    if let Some(parent) = log_path.and_then(Utf8Path::parent) {
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create log directory", parent, source))?;
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

    let mut child = command
        .spawn()
        .map_err(|source| AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source,
        })?;
    let process_group = child.id();
    let _process_group_guard = match rustferry_core::process_control::track_child(&child) {
        Ok(guard) => guard,
        Err(source) => {
            terminate_process_tree(&mut child, process_group);
            return Err(AndroidError::CommandSpawn {
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
    let mut status = None;
    loop {
        if rustferry_core::process_control::interrupt_requested() {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            return Err(AndroidError::CommandInterrupted {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
            });
        }
        let capture_status = match capture.poll() {
            Ok(capture_status) => capture_status,
            Err(source) => {
                terminate_process_tree(&mut child, process_group);
                return Err(output_read_error(spec, log_path, source));
            }
        };
        if let OutputCaptureStatus::LimitExceeded(stream) = capture_status {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            let output = capture.into_partial_output();
            if let Some(path) = log_path {
                write_log(spec, path, &output.stdout, &output.stderr)?;
            }
            return Err(AndroidError::ProcessOutputTooLarge {
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
                    return Err(AndroidError::CommandSpawn {
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
        let remaining = spec.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            terminate_process_tree(&mut child, process_group);
            drain_after_termination(&mut capture);
            let output = capture.into_partial_output();
            if let Some(path) = log_path {
                write_log(spec, path, &output.stdout, &output.stderr)?;
            }
            return Err(AndroidError::CommandTimedOut {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
                log: log_path.map(Utf8Path::to_owned),
            });
        }
        if capture.is_complete() {
            thread::sleep(remaining.min(OUTPUT_POLL_INTERVAL));
        } else if let Err(source) = capture.wait_timeout(remaining.min(OUTPUT_POLL_INTERVAL)) {
            terminate_process_tree(&mut child, process_group);
            return Err(output_read_error(spec, log_path, source));
        }
    }

    let output = capture.into_partial_output();
    if let Some(log_path) = log_path {
        write_log(spec, log_path, &output.stdout, &output.stderr)?;
    }
    let status = status.expect("completed capture requires a reaped child");
    if !status.success() {
        return Err(AndroidError::CommandFailed {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            status: status.code().map_or_else(
                || "terminated by signal".to_owned(),
                |code| code.to_string(),
            ),
            summary: Box::new(command_summary(&output.stdout, &output.stderr)),
            log: log_path.map(Utf8Path::to_owned),
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
) -> Result<BoundedOutputCapture, AndroidError> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source: std::io::Error::other("spawned process did not expose piped stdout"),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source: std::io::Error::other("spawned process did not expose piped stderr"),
        })?;
    BoundedOutputCapture::spawn(stdout, stderr, output_limit).map_err(|source| {
        AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source,
        }
    })
}

fn output_read_error(
    spec: &CommandSpec,
    log_path: Option<&Utf8Path>,
    source: std::io::Error,
) -> AndroidError {
    io_error(
        "read command output",
        log_path.unwrap_or(&spec.program),
        source,
    )
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

pub(crate) fn external_tool_path_arg(path: &Utf8Path) -> Result<String, AndroidError> {
    let value = path.as_str();
    if value.chars().any(char::is_control) {
        return Err(AndroidError::InvalidExternalToolPath {
            reason: "control characters are not allowed",
        });
    }

    #[cfg(windows)]
    {
        if strip_ascii_prefix(value, r"\\.\").is_some() {
            return Err(AndroidError::InvalidExternalToolPath {
                reason: "Windows device namespaces are not supported",
            });
        }
        if let Some(verbatim) = strip_ascii_prefix(value, r"\\?\") {
            if let Some(unc) = strip_ascii_prefix(verbatim, r"UNC\") {
                let mut components = unc.split('\\');
                if components.next().is_some_and(|part| !part.is_empty())
                    && components.next().is_some_and(|part| !part.is_empty())
                {
                    return Ok(format!(r"\\{unc}"));
                }
                return Err(AndroidError::InvalidExternalToolPath {
                    reason: "verbatim UNC paths require a server and share",
                });
            }
            let bytes = verbatim.as_bytes();
            if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
            {
                return Ok(verbatim.to_owned());
            }
            return Err(AndroidError::InvalidExternalToolPath {
                reason: "unsupported Windows verbatim namespace",
            });
        }
    }

    if !path.is_absolute() {
        return Err(AndroidError::InvalidExternalToolPath {
            reason: "path must be absolute",
        });
    }
    Ok(value.to_owned())
}

#[cfg(windows)]
fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn write_log(
    spec: &CommandSpec,
    path: &Utf8Path,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), AndroidError> {
    let argv = spec
        .redacted_argv()
        .into_iter()
        .map(|argument| format!("{argument:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    let contents = format!(
        "stage: {}\ncwd: {}\ncommand: {}\n\n[stdout]\n{}\n\n[stderr]\n{}\n",
        spec.stage,
        spec.current_dir,
        argv,
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
    fn rendered_command_redacts_selected_arguments() {
        let mut command = CommandSpec::new("sign", "/tools/apksigner", "/project");
        command.args = vec!["--ks-pass".into(), "pass:secret".into(), "app.apk".into()];
        command.redacted_args.insert(1);
        assert_eq!(
            command.redacted_argv(),
            ["/tools/apksigner", "--ks-pass", "<redacted>", "app.apk"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn timeout_is_not_held_open_by_descendant_pipes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let mut command = CommandSpec::new("descendant timeout", "/bin/sh", &root);
        command.args = vec!["-c".into(), "sleep 10 & exit 0".into()];
        command.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let error = run_command(&command, &root.join("command.log")).unwrap_err();
        assert!(matches!(error, AndroidError::CommandTimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[cfg(unix)]
    #[test]
    fn oversized_stdout_is_typed_and_log_is_bounded() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let log_path = root.join("command.log");
        let mut command = CommandSpec::new("oversized stdout", "/usr/bin/yes", &root);
        command.args = vec!["overflow".into()];
        command.timeout = Duration::from_secs(5);
        let started = Instant::now();
        let error = run_command_with_output_limit(&command, Some(&log_path), TEST_OUTPUT_LIMIT)
            .unwrap_err();
        assert!(matches!(
            error,
            AndroidError::ProcessOutputTooLarge {
                ref stream,
                limit_bytes: TEST_OUTPUT_LIMIT,
                ..
            } if stream == "stdout"
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(fs::metadata(log_path).unwrap().len() <= (TEST_OUTPUT_LIMIT + 4096) as u64);
    }
}
