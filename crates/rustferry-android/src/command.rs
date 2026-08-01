use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use camino::{Utf8Path, Utf8PathBuf};

use crate::{AndroidError, error::io_error};

/// Default deadline for one external build-tool invocation.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_mins(30);

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
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source: std::io::Error::other("spawned process did not expose piped stdout"),
        })?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| AndroidError::CommandSpawn {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            source: std::io::Error::other("spawned process did not expose piped stderr"),
        })?;
    let (stdout_sender, stdout_reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.read_to_end(&mut bytes).map(|_| bytes);
        let _ = stdout_sender.send(result);
    });
    let (stderr_sender, stderr_reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.read_to_end(&mut bytes).map(|_| bytes);
        let _ = stderr_sender.send(result);
    });

    let started = Instant::now();
    let status = loop {
        if rustferry_core::process_control::interrupt_requested() {
            terminate_process_tree(&mut child, process_group);
            return Err(AndroidError::CommandInterrupted {
                stage: spec.stage.clone(),
                program: spec.program.clone(),
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < spec.timeout => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                terminate_process_tree(&mut child, process_group);
                break None;
            }
            Err(source) => {
                terminate_process_tree(&mut child, process_group);
                return Err(AndroidError::CommandSpawn {
                    stage: spec.stage.clone(),
                    program: spec.program.clone(),
                    source,
                });
            }
        }
    };

    let mut stdout = None;
    let mut stderr = None;
    let mut timed_out = status.is_none();
    if !timed_out {
        stdout = receive_reader(&stdout_reader, started, spec.timeout).map_err(|source| {
            if source.kind() == std::io::ErrorKind::Interrupted {
                terminate_process_tree(&mut child, process_group);
                return AndroidError::CommandInterrupted {
                    stage: spec.stage.clone(),
                    program: spec.program.clone(),
                };
            }
            io_error(
                "read command stdout",
                log_path.unwrap_or(&spec.program),
                source,
            )
        })?;
        stderr = receive_reader(&stderr_reader, started, spec.timeout).map_err(|source| {
            if source.kind() == std::io::ErrorKind::Interrupted {
                terminate_process_tree(&mut child, process_group);
                return AndroidError::CommandInterrupted {
                    stage: spec.stage.clone(),
                    program: spec.program.clone(),
                };
            }
            io_error(
                "read command stderr",
                log_path.unwrap_or(&spec.program),
                source,
            )
        })?;
        if stdout.is_none() || stderr.is_none() {
            timed_out = true;
            terminate_process_tree(&mut child, process_group);
        }
    }
    if timed_out {
        let grace_started = Instant::now();
        let grace = Duration::from_secs(1);
        if stdout.is_none() {
            stdout = receive_reader(&stdout_reader, grace_started, grace)
                .ok()
                .flatten();
        }
        if stderr.is_none() {
            stderr = receive_reader(&stderr_reader, grace_started, grace)
                .ok()
                .flatten();
        }
    }
    let stdout = stdout.unwrap_or_default();
    let stderr = stderr.unwrap_or_default();
    if let Some(log_path) = log_path {
        write_log(spec, log_path, &stdout, &stderr)?;
    }

    let Some(status) = status.filter(|_| !timed_out) else {
        return Err(AndroidError::CommandTimedOut {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            log: log_path.map(Utf8Path::to_owned),
        });
    };
    if !status.success() {
        return Err(AndroidError::CommandFailed {
            stage: spec.stage.clone(),
            program: spec.program.clone(),
            status: status.code().map_or_else(
                || "terminated by signal".to_owned(),
                |code| code.to_string(),
            ),
            summary: command_summary(&stdout, &stderr),
            log: log_path.map(Utf8Path::to_owned),
        });
    }
    Ok(CommandOutput {
        stdout,
        stderr,
        status,
    })
}

fn receive_reader(
    reader: &Receiver<std::io::Result<Vec<u8>>>,
    started: Instant,
    timeout: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        if rustferry_core::process_control::interrupt_requested() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "command output drain interrupted",
            ));
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        match reader.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(result) => return result.map(Some),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(std::io::Error::other("command output reader disconnected"));
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
}
