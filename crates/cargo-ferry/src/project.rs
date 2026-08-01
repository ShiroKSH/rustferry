use std::ffi::OsString;
#[cfg(unix)]
use std::fs;
use std::io::{Read, Write as _};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};

use crate::error::CliError;
use crate::output::Reporter;

const COMMAND_TIMEOUT: Duration = Duration::from_mins(30);
type OutputReader = Receiver<std::io::Result<Vec<u8>>>;

/// Resolve a `RustFerry` project from an explicit path or the current directory.
pub fn find_project_root(explicit: Option<&Utf8Path>) -> Result<Utf8PathBuf, CliError> {
    let start = match explicit {
        Some(path) => path.to_owned(),
        None => {
            Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| CliError::Io {
                action: "read current directory",
                path: Utf8PathBuf::from("."),
                source,
            })?)
            .map_err(CliError::NonUtf8Path)?
        }
    };
    let start = start.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve project directory",
        path: start.clone(),
        source,
    })?;
    let mut cursor = Some(start.as_path());
    while let Some(directory) = cursor {
        if directory.join("ferry.toml").is_file() && directory.join("Cargo.toml").is_file() {
            return Ok(directory.to_owned());
        }
        cursor = directory.parent();
    }
    Err(CliError::ProjectNotFound { start })
}

/// Run an external command with argument boundaries preserved and output captured.
pub fn run_captured(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
) -> Result<Output, CliError> {
    run_captured_with_timeout(
        program,
        arguments,
        current_directory,
        stage,
        reporter,
        COMMAND_TIMEOUT,
        None,
        None,
        false,
    )
}

/// Run an external command while bounding each captured output stream.
pub fn run_captured_bounded(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    output_limit: usize,
) -> Result<Output, CliError> {
    run_captured_with_timeout(
        program,
        arguments,
        current_directory,
        stage,
        reporter,
        COMMAND_TIMEOUT,
        Some(output_limit),
        None,
        false,
    )
}

/// Run a bounded command with a minimal environment and optional fixed stdin bytes.
pub fn run_captured_bounded_isolated(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    output_limit: usize,
    input: Option<&[u8]>,
) -> Result<Output, CliError> {
    run_captured_with_timeout(
        program,
        arguments,
        current_directory,
        stage,
        reporter,
        COMMAND_TIMEOUT,
        Some(output_limit),
        input,
        true,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_captured_with_timeout(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    timeout: Duration,
    output_limit: Option<usize>,
    input: Option<&[u8]>,
    isolated_environment: bool,
) -> Result<Output, CliError> {
    reporter.verbose(format_command(program, arguments));
    let mut command = Command::new(program);
    command.args(arguments).current_dir(current_directory);
    if isolated_environment {
        apply_minimal_environment(&mut command);
    }
    command
        .env("CARGO_TERM_COLOR", "never")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command.spawn().map_err(|source| CliError::Io {
        action: "start external command",
        path: program.to_owned(),
        source,
    })?;
    let process_group = child.id();
    let _process_group_guard = track_child(&mut child, program)?;
    let (stdout_reader, stderr_reader) = capture_output(&mut child, program, output_limit)?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().ok_or_else(|| CliError::Io {
            action: "open external command stdin",
            path: program.to_owned(),
            source: std::io::Error::other("spawned process did not expose stdin"),
        })?;
        stdin.write_all(input).map_err(|source| {
            terminate_process_tree(&mut child, process_group);
            CliError::Io {
                action: "write external command stdin",
                path: program.to_owned(),
                source,
            }
        })?;
    }
    let started = Instant::now();
    let status = loop {
        if rustferry_core::process_control::interrupt_requested() {
            terminate_process_tree(&mut child, process_group);
            return Err(CliError::CommandInterrupted {
                tool: program.to_string(),
                stage,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                terminate_process_tree(&mut child, process_group);
                break None;
            }
            Err(source) => {
                terminate_process_tree(&mut child, process_group);
                return Err(CliError::Io {
                    action: "wait for external command",
                    path: program.to_owned(),
                    source,
                });
            }
        }
    };
    let Some(status) = status else {
        return Err(CliError::CommandTimedOut {
            tool: program.to_string(),
            stage,
            timeout_seconds: timeout.as_secs(),
        });
    };
    let stdout = receive_reader(&stdout_reader, started, timeout).map_err(|source| {
        if source.kind() == std::io::ErrorKind::Interrupted {
            terminate_process_tree(&mut child, process_group);
            return CliError::CommandInterrupted {
                tool: program.to_string(),
                stage,
            };
        }
        CliError::Io {
            action: "read external command stdout",
            path: program.to_owned(),
            source,
        }
    })?;
    let stderr = receive_reader(&stderr_reader, started, timeout).map_err(|source| {
        if source.kind() == std::io::ErrorKind::Interrupted {
            terminate_process_tree(&mut child, process_group);
            return CliError::CommandInterrupted {
                tool: program.to_string(),
                stage,
            };
        }
        CliError::Io {
            action: "read external command stderr",
            path: program.to_owned(),
            source,
        }
    })?;
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        terminate_process_tree(&mut child, process_group);
        return Err(CliError::CommandTimedOut {
            tool: program.to_string(),
            stage,
            timeout_seconds: timeout.as_secs(),
        });
    };
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn apply_minimal_environment(command: &mut Command) {
    command.env_clear();
    for name in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "TMPDIR",
        "TMP",
        "TEMP",
    ] {
        if let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            command.env(name, value);
        }
    }
    command.env("LC_ALL", "C").env("LANG", "C");
}

fn track_child(
    child: &mut Child,
    program: &Utf8Path,
) -> Result<rustferry_core::process_control::ProcessGroupGuard, CliError> {
    let process_group = child.id();
    rustferry_core::process_control::track_child(child).map_err(|source| {
        terminate_process_tree(child, process_group);
        CliError::Io {
            action: "contain external command process tree",
            path: program.to_owned(),
            source,
        }
    })
}

fn capture_output(
    child: &mut Child,
    program: &Utf8Path,
    output_limit: Option<usize>,
) -> Result<(OutputReader, OutputReader), CliError> {
    let stdout = child.stdout.take().ok_or_else(|| CliError::Io {
        action: "capture command stdout",
        path: program.to_owned(),
        source: std::io::Error::other("spawned process did not expose stdout"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| CliError::Io {
        action: "capture command stderr",
        path: program.to_owned(),
        source: std::io::Error::other("spawned process did not expose stderr"),
    })?;
    Ok((
        spawn_reader(stdout, output_limit),
        spawn_reader(stderr, output_limit),
    ))
}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
    output_limit: Option<usize>,
) -> OutputReader {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(output_limit.unwrap_or(0).min(16 * 1024));
        let mut buffer = [0_u8; 16 * 1024];
        let mut exceeded = false;
        let result = loop {
            match reader.read(&mut buffer) {
                Ok(0) if exceeded => {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "captured command output exceeded its configured bound",
                    ));
                }
                Ok(0) => break Ok(bytes),
                Ok(read) => {
                    if let Some(limit) = output_limit {
                        let retained = limit.saturating_sub(bytes.len()).min(read);
                        bytes.extend_from_slice(&buffer[..retained]);
                        exceeded |= retained < read;
                    } else {
                        bytes.extend_from_slice(&buffer[..read]);
                    }
                }
                Err(source) => break Err(source),
            }
        };
        let _ = sender.send(result);
    });
    receiver
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
            .args(["-KILL", "--", &format!("-{process_group}")])
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

/// Find an executable in PATH without invoking a shell.
pub fn find_in_path(name: &str) -> Option<Utf8PathBuf> {
    let paths = std::env::var_os("PATH")?;
    #[cfg(windows)]
    let candidates = {
        let requested = std::path::Path::new(name);
        if requested.extension().is_some() {
            vec![OsString::from(name)]
        } else {
            std::env::var_os("PATHEXT")
                .unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD"))
                .to_string_lossy()
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(|extension| {
                    let mut candidate = OsString::from(name);
                    candidate.push(extension);
                    candidate
                })
                .collect::<Vec<_>>()
        }
    };
    #[cfg(not(windows))]
    let candidates = [OsString::from(name)];
    for directory in std::env::split_paths(&paths) {
        for name in &candidates {
            let candidate = directory.join(name);
            if candidate.is_file()
                && let Ok(path) = Utf8PathBuf::from_path_buf(candidate)
            {
                return Some(path);
            }
        }
    }
    None
}

/// Atomically replace one text file after its new contents are complete.
pub fn write_atomic(path: &Utf8Path, contents: &str) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| CliError::Io {
        action: "resolve file parent",
        path: path.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|source| CliError::Io {
        action: "create temporary file",
        path: parent.to_owned(),
        source,
    })?;
    temporary
        .write_all(contents.as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| CliError::Io {
            action: "write temporary file",
            path: path.to_owned(),
            source,
        })?;
    temporary.persist(path).map_err(|error| CliError::Io {
        action: "replace file",
        path: path.to_owned(),
        source: error.error,
    })?;
    sync_directory(parent)
}

#[cfg(unix)]
fn sync_directory(path: &Utf8Path) -> Result<(), CliError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CliError::Io {
            action: "sync directory",
            path: path.to_owned(),
            source,
        })?;
    Ok(())
}

#[cfg(not(unix))]
const fn sync_directory(_path: &Utf8Path) -> Result<(), CliError> {
    Ok(())
}

fn format_command(program: &Utf8Path, arguments: &[OsString]) -> String {
    let mut rendered = vec![shell_display(program.as_str())];
    let mut redact_next = false;
    for argument in arguments {
        let value = argument.to_string_lossy();
        if redact_next {
            rendered.push("<redacted>".to_owned());
            redact_next = false;
            continue;
        }
        if matches!(
            value.as_ref(),
            "--password" | "--ks-pass" | "--key-pass" | "--token"
        ) {
            redact_next = true;
        }
        rendered.push(shell_display(&value));
    }
    format!("Running: {}", rendered.join(" "))
}

fn shell_display(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_=./:".contains(character))
    {
        value.to_owned()
    } else {
        format!("{value:?}")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_not_held_open_by_descendant_pipes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let reporter = Reporter::new(false, true, false);
        let started = Instant::now();
        let error = run_captured_with_timeout(
            Utf8Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("sleep 10 & exit 0")],
            &root,
            "descendant timeout",
            &reporter,
            Duration::from_millis(200),
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::CommandTimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn bounded_capture_drains_but_rejects_oversized_output() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let reporter = Reporter::new(false, true, false);
        let error = run_captured_bounded(
            Utf8Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("printf 123456789")],
            &root,
            "bounded output",
            &reporter,
            4,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::Io { .. }));
    }
}
