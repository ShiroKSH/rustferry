use std::ffi::OsString;
#[cfg(unix)]
use std::fs;
use std::io::{self, Write as _};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::{
    DirectoryFilesystemIdentity, DirectoryIdentityError,
    process_control::{BoundedOutputCapture, DEFAULT_PROCESS_OUTPUT_LIMIT, OutputCaptureStatus},
    verify_directory_identity,
};

use crate::error::CliError;
use crate::output::Reporter;

const COMMAND_TIMEOUT: Duration = Duration::from_mins(30);
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Capture the handle-bound filesystem identity of a canonical project directory.
///
/// # Errors
///
/// Returns a typed identity error when the path is not an absolute plain directory or the
/// filesystem cannot provide the required persistent identity.
pub fn capture_project_directory_identity(
    project_root: &Utf8Path,
) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
    DirectoryFilesystemIdentity::capture(project_root.as_std_path())
}

/// Reopen a canonical project directory and require its exact persisted filesystem identity.
///
/// # Errors
///
/// Returns a typed identity error when the path cannot be reopened safely or identifies a
/// different filesystem object.
pub fn verify_project_directory_identity(
    project_root: &Utf8Path,
    expected: &DirectoryFilesystemIdentity,
) -> Result<(), DirectoryIdentityError> {
    verify_directory_identity(project_root.as_std_path(), expected)
}

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

/// Run a bounded external command with only the supplied environment entries.
///
/// The child environment is cleared before the exact entries are installed. Argument boundaries,
/// output limits, timeout, and process-tree containment are identical to [`run_captured_bounded`].
///
/// # Errors
///
/// Returns a typed process, timeout, output-limit, interruption, or local I/O error.
pub fn run_captured_bounded_with_exact_environment(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    output_limit: usize,
    environment: &[(OsString, OsString)],
) -> Result<Output, CliError> {
    run_captured_with_limits(
        program,
        arguments,
        current_directory,
        stage,
        reporter,
        COMMAND_TIMEOUT,
        output_limit,
        None,
        false,
        Some(environment),
        true,
    )
}

/// Run a bounded command with a minimal environment and optional fixed stdin bytes.
#[cfg(all(test, unix))]
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
    run_captured_with_limits(
        program,
        arguments,
        current_directory,
        stage,
        reporter,
        timeout,
        output_limit.unwrap_or(DEFAULT_PROCESS_OUTPUT_LIMIT),
        input,
        isolated_environment,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_captured_with_limits(
    program: &Utf8Path,
    arguments: &[OsString],
    current_directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    timeout: Duration,
    output_limit: usize,
    input: Option<&[u8]>,
    isolated_environment: bool,
    exact_environment: Option<&[(OsString, OsString)]>,
    atomically_contained: bool,
) -> Result<Output, CliError> {
    reporter.verbose(format_command(program, arguments));
    let mut command = Command::new(program);
    command.args(arguments).current_dir(current_directory);
    if let Some(environment) = exact_environment {
        command
            .env_clear()
            .envs(environment.iter().map(|(name, value)| (name, value)));
    } else if isolated_environment {
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
    let (mut child, process_group_guard) =
        spawn_project_child(&mut command, program, atomically_contained)?;
    let mut process_group_guard = Some(process_group_guard);
    let process_group = child.id();
    let started = Instant::now();
    let mut capture = match capture_output(&mut child, program, output_limit) {
        Ok(capture) => capture,
        Err(error) => {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            return Err(error);
        }
    };
    let stdin_writer = if let Some(input) = input {
        let Some(stdin) = child.stdin.take() else {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            drain_after_termination(&mut capture);
            return Err(CliError::Io {
                action: "open external command stdin",
                path: program.to_owned(),
                source: io::Error::other("spawned process did not expose stdin"),
            });
        };
        match spawn_stdin_writer(stdin, input.to_vec()) {
            Ok(writer) => Some(writer),
            Err(source) => {
                terminate_supervised_process_tree(
                    &mut child,
                    process_group,
                    &mut process_group_guard,
                    atomically_contained,
                );
                drain_after_termination(&mut capture);
                return Err(CliError::Io {
                    action: "start external command stdin writer",
                    path: program.to_owned(),
                    source,
                });
            }
        }
    } else {
        None
    };
    let mut stdin_complete = stdin_writer.is_none();
    let mut status = None;
    loop {
        if rustferry_core::process_control::interrupt_requested() {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            drain_after_termination(&mut capture);
            return Err(CliError::CommandInterrupted {
                tool: program.to_string(),
                stage,
            });
        }
        if !stdin_complete {
            let writer = stdin_writer
                .as_ref()
                .expect("incomplete stdin requires a writer");
            match poll_stdin_writer(writer) {
                Ok(true) => stdin_complete = true,
                Ok(false) => {}
                Err(source) => {
                    terminate_supervised_process_tree(
                        &mut child,
                        process_group,
                        &mut process_group_guard,
                        atomically_contained,
                    );
                    drain_after_termination(&mut capture);
                    return Err(CliError::Io {
                        action: "write external command stdin",
                        path: program.to_owned(),
                        source,
                    });
                }
            }
        }
        let capture_status = match capture.poll() {
            Ok(capture_status) => capture_status,
            Err(source) => {
                terminate_supervised_process_tree(
                    &mut child,
                    process_group,
                    &mut process_group_guard,
                    atomically_contained,
                );
                return Err(output_read_error(program, source));
            }
        };
        if let OutputCaptureStatus::LimitExceeded(stream) = capture_status {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            drain_after_termination(&mut capture);
            return Err(CliError::ProcessOutputTooLarge {
                tool: program.to_string(),
                stage,
                stream: stream.to_string(),
                limit_bytes: output_limit,
            });
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit_status)) => status = Some(exit_status),
                Ok(None) => {}
                Err(source) => {
                    terminate_supervised_process_tree(
                        &mut child,
                        process_group,
                        &mut process_group_guard,
                        atomically_contained,
                    );
                    return Err(CliError::Io {
                        action: "wait for external command",
                        path: program.to_owned(),
                        source,
                    });
                }
            }
        }
        if status.is_some() && capture.is_complete() && stdin_complete {
            break;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            drain_after_termination(&mut capture);
            return Err(CliError::CommandTimedOut {
                tool: program.to_string(),
                stage,
                timeout_seconds: timeout.as_secs(),
            });
        }
        if capture.is_complete() {
            thread::sleep(remaining.min(OUTPUT_POLL_INTERVAL));
        } else if let Err(source) = capture.wait_timeout(remaining.min(OUTPUT_POLL_INTERVAL)) {
            terminate_supervised_process_tree(
                &mut child,
                process_group,
                &mut process_group_guard,
                atomically_contained,
            );
            return Err(output_read_error(program, source));
        }
    }
    let captured = capture.into_partial_output();
    Ok(Output {
        status: status.expect("completed capture requires a reaped child"),
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

fn spawn_project_child(
    command: &mut Command,
    program: &Utf8Path,
    atomically_contained: bool,
) -> Result<(Child, rustferry_core::process_control::ProcessGroupGuard), CliError> {
    if atomically_contained {
        return rustferry_core::process_control::spawn_tracked_child(command).map_err(|source| {
            CliError::Io {
                action: "start contained external command",
                path: program.to_owned(),
                source,
            }
        });
    }
    let mut child = command.spawn().map_err(|source| CliError::Io {
        action: "start external command",
        path: program.to_owned(),
        source,
    })?;
    let guard = track_child(&mut child, program)?;
    Ok((child, guard))
}

fn output_read_error(program: &Utf8Path, source: std::io::Error) -> CliError {
    CliError::Io {
        action: "read external command output",
        path: program.to_owned(),
        source,
    }
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

fn capture_output(
    child: &mut Child,
    program: &Utf8Path,
    output_limit: usize,
) -> Result<BoundedOutputCapture, CliError> {
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
    BoundedOutputCapture::spawn(stdout, stderr, output_limit).map_err(|source| CliError::Io {
        action: "start command output readers",
        path: program.to_owned(),
        source,
    })
}

fn spawn_stdin_writer(
    mut stdin: ChildStdin,
    input: Vec<u8>,
) -> io::Result<Receiver<io::Result<()>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("rustferry-stdin-writer".to_owned())
        .spawn(move || {
            let result = stdin.write_all(&input);
            let _ = sender.send(result);
        })
        .map(|_| receiver)
}

fn poll_stdin_writer(writer: &Receiver<io::Result<()>>) -> io::Result<bool> {
    match writer.try_recv() {
        Ok(result) => result.map(|()| true),
        Err(TryRecvError::Empty) => Ok(false),
        Err(TryRecvError::Disconnected) => Err(io::Error::other(
            "external command stdin writer disconnected",
        )),
    }
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

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn terminate_supervised_process_tree(
    child: &mut Child,
    process_group: u32,
    process_group_guard: &mut Option<rustferry_core::process_control::ProcessGroupGuard>,
    atomically_contained: bool,
) {
    #[cfg(windows)]
    if atomically_contained {
        // Closing the dedicated kill-on-close Job Object is the exact contained runner's
        // termination authority. It avoids resolving any cleanup helper through ambient PATH.
        drop(process_group_guard.take());
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    let _ = process_group_guard;
    let _ = atomically_contained;
    terminate_process_tree(child, process_group);
}

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
    #[cfg(unix)]
    sync_directory(parent)?;
    Ok(())
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

#[cfg(test)]
mod filesystem_identity_tests {
    use super::*;

    #[test]
    fn project_directory_identity_survives_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let project = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let identity = capture_project_directory_identity(&project).unwrap();

        assert_eq!(
            capture_project_directory_identity(&project).unwrap(),
            identity
        );
        verify_project_directory_identity(&project, &identity).unwrap();
    }

    #[test]
    fn project_directory_identity_rejects_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let project = Utf8PathBuf::from_path_buf(project).unwrap();
        let identity = capture_project_directory_identity(&project).unwrap();

        std::fs::rename(project.as_std_path(), &displaced).unwrap();
        std::fs::create_dir(&project).unwrap();

        assert!(verify_project_directory_identity(&project, &identity).is_err());
    }
}

#[cfg(all(test, windows))]
mod exact_environment_tests {
    use super::*;

    #[test]
    fn exact_environment_capture_does_not_inherit_windows_entries() {
        let system_root = Utf8PathBuf::from_path_buf(
            rustferry_core::windows_system_root().expect("authoritative Windows root"),
        )
        .expect("UTF-8 Windows root");
        let system32 = system_root.join("System32");
        let program = system32.join("cmd.exe");
        let fixed_path = format!("{system32};{system_root}");
        let assertion = concat!(
            "echo [%RUSTFERRY_SAFE%]",
            "[%BROWSER%]",
            "[%HOME%]",
            "[%HTTP_PROXY%]",
            "[%HTTPS_PROXY%]",
            "[%GH_TOKEN%]",
            "[%GITHUB_TOKEN%]",
            "[%USERPROFILE%]"
        );
        let reporter = Reporter::new(false, true, false);
        let output = run_captured_bounded_with_exact_environment(
            &program,
            &[
                OsString::from("/d"),
                OsString::from("/c"),
                OsString::from(assertion),
            ],
            &system_root,
            "exact environment",
            &reporter,
            4_096,
            &[
                (OsString::from("RUSTFERRY_SAFE"), OsString::from("fixed")),
                (
                    OsString::from("SystemRoot"),
                    OsString::from(system_root.as_str()),
                ),
                (
                    OsString::from("WINDIR"),
                    OsString::from(system_root.as_str()),
                ),
                (OsString::from("COMSPEC"), OsString::from(program.as_str())),
                (OsString::from("PATH"), OsString::from(&fixed_path)),
            ],
        )
        .unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            concat!(
                "[fixed]",
                "[%BROWSER%]",
                "[%HOME%]",
                "[%HTTP_PROXY%]",
                "[%HTTPS_PROXY%]",
                "[%GH_TOKEN%]",
                "[%GITHUB_TOKEN%]",
                "[%USERPROFILE%]"
            )
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const TEST_OUTPUT_LIMIT: usize = 64 * 1024;

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
        assert!(matches!(
            error,
            CliError::ProcessOutputTooLarge {
                ref stream,
                limit_bytes: 4,
                ..
            } if stream == "stdout"
        ));
    }

    #[test]
    fn oversized_descendant_output_stops_the_process_group() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let pid_path = root.join("writer.pid");
        let reporter = Reporter::new(false, true, false);
        let script = "(sleep 0.1; exec /usr/bin/yes overflow) & writer=$!; printf '%s\n' \"$writer\" > \"$1\"; wait";
        let started = Instant::now();
        let error = run_captured_with_limits(
            Utf8Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("rustferry-output-test"),
                OsString::from(pid_path.as_str()),
            ],
            &root,
            "oversized descendant output",
            &reporter,
            Duration::from_secs(5),
            TEST_OUTPUT_LIMIT,
            None,
            false,
            None,
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::ProcessOutputTooLarge {
                ref stream,
                limit_bytes: TEST_OUTPUT_LIMIT,
                ..
            } if stream == "stdout"
        ));
        assert!(started.elapsed() < Duration::from_secs(4));

        let writer_pid = fs::read_to_string(pid_path).unwrap();
        let writer_pid = writer_pid.trim();
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_exists(writer_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_exists(writer_pid));
    }

    fn process_exists(pid: &str) -> bool {
        Command::new("/bin/kill")
            .args(["-0", pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn isolated_capture_writes_fixed_stdin() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let reporter = Reporter::new(false, true, false);
        let output = run_captured_bounded_isolated(
            Utf8Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("cat")],
            &root,
            "isolated stdin",
            &reporter,
            32,
            Some(b"fixed-input"),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"fixed-input");
    }

    #[test]
    fn exact_environment_capture_does_not_inherit_ambient_entries() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let reporter = Reporter::new(false, true, false);
        let output = run_captured_bounded_with_exact_environment(
            Utf8Path::new("/usr/bin/env"),
            &[],
            &root,
            "exact environment",
            &reporter,
            4_096,
            &[(OsString::from("RUSTFERRY_SAFE"), OsString::from("fixed"))],
        )
        .unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(environment.contains("RUSTFERRY_SAFE=fixed\n"));
        assert!(!environment.contains("PATH="));
        assert!(!environment.contains("HOME="));
        assert!(!environment.contains("BROWSER="));
    }
}
