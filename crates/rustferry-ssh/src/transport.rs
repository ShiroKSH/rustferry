use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

#[cfg(any(unix, windows))]
use std::fs::File;
#[cfg(windows)]
use std::path::PathBuf;

use rustferry_remote::{
    CancellationToken, MAX_WORKER_STDIO_REQUEST_BYTES, MAX_WORKER_STDIO_RESPONSE_BYTES,
};
use same_file::Handle as FileIdentityHandle;
use tempfile::NamedTempFile;
#[cfg(not(windows))]
use tempfile::TempDir;
use thiserror::Error;
#[cfg(windows)]
use uuid::Uuid;

use crate::config::{SshConfigError, SshEndpointConfig, SshIdentityFileGuard};

/// Maximum JSON request accepted by the process transport.
pub const MAX_SSH_REQUEST_BYTES: usize = MAX_WORKER_STDIO_REQUEST_BYTES;
/// Maximum JSON response accepted from a worker.
pub const MAX_SSH_RESPONSE_BYTES: usize = MAX_WORKER_STDIO_RESPONSE_BYTES;
const MAX_SSH_STDERR_BYTES: usize = 64 * 1024;
/// Fixed OpenSSH TCP connection timeout.
pub const SSH_CONNECT_TIMEOUT_SECONDS: u64 = 15;
/// Fixed deadline for one protocol exchange, including worker diagnostics.
pub const SSH_OPERATION_TIMEOUT: Duration = Duration::from_mins(2);
/// Fixed finite deadline for one complete Rust/Xcode snapshot build session.
pub const SSH_SNAPSHOT_SESSION_TIMEOUT: Duration = Duration::from_hours(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_millis(100);
#[cfg(windows)]
const WINDOWS_SNAPSHOT_CREATE_ATTEMPTS: usize = 16;

#[derive(Debug)]
struct PrivateSnapshotDirectory {
    #[cfg(not(windows))]
    temporary: TempDir,
    #[cfg(unix)]
    _handle: File,
    #[cfg(windows)]
    path: PathBuf,
    #[cfg(windows)]
    handle: Option<File>,
    #[cfg(windows)]
    identity: Option<FileIdentityHandle>,
}

impl PrivateSnapshotDirectory {
    fn path(&self) -> &Path {
        #[cfg(windows)]
        {
            &self.path
        }
        #[cfg(not(windows))]
        {
            self.temporary.path()
        }
    }

    #[cfg(windows)]
    fn revalidate(&self) -> Result<(), SshConfigError> {
        use std::os::windows::io::AsHandle as _;

        let handle = self
            .handle
            .as_ref()
            .ok_or(SshConfigError::KnownHostsSnapshotFailed)?;
        rustferry_core::windows_private_directory::verify_private_directory_handle(
            handle.as_handle(),
        )
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        let retained = self
            .identity
            .as_ref()
            .ok_or(SshConfigError::KnownHostsSnapshotFailed)?;
        let named = FileIdentityHandle::from_path(&self.path)
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        if &named != retained || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SshConfigError::KnownHostsSnapshotFailed);
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for PrivateSnapshotDirectory {
    fn drop(&mut self) {
        drop(self.identity.take());
        if let Some(handle) = self.handle.take() {
            // The trust file's own temporary-path cleanup has an unavoidable same-user race. The
            // directory itself is removed only through this exact retained handle, never by path.
            let _ =
                rustferry_core::windows_private_directory::remove_private_directory_handle(handle);
        }
    }
}

/// Fixed OpenSSH process specification for one worker exchange.
#[derive(Debug)]
pub struct SshInvocation {
    program: OsString,
    arguments: Vec<OsString>,
    timeout: Duration,
    known_hosts_snapshot: NamedTempFile,
    known_hosts_identity: FileIdentityHandle,
    snapshot_directory: PrivateSnapshotDirectory,
    identity_file_guard: Option<SshIdentityFileGuard>,
}

impl SshInvocation {
    /// Fixed executable name resolved by the operating system.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Exact argument array. No element is interpreted by a local shell.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Total deadline for this exchange.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Private operation-owned trust snapshot retained for this invocation.
    pub fn known_hosts_snapshot_path(&self) -> &Path {
        self.known_hosts_snapshot.path()
    }

    pub(crate) fn revalidate_identity_file(&self) -> Result<(), SshConfigError> {
        if let Some(guard) = &self.identity_file_guard {
            guard.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn revalidate_trust_snapshot(&self) -> Result<(), SshConfigError> {
        #[cfg(windows)]
        self.snapshot_directory.revalidate()?;
        #[cfg(not(windows))]
        let _ = self.snapshot_directory.path();
        let named = FileIdentityHandle::from_path(self.known_hosts_snapshot.path())
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        let metadata = fs::symlink_metadata(self.known_hosts_snapshot.path())
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        if named != self.known_hosts_identity
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
        {
            return Err(SshConfigError::KnownHostsSnapshotFailed);
        }
        Ok(())
    }
}

/// Build the only OpenSSH invocation accepted by this crate.
///
/// # Errors
///
/// Revalidates the identity path and publishes the pinned host entry into a
/// private operation-owned snapshot retained by the returned invocation.
pub fn build_ssh_invocation(config: &SshEndpointConfig) -> Result<SshInvocation, SshConfigError> {
    build_ssh_invocation_for(config, "--stdio", SSH_OPERATION_TIMEOUT)
}

/// Build the fixed OpenSSH invocation for one framed snapshot session.
///
/// # Errors
///
/// Applies the same pinned-host and retained-identity checks as
/// [`build_ssh_invocation`], with the sole remote mode
/// `ferry-worker-macos serve --stdio-session-v1`.
pub fn build_ssh_session_invocation(
    config: &SshEndpointConfig,
) -> Result<SshInvocation, SshConfigError> {
    build_ssh_invocation_for(config, "--stdio-session-v1", SSH_SNAPSHOT_SESSION_TIMEOUT)
}

fn build_ssh_invocation_for(
    config: &SshEndpointConfig,
    remote_mode: &'static str,
    timeout: Duration,
) -> Result<SshInvocation, SshConfigError> {
    let known_hosts_bytes = config.validated_known_hosts_bytes()?;
    let identity_file_guard = config.open_identity_file_guard()?;
    let snapshot_directory = create_private_snapshot_directory()?;
    let mut known_hosts_snapshot = tempfile::Builder::new()
        .prefix("known-hosts-")
        .tempfile_in(snapshot_directory.path())
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        known_hosts_snapshot
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    }
    known_hosts_snapshot
        .write_all(&known_hosts_bytes)
        .and_then(|()| known_hosts_snapshot.flush())
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    let known_hosts_identity = snapshot_file_identity(&known_hosts_snapshot)?;
    let known_hosts_option = known_hosts_option(known_hosts_snapshot.path())?;
    let mut arguments = vec![
        "-F".into(),
        "none".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        known_hosts_option,
        "-o".into(),
        "GlobalKnownHostsFile=none".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ClearAllForwardings=yes".into(),
        "-o".into(),
        "RequestTTY=no".into(),
        "-o".into(),
        "PermitLocalCommand=no".into(),
        "-o".into(),
        "ConnectionAttempts=1".into(),
        "-o".into(),
        OsString::from(format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}")),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=2".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-T".into(),
    ];
    if let Some(identity_file) = config.identity_file() {
        arguments.extend([
            OsString::from("-o"),
            OsString::from("IdentitiesOnly=yes"),
            OsString::from("-i"),
            OsString::from(identity_file.as_str()),
        ]);
    }
    arguments.extend([
        OsString::from("-p"),
        OsString::from(config.port().to_string()),
        OsString::from("-l"),
        OsString::from(config.user().as_str()),
        OsString::from(config.host().as_str()),
        OsString::from("ferry-worker-macos"),
        OsString::from("serve"),
        OsString::from(remote_mode),
    ]);
    let invocation = SshInvocation {
        program: "ssh".into(),
        arguments,
        timeout,
        known_hosts_snapshot,
        known_hosts_identity,
        snapshot_directory,
        identity_file_guard,
    };
    invocation.revalidate_trust_snapshot()?;
    Ok(invocation)
}

fn known_hosts_option(path: &Path) -> Result<OsString, SshConfigError> {
    validate_openssh_path(path)?;
    let path = path
        .to_str()
        .ok_or(SshConfigError::KnownHostsSnapshotFailed)?;
    let mut option = String::with_capacity(path.len().saturating_add(24));
    option.push_str("UserKnownHostsFile=\"");
    for character in path.chars() {
        match character {
            '\\' | '"' => {
                option.push('\\');
                option.push(character);
            }
            _ => option.push(character),
        }
    }
    option.push('"');
    Ok(option.into())
}

fn snapshot_file_identity(snapshot: &NamedTempFile) -> Result<FileIdentityHandle, SshConfigError> {
    snapshot
        .as_file()
        .try_clone()
        .and_then(FileIdentityHandle::from_file)
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)
}

#[cfg(windows)]
fn create_private_snapshot_directory() -> Result<PrivateSnapshotDirectory, SshConfigError> {
    let requested_parent = std::env::temp_dir();
    validate_openssh_path(&requested_parent)?;
    let parent =
        fs::canonicalize(requested_parent).map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    validate_openssh_path(&parent)?;
    for _ in 0..WINDOWS_SNAPSHOT_CREATE_ATTEMPTS {
        let path = parent.join(format!("rustferry-ssh-{}", Uuid::new_v4().simple()));
        validate_openssh_path(&path)?;
        match rustferry_core::windows_private_directory::create_private_directory(&path) {
            Ok(handle) => {
                let mut directory = PrivateSnapshotDirectory {
                    path,
                    handle: Some(handle),
                    identity: None,
                };
                let retained = directory
                    .handle
                    .as_ref()
                    .expect("new private snapshot handle")
                    .try_clone()
                    .and_then(FileIdentityHandle::from_file)
                    .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
                directory.identity = Some(retained);
                directory.revalidate()?;
                return Ok(directory);
            }
            Err(error)
                if error.kind()
                    == rustferry_core::windows_private_directory::PrivateDirectoryErrorKind::AlreadyExists =>
            {
            }
            Err(_) => return Err(SshConfigError::KnownHostsSnapshotFailed),
        }
    }
    Err(SshConfigError::KnownHostsSnapshotFailed)
}

#[cfg(not(windows))]
fn create_private_snapshot_directory() -> Result<PrivateSnapshotDirectory, SshConfigError> {
    let requested_parent = std::env::temp_dir();
    validate_openssh_path(&requested_parent)?;
    let parent =
        fs::canonicalize(requested_parent).map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    validate_openssh_path(&parent)?;
    let temporary = tempfile::Builder::new()
        .prefix("rustferry-ssh-")
        .tempdir_in(&parent)
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    #[cfg(unix)]
    fs::set_permissions(
        temporary.path(),
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    let canonical_directory =
        fs::canonicalize(temporary.path()).map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    if canonical_directory != temporary.path() {
        return Err(SshConfigError::KnownHostsSnapshotFailed);
    }
    validate_openssh_path(&canonical_directory)?;
    let path_metadata = fs::symlink_metadata(&canonical_directory)
        .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_dir() {
        return Err(SshConfigError::KnownHostsSnapshotFailed);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let handle = File::open(&canonical_directory)
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        let opened_metadata = handle
            .metadata()
            .map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
            || opened_metadata.mode() & 0o077 != 0
        {
            return Err(SshConfigError::KnownHostsSnapshotFailed);
        }
        validate_unix_temp_ancestors(&canonical_directory, opened_metadata.uid())?;
        Ok(PrivateSnapshotDirectory {
            temporary,
            _handle: handle,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(PrivateSnapshotDirectory { temporary })
    }
}

fn validate_openssh_path(path: &Path) -> Result<(), SshConfigError> {
    if !path.is_absolute() {
        return Err(SshConfigError::KnownHostsSnapshotFailed);
    }
    let path = path
        .to_str()
        .ok_or(SshConfigError::KnownHostsSnapshotFailed)?;
    if path
        .chars()
        .any(|character| character.is_control() || matches!(character, '%' | '$'))
    {
        return Err(SshConfigError::KnownHostsSnapshotFailed);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_temp_ancestors(directory: &Path, current_uid: u32) -> Result<(), SshConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    for ancestor in directory.ancestors().skip(1) {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| SshConfigError::KnownHostsSnapshotFailed)?;
        let mode = metadata.mode();
        let owned_by_trusted_principal = metadata.uid() == current_uid || metadata.uid() == 0;
        let writable_by_another_principal = mode & 0o022 != 0;
        let sticky = mode & u32::from(libc::S_ISVTX) != 0;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || !owned_by_trusted_principal
            || (writable_by_another_principal && !sticky)
        {
            return Err(SshConfigError::KnownHostsSnapshotFailed);
        }
    }
    Ok(())
}

/// Stable, secret-free OpenSSH transport failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SshTransportError {
    /// The client cancelled the operation.
    #[error("SSH worker operation was cancelled")]
    Cancelled,
    /// The request exceeded the local protocol bound.
    #[error("SSH worker request is {bytes} bytes; maximum is {maximum} bytes")]
    RequestTooLarge {
        /// Observed request size.
        bytes: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// The OpenSSH client could not be started.
    #[error("OpenSSH client could not be started")]
    SpawnFailed,
    /// A local pipe failed without exposing worker output.
    #[error("OpenSSH protocol pipe failed")]
    IoFailed,
    /// The fixed operation deadline elapsed.
    #[error("SSH worker operation timed out")]
    TimedOut,
    /// OpenSSH exited unsuccessfully. Stderr remains private.
    #[error("OpenSSH client exited unsuccessfully with status {status:?}")]
    ProcessFailed {
        /// Numeric exit status when the operating system supplied one.
        status: Option<i32>,
    },
    /// The private-key path no longer matched its retained file handle.
    #[error("SSH identity file changed before process start")]
    IdentityFileChanged,
    /// The private host-key snapshot or its retained directory failed revalidation.
    #[error("SSH host-key trust snapshot changed before process start")]
    TrustSnapshotChanged,
    /// Worker stdout exceeded its public protocol limit.
    #[error("SSH worker response exceeded the {maximum}-byte limit")]
    ResponseTooLarge {
        /// Accepted maximum.
        maximum: usize,
    },
}

/// Runtime-neutral boundary around a complete request/response exchange.
pub trait SshRunner: Send + Sync {
    /// Send one bounded JSON request and return one bounded JSON response.
    ///
    /// # Errors
    ///
    /// Returns a stable transport error without exposing remote stderr.
    fn exchange(
        &self,
        invocation: &SshInvocation,
        request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, SshTransportError>;
}

/// OpenSSH-backed runner using argument arrays and piped standard I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessSshRunner;

impl SshRunner for ProcessSshRunner {
    fn exchange(
        &self,
        invocation: &SshInvocation,
        request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, SshTransportError> {
        let deadline = Instant::now() + invocation.timeout();
        if cancellation.is_cancelled() {
            return Err(SshTransportError::Cancelled);
        }
        if request.len() > MAX_SSH_REQUEST_BYTES {
            return Err(SshTransportError::RequestTooLarge {
                bytes: request.len(),
                maximum: MAX_SSH_REQUEST_BYTES,
            });
        }
        invocation
            .revalidate_identity_file()
            .map_err(|_| SshTransportError::IdentityFileChanged)?;
        invocation
            .revalidate_trust_snapshot()
            .map_err(|_| SshTransportError::TrustSnapshotChanged)?;

        let mut child = Command::new(invocation.program())
            .args(invocation.arguments())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| SshTransportError::SpawnFailed)?;
        let Some((stdin, stdout, stderr)) = take_child_pipes(&mut child) else {
            terminate_child_bounded(child, deadline);
            return Err(SshTransportError::IoFailed);
        };
        let request = request.to_vec();
        let Ok(pipe_events) = spawn_pipe_tasks(stdin, stdout, stderr, request) else {
            terminate_child_bounded(child, deadline);
            return Err(SshTransportError::IoFailed);
        };
        let mut write_result = None;
        let mut stdout_result = None;
        let mut stderr_result = None;
        let mut status = None;

        loop {
            if cancellation.is_cancelled() {
                terminate_child_bounded(child, deadline);
                return Err(SshTransportError::Cancelled);
            }
            if Instant::now() >= deadline {
                terminate_child_bounded(child, deadline);
                return Err(SshTransportError::TimedOut);
            }

            if status.is_none() {
                match child.try_wait() {
                    Ok(Some(exit_status)) => status = Some(exit_status),
                    Ok(None) => {}
                    Err(_) => {
                        terminate_child_bounded(child, deadline);
                        return Err(SshTransportError::IoFailed);
                    }
                }
            }

            if drain_pipe_events(
                &pipe_events,
                &mut write_result,
                &mut stdout_result,
                &mut stderr_result,
            )
            .is_err()
            {
                terminate_child_bounded(child, deadline);
                return Err(SshTransportError::IoFailed);
            }

            if let Some(exit_status) = status {
                if !exit_status.success() {
                    return Err(SshTransportError::ProcessFailed {
                        status: exit_status.code(),
                    });
                }
                if write_result.is_some() && stdout_result.is_some() && stderr_result.is_some() {
                    if Instant::now() >= deadline {
                        return Err(SshTransportError::TimedOut);
                    }
                    let write_result = write_result
                        .take()
                        .expect("completed writer result remains available");
                    let stdout = stdout_result
                        .take()
                        .expect("completed stdout result remains available");
                    let stderr = stderr_result
                        .take()
                        .expect("completed stderr result remains available");
                    write_result.map_err(|_| SshTransportError::IoFailed)?;
                    let stdout = stdout.map_err(|_| SshTransportError::IoFailed)?;
                    stderr.map_err(|_| SshTransportError::IoFailed)?;
                    if stdout.exceeded {
                        return Err(SshTransportError::ResponseTooLarge {
                            maximum: MAX_SSH_RESPONSE_BYTES,
                        });
                    }
                    return Ok(stdout.bytes);
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(PROCESS_POLL_INTERVAL.min(remaining));
        }
    }
}

fn take_child_pipes(child: &mut Child) -> Option<(ChildStdin, ChildStdout, ChildStderr)> {
    Some((
        child.stdin.take()?,
        child.stdout.take()?,
        child.stderr.take()?,
    ))
}

enum PipeEvent {
    Write(io::Result<()>),
    Stdout(io::Result<BoundedRead>),
    Stderr(io::Result<BoundedRead>),
}

fn spawn_pipe_tasks(
    mut stdin: impl Write + Send + 'static,
    stdout: impl Read + Send + 'static,
    stderr: impl Read + Send + 'static,
    request: Vec<u8>,
) -> io::Result<Receiver<PipeEvent>> {
    let (sender, receiver) = mpsc::channel();
    let write_sender = sender.clone();
    drop(
        thread::Builder::new()
            .name("rustferry-ssh-stdin".to_owned())
            .spawn(move || {
                let result = stdin.write_all(&request).and_then(|()| stdin.flush());
                let _ = write_sender.send(PipeEvent::Write(result));
            })?,
    );
    let stdout_sender = sender.clone();
    drop(
        thread::Builder::new()
            .name("rustferry-ssh-stdout".to_owned())
            .spawn(move || {
                let _ = stdout_sender.send(PipeEvent::Stdout(read_bounded(
                    stdout,
                    MAX_SSH_RESPONSE_BYTES,
                )));
            })?,
    );
    drop(
        thread::Builder::new()
            .name("rustferry-ssh-stderr".to_owned())
            .spawn(move || {
                let _ = sender.send(PipeEvent::Stderr(read_bounded(
                    stderr,
                    MAX_SSH_STDERR_BYTES,
                )));
            })?,
    );
    Ok(receiver)
}

fn drain_pipe_events(
    receiver: &Receiver<PipeEvent>,
    write_result: &mut Option<io::Result<()>>,
    stdout_result: &mut Option<io::Result<BoundedRead>>,
    stderr_result: &mut Option<io::Result<BoundedRead>>,
) -> Result<(), ()> {
    loop {
        match receiver.try_recv() {
            Ok(PipeEvent::Write(result)) => *write_result = Some(result),
            Ok(PipeEvent::Stdout(result)) => *stdout_result = Some(result),
            Ok(PipeEvent::Stderr(result)) => *stderr_result = Some(result),
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                return if write_result.is_some()
                    && stdout_result.is_some()
                    && stderr_result.is_some()
                {
                    Ok(())
                } else {
                    Err(())
                };
            }
        }
    }
}

pub(crate) fn terminate_child_bounded(mut child: Child, operation_deadline: Instant) {
    let _ = child.kill();
    let cleanup_deadline = operation_deadline.min(Instant::now() + PROCESS_REAP_TIMEOUT);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            spawn_child_reaper(child);
            return;
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(remaining));
    }
}

fn spawn_child_reaper(mut child: Child) {
    let _ = thread::Builder::new()
        .name("rustferry-ssh-reaper".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
}

struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> io::Result<BoundedRead> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut exceeded = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_add(1).saturating_sub(bytes.len());
        let retained = count.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        exceeded |= count > retained || bytes.len() > maximum;
    }
    Ok(BoundedRead { bytes, exceeded })
}

#[cfg(test)]
pub(crate) fn test_invocation(
    program: impl Into<OsString>,
    arguments: impl IntoIterator<Item = OsString>,
    timeout: Duration,
) -> SshInvocation {
    let snapshot_directory =
        create_private_snapshot_directory().expect("private snapshot directory");
    let known_hosts_snapshot =
        NamedTempFile::new_in(snapshot_directory.path()).expect("snapshot placeholder");
    let known_hosts_identity =
        snapshot_file_identity(&known_hosts_snapshot).expect("snapshot identity");
    SshInvocation {
        program: program.into(),
        arguments: arguments.into_iter().collect(),
        timeout,
        known_hosts_snapshot,
        known_hosts_identity,
        snapshot_directory,
        identity_file_guard: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hosts_option_quotes_lists_and_escapes_tokens() {
        let option =
            known_hosts_option(Path::new("/tmp/rust ferry/\"key\"")).expect("quoted OpenSSH path");
        assert_eq!(
            option,
            OsString::from("UserKnownHostsFile=\"/tmp/rust ferry/\\\"key\\\"\"")
        );
    }

    #[test]
    fn known_hosts_option_rejects_openssh_expansions() {
        for path in ["/tmp/%h/known_hosts", "/tmp/${HOME}/known_hosts"] {
            assert_eq!(
                known_hosts_option(Path::new(path)),
                Err(SshConfigError::KnownHostsSnapshotFailed)
            );
        }
    }

    #[test]
    fn process_deadline_does_not_join_descendant_held_pipes() {
        let invocation = subprocess_invocation(
            "transport::tests::subprocess_exits_while_descendant_holds_pipes",
            Duration::from_millis(150),
        );
        let started = Instant::now();
        assert_eq!(
            ProcessSshRunner.exchange(&invocation, b"{}\n", &CancellationToken::new()),
            Err(SshTransportError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn process_cancellation_has_bounded_reap_and_no_thread_joins() {
        let invocation = subprocess_invocation(
            "transport::tests::subprocess_pipe_holder",
            Duration::from_secs(5),
        );
        let cancellation = CancellationToken::new();
        let cancellation_request = cancellation.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _ = cancellation_request.cancel();
        });
        let started = Instant::now();
        assert_eq!(
            ProcessSshRunner.exchange(&invocation, b"{}\n", &cancellation),
            Err(SshTransportError::Cancelled)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn subprocess_invocation(test_name: &str, timeout: Duration) -> SshInvocation {
        let snapshot_directory =
            create_private_snapshot_directory().expect("private snapshot directory");
        let known_hosts_snapshot =
            NamedTempFile::new_in(snapshot_directory.path()).expect("snapshot placeholder");
        let known_hosts_identity =
            snapshot_file_identity(&known_hosts_snapshot).expect("snapshot identity");
        SshInvocation {
            program: std::env::current_exe()
                .expect("current test executable")
                .into_os_string(),
            arguments: ["--exact", test_name, "--ignored", "--nocapture"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            timeout,
            known_hosts_snapshot,
            known_hosts_identity,
            snapshot_directory,
            identity_file_guard: None,
        }
    }

    #[test]
    #[ignore = "subprocess helper"]
    #[allow(clippy::zombie_processes)]
    fn subprocess_exits_while_descendant_holds_pipes() {
        Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "transport::tests::subprocess_pipe_holder",
                "--ignored",
                "--nocapture",
            ])
            .spawn()
            .expect("pipe-holding descendant");
    }

    #[test]
    #[ignore = "subprocess helper"]
    fn subprocess_pipe_holder() {
        thread::sleep(Duration::from_secs(2));
    }
}
