//! OpenSSH-backed execution for one framed snapshot session.

use std::{
    fs::File,
    io::{self, Read, Write},
    panic::{self, AssertUnwindSafe},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use camino::Utf8Path;
use rustferry_remote::{
    CancellationToken, ProtocolPath, RemoteBuildEvent, SnapshotArtifactDescriptor,
    WorkerDataPlaneFrameKind, write_worker_data_plane_frame,
};
use thiserror::Error;

use crate::{
    session::{
        CreateOnlyArtifactSpool, SnapshotSessionClientError, SnapshotSessionOutcome,
        SnapshotSessionProgress, SnapshotSessionRequest, run_snapshot_session_deferred,
    },
    transport::{ProcessSshRunner, SshInvocation, SshTransportError, terminate_child_bounded},
};

const SESSION_IO_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SESSION_CANCEL_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
const SESSION_EXIT_OBSERVATION_TIMEOUT: Duration = Duration::from_millis(100);
const SESSION_STDERR_BUFFER_BYTES: usize = 16 * 1024;
const SESSION_PIPE_CHUNK_BYTES: usize = 16 * 1024;

/// Stable distinction between a validated session failure and process transport failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SshSnapshotSessionError {
    /// Framing, peer identity, artifact verification, publication, or cleanup failed.
    #[error(transparent)]
    Session(#[from] SnapshotSessionClientError),
    /// OpenSSH spawn, pipe, cancellation, timeout, or exit status failed.
    #[error(transparent)]
    Transport(#[from] SshTransportError),
}

impl ProcessSshRunner {
    /// Run one full-duplex framed snapshot build through the fixed OpenSSH invocation.
    ///
    /// Successful protocol completion and a zero OpenSSH exit authorize the artifact
    /// guard. The caller must still invoke [`CreateOnlyArtifactSpool::commit`] after
    /// its own supporting-output checks.
    ///
    /// # Errors
    ///
    /// Distinguishes validated session failures from secret-free transport failures.
    #[allow(clippy::too_many_arguments)]
    pub fn run_snapshot_session<EventSink, Verifier, VerifyError>(
        &self,
        invocation: &SshInvocation,
        request: SnapshotSessionRequest<'_>,
        artifact_spool: &mut CreateOnlyArtifactSpool,
        cancellation: &CancellationToken,
        on_event: EventSink,
        verify_artifact: Verifier,
    ) -> Result<SnapshotSessionOutcome, SshSnapshotSessionError>
    where
        EventSink: FnMut(RemoteBuildEvent),
        Verifier: FnOnce(
            &mut File,
            &Utf8Path,
            &SnapshotArtifactDescriptor,
        ) -> Result<ProtocolPath, VerifyError>,
    {
        let deadline = Instant::now() + invocation.timeout();
        if cancellation.is_cancelled() {
            return transport_error(artifact_spool, SshTransportError::Cancelled);
        }
        if invocation.revalidate_identity_file().is_err() {
            return transport_error(artifact_spool, SshTransportError::IdentityFileChanged);
        }
        if invocation.revalidate_trust_snapshot().is_err() {
            return transport_error(artifact_spool, SshTransportError::TrustSnapshotChanged);
        }

        let Ok(mut child) = Command::new(invocation.program())
            .args(invocation.arguments())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return transport_error(artifact_spool, SshTransportError::SpawnFailed);
        };
        let Some(stdin) = child.stdin.take() else {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        };

        let abort = AbortController::new(cancellation.clone(), deadline);
        if spawn_stderr_drain(stderr).is_err() {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        }
        let Ok(stdout_events) = spawn_stdout_reader(stdout) else {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        };
        let Ok(mut writer) = InterruptibleWriter::spawn(stdin, abort.clone()) else {
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, SshTransportError::IoFailed);
        };
        let mut reader = InterruptibleReader::new(stdout_events, abort.clone());
        let mut progress = SnapshotSessionProgress::default();

        let session = panic::catch_unwind(AssertUnwindSafe(|| {
            run_snapshot_session_deferred(
                &mut reader,
                &mut writer,
                request,
                artifact_spool,
                on_event,
                verify_artifact,
                &mut progress,
            )
        }));
        let session = match session {
            Ok(session) => session,
            Err(payload) => {
                if progress.can_send_cancel() && writer.best_effort_cancel() {
                    progress.mark_cancel_sent();
                }
                drop(writer);
                terminate_child_bounded(child, deadline);
                let _ = artifact_spool.cleanup_failure();
                panic::resume_unwind(payload);
            }
        };
        let outcome = match session {
            Ok(outcome) => outcome,
            Err(error) => {
                if progress.can_send_cancel() && writer.best_effort_cancel() {
                    progress.mark_cancel_sent();
                }
                drop(writer);
                return finish_failed_session(child, deadline, &abort, error);
            }
        };

        if writer.close().is_err() {
            let error = classify_abort(&abort).unwrap_or(SshTransportError::IoFailed);
            terminate_child_bounded(child, deadline);
            return transport_error(artifact_spool, error);
        }
        wait_for_successful_exit(child, deadline, &abort)
            .or_else(|error| transport_error(artifact_spool, error))?;
        if let Err(error) = artifact_spool.authorize_commit() {
            return session_error(artifact_spool, error);
        }
        Ok(outcome)
    }
}

fn session_error<T>(
    spool: &mut CreateOnlyArtifactSpool,
    error: SnapshotSessionClientError,
) -> Result<T, SshSnapshotSessionError> {
    spool.cleanup_failure()?;
    Err(SshSnapshotSessionError::Session(error))
}

fn transport_error<T>(
    spool: &mut CreateOnlyArtifactSpool,
    error: SshTransportError,
) -> Result<T, SshSnapshotSessionError> {
    spool.cleanup_failure()?;
    Err(SshSnapshotSessionError::Transport(error))
}

fn finish_failed_session<T>(
    mut child: Child,
    deadline: Instant,
    abort: &AbortController,
    session_error: SnapshotSessionClientError,
) -> Result<T, SshSnapshotSessionError> {
    if !matches!(session_error, SnapshotSessionClientError::DataPlane(_)) {
        terminate_child_bounded(child, deadline);
        return Err(SshSnapshotSessionError::Session(session_error));
    }
    if let Some(error) = classify_cancel_or_timeout(abort) {
        terminate_child_bounded(child, deadline);
        return Err(SshSnapshotSessionError::Transport(error));
    }
    if let Some(status) = observe_exit_status(&mut child, deadline, &session_error) {
        return if status.success() {
            Err(SshSnapshotSessionError::Session(session_error))
        } else {
            Err(SshSnapshotSessionError::Transport(
                SshTransportError::ProcessFailed {
                    status: status.code(),
                },
            ))
        };
    }
    let transport = classify_abort(abort);
    terminate_child_bounded(child, deadline);
    match transport {
        Some(error) => Err(SshSnapshotSessionError::Transport(error)),
        None => Err(SshSnapshotSessionError::Session(session_error)),
    }
}

fn classify_cancel_or_timeout(abort: &AbortController) -> Option<SshTransportError> {
    if abort.cancellation.is_cancelled() {
        abort.mark(AbortReason::Cancelled);
    } else if Instant::now() >= abort.deadline {
        abort.mark(AbortReason::TimedOut);
    }
    match abort.reason() {
        AbortReason::Cancelled => Some(SshTransportError::Cancelled),
        AbortReason::TimedOut => Some(SshTransportError::TimedOut),
        AbortReason::Active | AbortReason::IoFailed => None,
    }
}

fn observe_exit_status(
    child: &mut Child,
    deadline: Instant,
    error: &SnapshotSessionClientError,
) -> Option<ExitStatus> {
    let observe_until = if matches!(error, SnapshotSessionClientError::DataPlane(_)) {
        deadline.min(Instant::now() + SESSION_EXIT_OBSERVATION_TIMEOUT)
    } else {
        Instant::now()
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        let remaining = observe_until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(SESSION_IO_POLL_INTERVAL.min(remaining));
    }
}

fn wait_for_successful_exit(
    mut child: Child,
    deadline: Instant,
    abort: &AbortController,
) -> Result<(), SshTransportError> {
    loop {
        if let Some(error) = classify_abort(abort) {
            terminate_child_bounded(child, deadline);
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(SshTransportError::ProcessFailed {
                    status: status.code(),
                });
            }
            Ok(None) => {}
            Err(_) => {
                terminate_child_bounded(child, deadline);
                return Err(SshTransportError::IoFailed);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            abort.mark(AbortReason::TimedOut);
            terminate_child_bounded(child, deadline);
            return Err(SshTransportError::TimedOut);
        }
        thread::sleep(SESSION_IO_POLL_INTERVAL.min(remaining));
    }
}

#[derive(Clone)]
struct AbortController {
    state: Arc<AtomicU8>,
    cancellation: CancellationToken,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AbortReason {
    Active = 0,
    Cancelled = 1,
    TimedOut = 2,
    IoFailed = 3,
}

impl AbortController {
    fn new(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            state: Arc::new(AtomicU8::new(AbortReason::Active as u8)),
            cancellation,
            deadline,
        }
    }

    fn checkpoint(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            self.mark(AbortReason::Cancelled);
        } else if Instant::now() >= self.deadline {
            self.mark(AbortReason::TimedOut);
        }
        match self.reason() {
            AbortReason::Active => Ok(()),
            AbortReason::Cancelled => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "snapshot session cancelled",
            )),
            AbortReason::TimedOut => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "snapshot session timed out",
            )),
            AbortReason::IoFailed => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snapshot session pipe failed",
            )),
        }
    }

    fn wait_interval(&self) -> Duration {
        SESSION_IO_POLL_INTERVAL.min(self.deadline.saturating_duration_since(Instant::now()))
    }

    fn mark(&self, reason: AbortReason) {
        let _ = self.state.compare_exchange(
            AbortReason::Active as u8,
            reason as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn reason(&self) -> AbortReason {
        match self.state.load(Ordering::Acquire) {
            1 => AbortReason::Cancelled,
            2 => AbortReason::TimedOut,
            3 => AbortReason::IoFailed,
            _ => AbortReason::Active,
        }
    }
}

fn classify_abort(abort: &AbortController) -> Option<SshTransportError> {
    if abort.cancellation.is_cancelled() {
        abort.mark(AbortReason::Cancelled);
    } else if Instant::now() >= abort.deadline {
        abort.mark(AbortReason::TimedOut);
    }
    match abort.reason() {
        AbortReason::Active => None,
        AbortReason::Cancelled => Some(SshTransportError::Cancelled),
        AbortReason::TimedOut => Some(SshTransportError::TimedOut),
        AbortReason::IoFailed => Some(SshTransportError::IoFailed),
    }
}

enum StdoutEvent {
    Bytes(Vec<u8>),
    Eof,
    Failed,
}

fn spawn_stdout_reader(mut stdout: ChildStdout) -> Result<Receiver<StdoutEvent>, ()> {
    let (sender, receiver) = mpsc::sync_channel(2);
    thread::Builder::new()
        .name("rustferry-ssh-session-stdout".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; SESSION_PIPE_CHUNK_BYTES];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        let _ = sender.send(StdoutEvent::Eof);
                        return;
                    }
                    Ok(count) => {
                        if sender
                            .send(StdoutEvent::Bytes(buffer[..count].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = sender.send(StdoutEvent::Failed);
                        return;
                    }
                }
            }
        })
        .map(drop)
        .map_err(|_| ())?;
    Ok(receiver)
}

fn spawn_stderr_drain(mut stderr: ChildStderr) -> io::Result<()> {
    thread::Builder::new()
        .name("rustferry-ssh-session-stderr".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; SESSION_STDERR_BUFFER_BYTES];
            while let Ok(count) = stderr.read(&mut buffer) {
                if count == 0 {
                    return;
                }
            }
        })
        .map(drop)
}

struct InterruptibleReader {
    events: Receiver<StdoutEvent>,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
    abort: AbortController,
}

impl InterruptibleReader {
    fn new(events: Receiver<StdoutEvent>, abort: AbortController) -> Self {
        Self {
            events,
            pending: Vec::new(),
            offset: 0,
            eof: false,
            abort,
        }
    }
}

impl Read for InterruptibleReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.offset < self.pending.len() {
                let count = buffer.len().min(self.pending.len() - self.offset);
                buffer[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
                self.offset += count;
                if self.offset == self.pending.len() {
                    self.pending.clear();
                    self.offset = 0;
                }
                return Ok(count);
            }
            if self.eof {
                return Ok(0);
            }
            self.abort.checkpoint()?;
            match self.events.recv_timeout(self.abort.wait_interval()) {
                Ok(StdoutEvent::Bytes(bytes)) => self.pending = bytes,
                Ok(StdoutEvent::Eof) => self.eof = true,
                Ok(StdoutEvent::Failed) | Err(RecvTimeoutError::Disconnected) => {
                    self.abort.mark(AbortReason::IoFailed);
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "snapshot session stdout failed",
                    ));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

enum StdinCommand {
    Write {
        bytes: Vec<u8>,
        flush: bool,
        result: SyncSender<io::Result<()>>,
    },
    Close {
        result: SyncSender<io::Result<()>>,
    },
}

struct InterruptibleWriter {
    commands: SyncSender<StdinCommand>,
    abort: AbortController,
}

impl InterruptibleWriter {
    fn spawn(mut stdin: ChildStdin, abort: AbortController) -> Result<Self, ()> {
        let (commands, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("rustferry-ssh-session-stdin".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        StdinCommand::Write {
                            bytes,
                            flush,
                            result,
                        } => {
                            let written = stdin
                                .write_all(&bytes)
                                .and_then(|()| if flush { stdin.flush() } else { Ok(()) });
                            let failed = written.is_err();
                            let _ = result.send(written);
                            if failed {
                                return;
                            }
                        }
                        StdinCommand::Close { result } => {
                            let flushed = stdin.flush();
                            drop(stdin);
                            let _ = result.send(flushed);
                            return;
                        }
                    }
                }
            })
            .map(drop)
            .map_err(|_| ())?;
        Ok(Self { commands, abort })
    }

    fn request(&self, bytes: Vec<u8>, flush: bool) -> io::Result<()> {
        self.abort.checkpoint()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send_command(StdinCommand::Write {
            bytes,
            flush,
            result: sender,
        })?;
        self.wait_result(&receiver)
    }

    fn send_command(&self, mut command: StdinCommand) -> io::Result<()> {
        loop {
            self.abort.checkpoint()?;
            match self.commands.try_send(command) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) => command = returned,
                Err(TrySendError::Disconnected(_)) => {
                    self.abort.mark(AbortReason::IoFailed);
                    return self.abort.checkpoint();
                }
            }
            thread::sleep(self.abort.wait_interval());
        }
    }

    fn wait_result(&self, receiver: &Receiver<io::Result<()>>) -> io::Result<()> {
        loop {
            self.abort.checkpoint()?;
            match receiver.recv_timeout(self.abort.wait_interval()) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                    self.abort.mark(AbortReason::IoFailed);
                    return self.abort.checkpoint();
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn best_effort_cancel(&self) -> bool {
        let mut bytes = Vec::new();
        if write_worker_data_plane_frame(&mut bytes, WorkerDataPlaneFrameKind::Cancel, 3, &[])
            .is_err()
        {
            return false;
        }
        let deadline = Instant::now() + SESSION_CANCEL_WRITE_TIMEOUT;
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut command = StdinCommand::Write {
            bytes,
            flush: true,
            result: sender,
        };
        loop {
            match self.commands.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => command = returned,
                Err(TrySendError::Disconnected(_)) => return false,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            thread::sleep(SESSION_IO_POLL_INTERVAL.min(remaining));
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match receiver.recv_timeout(SESSION_IO_POLL_INTERVAL.min(remaining)) {
                Ok(Ok(())) => return true,
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => return false,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn close(self) -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send_command(StdinCommand::Close { result: sender })?;
        self.wait_result(&receiver)
    }
}

impl Write for InterruptibleWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.request(buffer.to_vec(), false)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.request(Vec::new(), true)
    }
}
