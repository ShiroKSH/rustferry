//! One-shot framed SSH snapshot-build worker session.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};

use camino::{Utf8Path, Utf8PathBuf};
use cap_std::{ambient_authority, fs::Dir as CapabilityDir};
use rustferry_remote::{
    ArtifactKind, ArtifactRecord, COMPILE_HANDOFF_SCHEMA_VERSION, CancellationToken,
    CleanupConfirmation, CompileHandoff, IosArtifactType, IosDeviceBuildRequest, JobState,
    MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES, RemoteBuildEvent, RemoteBuildEventKind,
    SnapshotArtifactDescriptor, SnapshotArtifactReceipt, SnapshotBuildComplete, SnapshotBuildStart,
    SnapshotJobAccepted, SnapshotSessionError, SourceArchiveLimits, SourceBundleDescriptor,
    WorkerDataPlaneFrameError, WorkerDataPlaneFrameHeader, WorkerDataPlaneFrameKind,
    WorkerDataPlaneSequence, canonical_request_sha256, copy_worker_data_plane_payload,
    read_worker_data_plane_header, read_worker_data_plane_payload,
    verify_and_extract_source_bundle, write_worker_data_plane_frame,
    write_worker_data_plane_stream,
};
use same_file::Handle;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::stdio::{SSH_STDIO_PROVIDER_ID, SSH_STDIO_WORKER_ID};

const JOB_MARKER_NAME: &str = ".rustferry-worker-job-v1.json";
const SOURCE_ARCHIVE_NAME: &str = "source.zip";
const SOURCE_DIRECTORY_NAME: &str = "source";
const ARTIFACTS_DIRECTORY_NAME: &str = "artifacts";
const UNSIGNED_ARCHIVE_NAME: &str = "unsigned-archive.zip";
const UNSIGNED_ARTIFACT_ID: &str = "unsigned-xcarchive";
const INPUT_READ_CHUNK_BYTES: usize = 16 * 1024;
const INPUT_TOTAL_DEADLINE: Duration = Duration::from_mins(10);
const INPUT_INACTIVITY_DEADLINE: Duration = Duration::from_secs(30);
const RECEIPT_DEADLINE: Duration = Duration::from_mins(2);

/// Exact inputs supplied to the production unsigned compiler.
pub struct SnapshotCompileContext<'a> {
    request: &'a IosDeviceBuildRequest,
    source_root: &'a Utf8Path,
    output_directory: &'a Utf8Path,
    job_id: &'a str,
    cancellation: &'a CancellationToken,
}

impl SnapshotCompileContext<'_> {
    /// Fully reconstructed and validated snapshot request.
    pub fn request(&self) -> &IosDeviceBuildRequest {
        self.request
    }

    /// Verified materialized source root.
    pub fn source_root(&self) -> &Utf8Path {
        self.source_root
    }

    /// Fresh worker-owned artifact directory.
    pub fn output_directory(&self) -> &Utf8Path {
        self.output_directory
    }

    /// Provider-owned job identifier.
    pub fn job_id(&self) -> &str {
        self.job_id
    }

    /// Token bound to Apple subprocess cancellation by the production adapter.
    pub fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
}

/// Exact public output returned by a snapshot compiler adapter.
pub struct SnapshotCompileOutput {
    /// Complete request-bound unsigned compile evidence.
    pub handoff: CompileHandoff,
    /// Exact sealed archive file to stream to the client.
    pub artifact_path: Utf8PathBuf,
}

/// Stable secret-free compile adapter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("snapshot compile failed")]
pub struct SnapshotCompileFailure {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl SnapshotCompileFailure {
    /// Construct a bounded public failure from a trusted static category.
    #[must_use]
    pub const fn new(code: &'static str, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
        }
    }
}

/// Trusted adapter for the real physical-iPhone compile pipeline.
pub trait SnapshotCompiler {
    /// Compile one already verified source tree and seal its unsigned archive.
    ///
    /// # Errors
    ///
    /// Returns only a stable public failure; raw tool output must remain private.
    fn compile(
        &mut self,
        context: SnapshotCompileContext<'_>,
    ) -> Result<SnapshotCompileOutput, SnapshotCompileFailure>;
}

/// Failure to complete a structured response on worker stdout.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SnapshotSessionServeError {
    /// A framed response could not be encoded or written.
    #[error("snapshot worker response could not be completed")]
    Output,
}

/// Serve exactly one unsigned snapshot build over the framed worker data plane.
///
/// Input paths never cross this boundary. The worker creates every mutable path
/// below a prevalidated private root and removes it before terminal success.
///
/// # Errors
///
/// Returns only when a structured response cannot be written. Invalid input,
/// build failure, cancellation, and cleanup failure are returned as a framed
/// [`SnapshotSessionError`].
pub fn serve_snapshot_session<R: Read + Send + 'static>(
    reader: R,
    writer: &mut impl Write,
    worker_root: &Utf8Path,
    compiler: &mut dyn SnapshotCompiler,
) -> Result<(), SnapshotSessionServeError> {
    let mut session = Session::new(writer, worker_root);
    match session.run(reader, compiler) {
        Ok(()) => Ok(()),
        Err(failure) => session.finish_failure(failure),
    }
}

#[cfg(test)]
fn serve_snapshot_session_with_job_id<R: Read + Send + 'static>(
    reader: R,
    writer: &mut impl Write,
    worker_root: &Utf8Path,
    compiler: &mut dyn SnapshotCompiler,
    job_id: &str,
) -> Result<(), SnapshotSessionServeError> {
    let mut session = Session::new(writer, worker_root);
    session.job_id_override = Some(job_id.to_owned());
    match session.run(reader, compiler) {
        Ok(()) => Ok(()),
        Err(failure) => session.finish_failure(failure),
    }
}

#[cfg(test)]
fn serve_snapshot_session_with_input_deadlines<R: Read + Send + 'static>(
    reader: R,
    writer: &mut impl Write,
    worker_root: &Utf8Path,
    compiler: &mut dyn SnapshotCompiler,
    job_id: &str,
    total_deadline: Duration,
    inactivity_deadline: Duration,
) -> Result<(), SnapshotSessionServeError> {
    let mut session = Session::new(writer, worker_root);
    session.job_id_override = Some(job_id.to_owned());
    session.input_total_deadline = total_deadline;
    session.input_inactivity_deadline = inactivity_deadline;
    match session.run(reader, compiler) {
        Ok(()) => Ok(()),
        Err(failure) => session.finish_failure(failure),
    }
}

#[repr(u8)]
enum ControlPhaseState {
    Compiling = 0,
    AwaitingReceipt = 1,
}

struct ControlPhase {
    state: AtomicU8,
}

impl ControlPhase {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ControlPhaseState::Compiling as u8),
        }
    }

    fn allow_receipt(&self) {
        self.state
            .store(ControlPhaseState::AwaitingReceipt as u8, Ordering::Release);
    }

    fn receipt_allowed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ControlPhaseState::AwaitingReceipt as u8
    }
}

enum InputChunk {
    Bytes(Vec<u8>),
    End,
    Error(io::Error),
}

struct InactivityReader {
    receiver: mpsc::Receiver<InputChunk>,
    buffered: Vec<u8>,
    offset: usize,
    total_deadline: Option<Instant>,
    inactivity_deadline: Duration,
    timed_out: bool,
}

impl InactivityReader {
    fn spawn(
        mut reader: impl Read + Send + 'static,
        total_deadline: Duration,
        inactivity_deadline: Duration,
    ) -> Result<Self, SessionFailure> {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("rustferry-ssh-session-stream".to_owned())
            .spawn(move || {
                loop {
                    let mut bytes = vec![0_u8; INPUT_READ_CHUNK_BYTES];
                    match reader.read(&mut bytes) {
                        Ok(0) => {
                            let _ = sender.send(InputChunk::End);
                            break;
                        }
                        Ok(read) => {
                            bytes.truncate(read);
                            if sender.send(InputChunk::Bytes(bytes)).is_err() {
                                break;
                            }
                        }
                        Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                        Err(source) => {
                            let _ = sender.send(InputChunk::Error(source));
                            break;
                        }
                    }
                }
            })
            .map_err(|_| SessionFailure::internal("input_reader_failed"))?;
        Ok(Self {
            receiver,
            buffered: Vec::new(),
            offset: 0,
            total_deadline: Instant::now().checked_add(total_deadline),
            inactivity_deadline,
            timed_out: false,
        })
    }

    fn disable_deadlines(&mut self) {
        self.total_deadline = None;
    }

    const fn frame_failure(&self, error: WorkerDataPlaneFrameError) -> SessionFailure {
        if self.timed_out {
            SessionFailure::output("session_input_timed_out")
        } else {
            SessionFailure::frame(error)
        }
    }

    fn receive(&mut self) -> io::Result<InputChunk> {
        let result = if let Some(total_deadline) = self.total_deadline {
            let remaining = total_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.timed_out = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "snapshot input total deadline exceeded",
                ));
            }
            self.receiver
                .recv_timeout(remaining.min(self.inactivity_deadline))
                .map_err(|error| match error {
                    RecvTimeoutError::Timeout => io::Error::new(
                        io::ErrorKind::TimedOut,
                        "snapshot input inactivity deadline exceeded",
                    ),
                    RecvTimeoutError::Disconnected => {
                        io::Error::other("snapshot input reader stopped")
                    }
                })
        } else {
            self.receiver
                .recv()
                .map_err(|_| io::Error::other("snapshot input reader stopped"))
        };
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            self.timed_out = true;
        }
        result
    }
}

impl Read for InactivityReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self
            .total_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.timed_out = true;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "snapshot input total deadline exceeded",
            ));
        }
        if self.offset == self.buffered.len() {
            match self.receive()? {
                InputChunk::Bytes(bytes) => {
                    self.buffered = bytes;
                    self.offset = 0;
                }
                InputChunk::End => return Ok(0),
                InputChunk::Error(source) => return Err(source),
            }
        }
        let available = &self.buffered[self.offset..];
        let read = available.len().min(output.len());
        output[..read].copy_from_slice(&available[..read]);
        self.offset += read;
        Ok(read)
    }
}

struct Session<'a, W> {
    writer: &'a mut W,
    worker_root: &'a Utf8Path,
    output_sequence: u64,
    event_sequence: u64,
    operation_id: Option<String>,
    job_id: Option<String>,
    root: Option<JobRootGuard>,
    job_id_override: Option<String>,
    input_total_deadline: Duration,
    input_inactivity_deadline: Duration,
    control_phase: Arc<ControlPhase>,
}

impl<'a, W: Write> Session<'a, W> {
    fn new(writer: &'a mut W, worker_root: &'a Utf8Path) -> Self {
        Self {
            writer,
            worker_root,
            output_sequence: 0,
            event_sequence: 0,
            operation_id: None,
            job_id: None,
            root: None,
            job_id_override: None,
            input_total_deadline: INPUT_TOTAL_DEADLINE,
            input_inactivity_deadline: INPUT_INACTIVITY_DEADLINE,
            control_phase: Arc::new(ControlPhase::new()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run<R: Read + Send + 'static>(
        &mut self,
        reader: R,
        compiler: &mut dyn SnapshotCompiler,
    ) -> Result<(), SessionFailure> {
        let mut reader = InactivityReader::spawn(
            reader,
            self.input_total_deadline,
            self.input_inactivity_deadline,
        )?;
        let mut input_sequence = WorkerDataPlaneSequence::new();
        let start_header = read_expected_header(
            &mut reader,
            &mut input_sequence,
            WorkerDataPlaneFrameKind::BuildRequest,
        )?;
        let start: SnapshotBuildStart = decode_session_json_payload(&mut reader, start_header)?;
        if start.source_descriptor_size > MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES {
            return Err(SessionFailure::invalid("source_descriptor_too_large"));
        }
        start
            .validate()
            .map_err(|_| SessionFailure::invalid("snapshot_start_invalid"))?;
        self.operation_id = Some(start.parameters.operation_id.clone());

        let descriptor_header = read_expected_header(
            &mut reader,
            &mut input_sequence,
            WorkerDataPlaneFrameKind::SourceDescriptor,
        )?;
        if descriptor_header.payload_bytes() != start.source_descriptor_size {
            return Err(SessionFailure::invalid("source_descriptor_size_mismatch"));
        }
        if descriptor_header.payload_bytes() > MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES {
            return Err(SessionFailure::invalid("source_descriptor_too_large"));
        }
        let descriptor: SourceBundleDescriptor = {
            let descriptor_bytes = read_worker_data_plane_payload(&mut reader, descriptor_header)
                .map_err(|error| reader.frame_failure(error))?;
            if sha256_bytes(&descriptor_bytes) != start.source_descriptor_sha256 {
                return Err(SessionFailure::invalid("source_descriptor_digest_mismatch"));
            }
            serde_json::from_slice(&descriptor_bytes)
                .map_err(|_| SessionFailure::invalid("source_descriptor_invalid"))?
        };
        let request = start
            .reconstruct_request(&descriptor, SourceArchiveLimits::default())
            .map_err(|_| SessionFailure::invalid("snapshot_request_invalid"))?;

        let job_id = self
            .job_id_override
            .take()
            .unwrap_or_else(|| format!("ssh-{}", Uuid::new_v4().simple()));
        let root = JobRootGuard::create(self.worker_root, &job_id, &request.operation_id)?;
        let source_archive_path = root.path().join(SOURCE_ARCHIVE_NAME);
        self.job_id = Some(job_id.clone());
        self.root = Some(root);

        let archive_header = read_expected_header(
            &mut reader,
            &mut input_sequence,
            WorkerDataPlaneFrameKind::SourceArchive,
        )?;
        if archive_header.payload_bytes() != descriptor.archive.size {
            return Err(SessionFailure::invalid("source_archive_size_mismatch"));
        }
        self.root
            .as_ref()
            .ok_or_else(|| SessionFailure::internal("job_root_missing"))?
            .verify()?;
        receive_source_archive(
            &mut reader,
            archive_header,
            &source_archive_path,
            &descriptor,
        )?;
        reader.disable_deadlines();

        let root = self
            .root
            .as_ref()
            .ok_or_else(|| SessionFailure::internal("job_root_missing"))?;
        root.verify()?;
        let source_root = root.path().join(SOURCE_DIRECTORY_NAME);
        verify_and_extract_source_bundle(
            &source_archive_path,
            &descriptor.archive,
            &descriptor.manifest,
            &source_root,
            SourceArchiveLimits::default(),
        )
        .map_err(|_| SessionFailure::invalid("source_archive_invalid"))?;
        remove_exact_file(&source_archive_path)?;
        root.verify()?;

        let output_directory = root.path().join(ARTIFACTS_DIRECTORY_NAME);
        create_private_directory(&output_directory)?;
        let cancellation = CancellationToken::new();
        let (control_sender, control_receiver) = mpsc::sync_channel(2);
        let control_cancellation = cancellation.clone();
        let control_phase = Arc::clone(&self.control_phase);
        thread::Builder::new()
            .name("rustferry-ssh-session-input".to_owned())
            .spawn(move || {
                monitor_client_control(
                    reader,
                    input_sequence,
                    &control_cancellation,
                    &control_phase,
                    &control_sender,
                );
            })
            .map_err(|_| SessionFailure::internal("control_reader_failed"))?;

        let accepted =
            SnapshotJobAccepted::new(request.operation_id.clone(), job_id.clone(), unix_time_ms())
                .map_err(|_| SessionFailure::internal("job_acceptance_invalid"))?;
        self.write_json(WorkerDataPlaneFrameKind::JobAccepted, &accepted)?;
        self.emit_event(
            &request,
            "operation",
            RemoteBuildEventKind::OperationStarted {
                command: "worker.ssh_snapshot_build".to_owned(),
            },
        )?;
        self.emit_event(
            &request,
            "accepted",
            RemoteBuildEventKind::JobCreated {
                state: JobState::Created,
            },
        )?;
        self.emit_event(
            &request,
            "accepted",
            RemoteBuildEventKind::WorkerAssigned {
                worker_id: SSH_STDIO_WORKER_ID.to_owned(),
            },
        )?;
        self.emit_event(
            &request,
            "source",
            RemoteBuildEventKind::SourcePrepared {
                file_count: request.source.entries.len() as u64,
                total_bytes: request.source.total_size,
            },
        )?;
        self.emit_event(
            &request,
            "source",
            RemoteBuildEventKind::SourceUploadStarted {
                total_bytes: descriptor.archive.size,
            },
        )?;
        self.emit_event(
            &request,
            "source",
            RemoteBuildEventKind::SourceUploadProgress {
                uploaded_bytes: descriptor.archive.size,
                total_bytes: descriptor.archive.size,
            },
        )?;
        self.emit_event(
            &request,
            "source",
            RemoteBuildEventKind::SourceVerified {
                sha256: request.source.sha256.clone(),
            },
        )?;
        self.emit_event(
            &request,
            "build",
            RemoteBuildEventKind::PhaseStarted {
                message: Some("Compiling unsigned physical-iPhone archive".to_owned()),
            },
        )?;
        self.writer
            .flush()
            .map_err(|_| SessionFailure::output("output_flush_failed"))?;

        let compile = compiler.compile(SnapshotCompileContext {
            request: &request,
            source_root: &source_root,
            output_directory: &output_directory,
            job_id: &job_id,
            cancellation: &cancellation,
        });
        if cancellation.is_cancelled() {
            return Err(cancellation_failure(&control_receiver));
        }
        let compile = compile.map_err(SessionFailure::compile)?;
        validate_compile_output(&request, &job_id, &output_directory, &compile)?;

        let artifact = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: compile.handoff.compile.sealed_archive.transport.size,
            sha256: compile
                .handoff
                .compile
                .sealed_archive
                .transport
                .sha256
                .clone(),
            media_type: Some("application/zip".to_owned()),
        };
        let artifact_descriptor = SnapshotArtifactDescriptor::new(
            request.operation_id.clone(),
            artifact,
            compile.handoff.compile,
        )
        .map_err(|_| SessionFailure::internal("artifact_descriptor_invalid"))?;
        self.emit_event(
            &request,
            "artifact",
            RemoteBuildEventKind::ArtifactCreated {
                artifact_id: artifact_descriptor.artifact.artifact_id.clone(),
                artifact_type: IosArtifactType::Xcarchive,
            },
        )?;
        self.emit_event(
            &request,
            "artifact",
            RemoteBuildEventKind::ArtifactUploadStarted {
                artifact_id: artifact_descriptor.artifact.artifact_id.clone(),
                total_bytes: artifact_descriptor.artifact.size,
            },
        )?;
        self.write_json(
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            &artifact_descriptor,
        )?;
        self.stream_artifact(&compile.artifact_path, &artifact_descriptor)?;
        // A receipt that becomes readable while the final pipe flush is in
        // progress is causally after all artifact bytes were written. Queue it,
        // but do not act on it until the flush itself succeeds below.
        self.control_phase.allow_receipt();
        self.writer
            .flush()
            .map_err(|_| SessionFailure::output("output_flush_failed"))?;

        let receipt = wait_for_receipt(&control_receiver)?;
        let receipt: SnapshotArtifactReceipt = serde_json::from_slice(&receipt)
            .map_err(|_| SessionFailure::invalid("artifact_receipt_invalid"))?;
        receipt
            .validate_for(&artifact_descriptor)
            .map_err(|_| SessionFailure::invalid("artifact_receipt_mismatch"))?;

        self.emit_event(&request, "cleanup", RemoteBuildEventKind::CleanupStarted)?;
        let cleanup = self.cleanup_root()?;
        self.emit_event(
            &request,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: cleanup.clone(),
            },
        )?;
        let complete = SnapshotBuildComplete::new(request.operation_id, cleanup)
            .map_err(|_| SessionFailure::internal("completion_invalid"))?;
        self.write_json(WorkerDataPlaneFrameKind::Complete, &complete)?;
        self.writer
            .flush()
            .map_err(|_| SessionFailure::output("output_flush_failed"))
    }

    fn emit_event(
        &mut self,
        request: &IosDeviceBuildRequest,
        phase: &str,
        kind: RemoteBuildEventKind,
    ) -> Result<(), SessionFailure> {
        let job_id = self
            .job_id
            .as_deref()
            .ok_or_else(|| SessionFailure::internal("job_id_missing"))?;
        let event = RemoteBuildEvent::new(
            request.operation_id.clone(),
            job_id,
            unix_time_ms(),
            SSH_STDIO_PROVIDER_ID,
            phase,
            self.event_sequence,
            kind,
        )
        .map_err(|_| SessionFailure::internal("event_invalid"))?;
        self.event_sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or_else(|| SessionFailure::internal("event_sequence_exhausted"))?;
        self.write_json(WorkerDataPlaneFrameKind::Event, &event)
    }

    fn write_json(
        &mut self,
        kind: WorkerDataPlaneFrameKind,
        value: &impl Serialize,
    ) -> Result<(), SessionFailure> {
        let payload = serde_json::to_vec(value)
            .map_err(|_| SessionFailure::internal("response_encoding_failed"))?;
        write_worker_data_plane_frame(self.writer, kind, self.output_sequence, &payload)
            .map_err(SessionFailure::frame)?;
        self.output_sequence = self
            .output_sequence
            .checked_add(1)
            .ok_or_else(|| SessionFailure::internal("output_sequence_exhausted"))?;
        Ok(())
    }

    fn stream_artifact(
        &mut self,
        path: &Utf8Path,
        descriptor: &SnapshotArtifactDescriptor,
    ) -> Result<(), SessionFailure> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| SessionFailure::internal("artifact_open_failed"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SessionFailure::internal("artifact_not_regular"));
        }
        let mut file =
            File::open(path).map_err(|_| SessionFailure::internal("artifact_open_failed"))?;
        let identity = Handle::from_file(
            file.try_clone()
                .map_err(|_| SessionFailure::internal("artifact_open_failed"))?,
        )
        .map_err(|_| SessionFailure::internal("artifact_open_failed"))?;
        if metadata.len() != descriptor.artifact.size
            || Handle::from_path(path).ok().as_ref() != Some(&identity)
        {
            return Err(SessionFailure::internal("artifact_identity_mismatch"));
        }
        let mut hashing = HashingReader::new(&mut file);
        write_worker_data_plane_stream(
            self.writer,
            WorkerDataPlaneFrameKind::Artifact,
            self.output_sequence,
            &mut hashing,
            descriptor.artifact.size,
        )
        .map_err(SessionFailure::frame)?;
        self.output_sequence = self
            .output_sequence
            .checked_add(1)
            .ok_or_else(|| SessionFailure::internal("output_sequence_exhausted"))?;
        let (bytes, sha256) = hashing.finish();
        if bytes != descriptor.artifact.size
            || sha256 != descriptor.artifact.sha256
            || Handle::from_path(path).ok().as_ref() != Some(&identity)
        {
            return Err(SessionFailure::internal("artifact_changed_during_stream"));
        }
        Ok(())
    }

    fn cleanup_root(&mut self) -> Result<CleanupConfirmation, SessionFailure> {
        let root = self
            .root
            .as_mut()
            .ok_or_else(|| SessionFailure::internal("job_root_missing"))?;
        let job_id = self
            .job_id
            .as_deref()
            .ok_or_else(|| SessionFailure::internal("job_id_missing"))?;
        root.cleanup()?;
        Ok(CleanupConfirmation {
            job_id: job_id.to_owned(),
            completed_at_ms: unix_time_ms(),
            workspace_removed: true,
            signing_material_removed: true,
            artifacts_retained: false,
        })
    }

    fn finish_failure(
        &mut self,
        mut failure: SessionFailure,
    ) -> Result<(), SnapshotSessionServeError> {
        let cleanup = if self.root.as_ref().is_some_and(JobRootGuard::is_owned) {
            if let Ok(cleanup) = self.cleanup_root() {
                Some(cleanup)
            } else {
                failure = SessionFailure::cleanup("worker_cleanup_failed");
                None
            }
        } else {
            None
        };
        let error = SnapshotSessionError::new(
            self.operation_id.clone(),
            self.job_id.clone(),
            failure.code,
            failure.message,
            failure.retryable,
            cleanup,
        )
        .map_err(|_| SnapshotSessionServeError::Output)?;
        self.write_json(WorkerDataPlaneFrameKind::Error, &error)
            .map_err(|_| SnapshotSessionServeError::Output)?;
        self.writer
            .flush()
            .map_err(|_| SnapshotSessionServeError::Output)
    }
}

fn read_expected_header(
    reader: &mut InactivityReader,
    sequence: &mut WorkerDataPlaneSequence,
    expected: WorkerDataPlaneFrameKind,
) -> Result<WorkerDataPlaneFrameHeader, SessionFailure> {
    let header =
        read_worker_data_plane_header(reader).map_err(|error| reader.frame_failure(error))?;
    sequence.accept(header).map_err(SessionFailure::frame)?;
    if header.kind() != expected {
        return Err(SessionFailure::invalid("unexpected_frame_kind"));
    }
    Ok(header)
}

fn decode_session_json_payload<T: serde::de::DeserializeOwned>(
    reader: &mut InactivityReader,
    header: WorkerDataPlaneFrameHeader,
) -> Result<T, SessionFailure> {
    let payload = read_worker_data_plane_payload(reader, header)
        .map_err(|error| reader.frame_failure(error))?;
    serde_json::from_slice(&payload).map_err(|_| SessionFailure::invalid("control_json_invalid"))
}

#[cfg(test)]
fn decode_json_payload<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    header: WorkerDataPlaneFrameHeader,
) -> Result<T, SessionFailure> {
    let payload = read_worker_data_plane_payload(reader, header).map_err(SessionFailure::frame)?;
    serde_json::from_slice(&payload).map_err(|_| SessionFailure::invalid("control_json_invalid"))
}

fn receive_source_archive(
    reader: &mut InactivityReader,
    header: WorkerDataPlaneFrameHeader,
    path: &Utf8Path,
    descriptor: &SourceBundleDescriptor,
) -> Result<(), SessionFailure> {
    let mut file = create_private_file(path)?;
    let mut hashing = HashingWriter::new(&mut file);
    let copied = copy_worker_data_plane_payload(reader, &mut hashing, header)
        .map_err(|error| reader.frame_failure(error))?;
    let (bytes, sha256) = hashing.finish();
    file.flush()
        .and_then(|()| file.sync_all())
        .map_err(|_| SessionFailure::internal("source_archive_write_failed"))?;
    if copied != descriptor.archive.size
        || bytes != descriptor.archive.size
        || sha256 != descriptor.archive.sha256
    {
        return Err(SessionFailure::invalid("source_archive_digest_mismatch"));
    }
    Ok(())
}

fn monitor_client_control(
    mut reader: InactivityReader,
    mut sequence: WorkerDataPlaneSequence,
    cancellation: &CancellationToken,
    phase: &ControlPhase,
    sender: &mpsc::SyncSender<ClientControl>,
) {
    let message = match read_worker_data_plane_header(&mut reader) {
        Ok(header) => match sequence.accept(header) {
            Err(error) => ClientControl::Failure(SessionFailure::frame(error)),
            Ok(()) => match header.kind() {
                WorkerDataPlaneFrameKind::Cancel => {
                    match read_worker_data_plane_payload(&mut reader, header) {
                        Ok(payload) if payload.is_empty() => ClientControl::Cancelled,
                        Ok(_) => ClientControl::Failure(SessionFailure::invalid(
                            "cancellation_payload_invalid",
                        )),
                        Err(error) => ClientControl::Failure(SessionFailure::frame(error)),
                    }
                }
                WorkerDataPlaneFrameKind::ArtifactReceipt => {
                    if phase.receipt_allowed() {
                        match read_worker_data_plane_payload(&mut reader, header) {
                            Ok(payload) => ClientControl::Receipt(payload),
                            Err(error) => ClientControl::Failure(reader.frame_failure(error)),
                        }
                    } else {
                        ClientControl::Failure(SessionFailure::invalid(
                            "artifact_receipt_too_early",
                        ))
                    }
                }
                _ => ClientControl::Failure(SessionFailure::invalid("unexpected_client_control")),
            },
        },
        Err(WorkerDataPlaneFrameError::EmptyInput) => ClientControl::Disconnected,
        Err(error) => ClientControl::Failure(reader.frame_failure(error)),
    };
    let cancels = !matches!(message, ClientControl::Receipt(_));
    let _ = sender.send(message);
    if cancels {
        let _ = cancellation.cancel();
    }
}

fn cancellation_failure(receiver: &mpsc::Receiver<ClientControl>) -> SessionFailure {
    match receiver.try_recv() {
        Ok(ClientControl::Failure(error)) => error,
        Ok(ClientControl::Cancelled | ClientControl::Disconnected | ClientControl::Receipt(_))
        | Err(_) => SessionFailure::cancelled(),
    }
}

fn wait_for_receipt(receiver: &mpsc::Receiver<ClientControl>) -> Result<Vec<u8>, SessionFailure> {
    match receiver.recv_timeout(RECEIPT_DEADLINE) {
        Ok(ClientControl::Receipt(payload)) => Ok(payload),
        Ok(ClientControl::Cancelled | ClientControl::Disconnected) => {
            Err(SessionFailure::cancelled())
        }
        Ok(ClientControl::Failure(error)) => Err(error),
        Err(RecvTimeoutError::Timeout) => Err(SessionFailure::output("artifact_receipt_timed_out")),
        Err(RecvTimeoutError::Disconnected) => {
            Err(SessionFailure::internal("control_reader_stopped"))
        }
    }
}

enum ClientControl {
    Receipt(Vec<u8>),
    Cancelled,
    Disconnected,
    Failure(SessionFailure),
}

fn validate_compile_output(
    request: &IosDeviceBuildRequest,
    job_id: &str,
    output_directory: &Utf8Path,
    output: &SnapshotCompileOutput,
) -> Result<(), SessionFailure> {
    let expected_path = output_directory.join(UNSIGNED_ARCHIVE_NAME);
    if output.artifact_path != expected_path
        || output.handoff.schema_version != COMPILE_HANDOFF_SCHEMA_VERSION
        || output.handoff.request != *request
        || output.handoff.compile.job_id != job_id
        || output.handoff.compile.provider != SSH_STDIO_PROVIDER_ID
        || output.handoff.compile.source_sha256 != request.source.sha256
        || output.handoff.compile.request_sha256
            != canonical_request_sha256(request)
                .map_err(|_| SessionFailure::internal("request_digest_failed"))?
    {
        return Err(SessionFailure::internal("compile_evidence_mismatch"));
    }
    Ok(())
}

struct JobRootGuard {
    worker_root: Utf8PathBuf,
    worker_root_directory: CapabilityDir,
    worker_root_identity: Handle,
    name: String,
    path: Utf8PathBuf,
    directory: Option<CapabilityDir>,
    identity: Handle,
    owned: bool,
}

impl JobRootGuard {
    fn create(
        worker_root: &Utf8Path,
        job_id: &str,
        operation_id: &str,
    ) -> Result<Self, SessionFailure> {
        validate_worker_root(worker_root)?;
        let worker_root_directory =
            CapabilityDir::open_ambient_dir(worker_root.as_std_path(), ambient_authority())
                .map_err(|_| SessionFailure::internal("worker_root_invalid"))?;
        let worker_root_identity = capability_directory_identity(&worker_root_directory)
            .map_err(|_| SessionFailure::internal("worker_root_invalid"))?;
        if Handle::from_path(worker_root).ok().as_ref() != Some(&worker_root_identity) {
            return Err(SessionFailure::internal("worker_root_invalid"));
        }
        let name = format!("rustferry-compile-{job_id}");
        let path = worker_root.join(&name);
        create_private_capability_directory(&worker_root_directory, &name)
            .map_err(|_| SessionFailure::internal("job_root_create_failed"))?;
        let Ok(directory) = worker_root_directory.open_dir(&name) else {
            let _ = worker_root_directory.remove_dir(&name);
            return Err(SessionFailure::internal("job_root_create_failed"));
        };
        let Ok(identity) = capability_directory_identity(&directory) else {
            let _ = directory.remove_open_dir_all();
            return Err(SessionFailure::internal("job_root_create_failed"));
        };
        let named_metadata = worker_root_directory.symlink_metadata(&name);
        let opened_metadata = directory.dir_metadata();
        if !matches!(named_metadata, Ok(metadata) if metadata.is_dir() && !metadata.is_symlink())
            || !matches!(opened_metadata, Ok(metadata) if metadata.is_dir() && !metadata.is_symlink())
            || Handle::from_path(&path).ok().as_ref() != Some(&identity)
        {
            let _ = directory.remove_open_dir_all();
            return Err(SessionFailure::internal("job_root_create_failed"));
        }
        let mut guard = Self {
            worker_root: worker_root.to_owned(),
            worker_root_directory,
            worker_root_identity,
            name,
            path,
            directory: Some(directory),
            identity,
            owned: true,
        };
        let marker = serde_json::json!({
            "schema_version": 1,
            "owner": "rustferry-worker-macos",
            "job_id": job_id,
            "operation_id": operation_id,
            "provider": SSH_STDIO_PROVIDER_ID,
        });
        let Ok(marker_bytes) = serde_json::to_vec(&marker) else {
            let _ = guard.cleanup();
            return Err(SessionFailure::internal("job_marker_failed"));
        };
        if let Err(error) = (|| {
            let mut file = create_private_file(&guard.path.join(JOB_MARKER_NAME))?;
            file.write_all(&marker_bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| SessionFailure::internal("job_marker_failed"))?;
            sync_directory(&guard.path)
        })() {
            let _ = guard.cleanup();
            return Err(error);
        }
        Ok(guard)
    }

    fn path(&self) -> &Utf8Path {
        &self.path
    }

    const fn is_owned(&self) -> bool {
        self.owned
    }

    fn verify(&self) -> Result<(), SessionFailure> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| SessionFailure::cleanup("job_root_changed"))?;
        let open_worker_root = capability_directory_identity(&self.worker_root_directory).ok();
        let open_job_root = capability_directory_identity(directory).ok();
        let named_job_root = self
            .worker_root_directory
            .open_dir(&self.name)
            .ok()
            .and_then(|directory| capability_directory_identity(&directory).ok());
        if !self.owned
            || open_worker_root.as_ref() != Some(&self.worker_root_identity)
            || Handle::from_path(&self.worker_root).ok().as_ref()
                != Some(&self.worker_root_identity)
            || open_job_root.as_ref() != Some(&self.identity)
            || named_job_root.as_ref() != Some(&self.identity)
            || Handle::from_path(&self.path).ok().as_ref() != Some(&self.identity)
        {
            return Err(SessionFailure::cleanup("job_root_changed"));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), SessionFailure> {
        if !self.owned {
            return Err(SessionFailure::cleanup("job_root_changed"));
        }
        let directory = self
            .directory
            .take()
            .ok_or_else(|| SessionFailure::cleanup("job_root_changed"))?;
        if capability_directory_identity(&directory).ok().as_ref() != Some(&self.identity) {
            self.directory = Some(directory);
            return Err(SessionFailure::cleanup("job_root_changed"));
        }
        match directory.remove_open_dir_all() {
            Ok(()) => {
                self.owned = false;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.owned = false;
            }
            Err(_) => return Err(SessionFailure::cleanup("worker_cleanup_failed")),
        }
        sync_capability_directory(&self.worker_root_directory)
            .map_err(|_| SessionFailure::cleanup("worker_cleanup_failed"))
    }
}

impl Drop for JobRootGuard {
    fn drop(&mut self) {
        if self.owned {
            let _ = self.cleanup();
        }
    }
}

fn validate_worker_root(path: &Utf8Path) -> Result<(), SessionFailure> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(SessionFailure::internal("worker_root_invalid"));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| SessionFailure::internal("worker_root_invalid"))?;
    if canonical != path.as_std_path() {
        return Err(SessionFailure::internal("worker_root_invalid"));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SessionFailure::internal("worker_root_invalid"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SessionFailure::internal("worker_root_invalid"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(SessionFailure::internal("worker_root_permissions_invalid"));
    }
    Ok(())
}

fn create_private_directory(path: &Utf8Path) -> Result<(), SessionFailure> {
    #[cfg(unix)]
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| SessionFailure::internal("worker_directory_create_failed"))?;
    #[cfg(not(unix))]
    fs::create_dir(path).map_err(|_| SessionFailure::internal("worker_directory_create_failed"))?;
    Ok(())
}

fn capability_directory_identity(directory: &CapabilityDir) -> io::Result<Handle> {
    Handle::from_file(directory.try_clone()?.into_std_file())
}

#[cfg(unix)]
fn create_private_capability_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
fn create_private_capability_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    parent.create_dir(name)
}

fn sync_capability_directory(directory: &CapabilityDir) -> io::Result<()> {
    #[cfg(unix)]
    directory.try_clone()?.into_std_file().sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn create_private_file(path: &Utf8Path) -> Result<File, SessionFailure> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|_| SessionFailure::internal("worker_file_create_failed"))
}

fn remove_exact_file(path: &Utf8Path) -> Result<(), SessionFailure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| SessionFailure::internal("source_archive_cleanup_failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SessionFailure::internal("source_archive_cleanup_failed"));
    }
    fs::remove_file(path).map_err(|_| SessionFailure::internal("source_archive_cleanup_failed"))
}

fn sync_directory(path: &Utf8Path) -> Result<(), SessionFailure> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SessionFailure::internal("worker_directory_sync_failed"))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

struct HashingWriter<'a> {
    inner: &'a mut File,
    hasher: Sha256,
    bytes: u64,
}

impl<'a> HashingWriter<'a> {
    fn new(inner: &'a mut File) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.bytes, hex::encode(self.hasher.finalize()))
    }
}

impl Write for HashingWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..count]);
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct HashingReader<'a> {
    inner: &'a mut File,
    hasher: Sha256,
    bytes: u64,
}

impl<'a> HashingReader<'a> {
    fn new(inner: &'a mut File) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.bytes, hex::encode(self.hasher.finalize()))
    }
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..count]);
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }
}

#[derive(Clone, Copy, Debug)]
struct SessionFailure {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl SessionFailure {
    const fn invalid(code: &'static str) -> Self {
        Self {
            code,
            message: "snapshot session input was rejected",
            retryable: false,
        }
    }

    const fn internal(code: &'static str) -> Self {
        Self {
            code,
            message: "snapshot worker could not complete the build",
            retryable: false,
        }
    }

    const fn output(code: &'static str) -> Self {
        Self {
            code,
            message: "snapshot worker transport could not complete",
            retryable: true,
        }
    }

    const fn cleanup(code: &'static str) -> Self {
        Self {
            code,
            message: "snapshot worker cleanup could not be confirmed",
            retryable: false,
        }
    }

    const fn cancelled() -> Self {
        Self {
            code: "snapshot_build_cancelled",
            message: "snapshot build was cancelled",
            retryable: true,
        }
    }

    const fn frame(error: WorkerDataPlaneFrameError) -> Self {
        match error {
            WorkerDataPlaneFrameError::Io => Self::output("session_io_failed"),
            WorkerDataPlaneFrameError::EmptyInput
            | WorkerDataPlaneFrameError::TruncatedHeader
            | WorkerDataPlaneFrameError::TruncatedPayload => {
                Self::output("session_input_truncated")
            }
            _ => Self::invalid("session_frame_invalid"),
        }
    }

    const fn compile(error: SnapshotCompileFailure) -> Self {
        Self {
            code: error.code,
            message: error.message,
            retryable: error.retryable,
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::Cursor,
        sync::mpsc::{self, Receiver, SyncSender},
    };

    use camino::Utf8PathBuf;
    use rustferry_remote::{
        ApplePlatform, BuildProfile, BundleIdentifier, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
        CURRENT_PROTOCOL_VERSION, CompilePhaseEvidence, CompileToolchainEvidence,
        IosDeviceProductExpectation, MachOSliceEvidence, ProtocolPath, ProtocolPathSemantics,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningMode, SigningPlan,
        SigningTarget, SigningTargetKind, SnapshotBuildParameters, SourceArchive,
        SourceBundleRequest, SourceMode, UnsignedAppInspection, UnsignedXcarchiveExpectation,
        UnsignedXcarchiveInspection, create_source_bundle_archive, plan_source_bundle,
    };

    use super::*;
    use crate::session_output::BoundedSessionOutput;

    const JOB_ID: &str = "ssh-test-job";
    const ARTIFACT_BYTES: &[u8] = b"deterministic sealed archive fixture";

    struct PhaseGatedReader {
        prefix: Cursor<Vec<u8>>,
        suffix: Cursor<Vec<u8>>,
        phase: Arc<ControlPhase>,
    }

    impl Read for PhaseGatedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let read = self.prefix.read(output)?;
            if read != 0 {
                return Ok(read);
            }
            while !self.phase.receipt_allowed() {
                thread::sleep(Duration::from_millis(1));
            }
            self.suffix.read(output)
        }
    }

    struct ReceiptDuringArtifactFlushReader {
        prefix: Cursor<Vec<u8>>,
        suffix: Cursor<Vec<u8>>,
        artifact_flush_started: Receiver<()>,
        receipt_consumed: Option<SyncSender<()>>,
        released: bool,
    }

    impl Read for ReceiptDuringArtifactFlushReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let read = self.prefix.read(output)?;
            if read != 0 {
                return Ok(read);
            }
            if !self.released {
                self.artifact_flush_started.recv().map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "artifact flush gate stopped")
                })?;
                self.released = true;
            }
            let read = self.suffix.read(output)?;
            if read != 0
                && self.suffix.position() == self.suffix.get_ref().len() as u64
                && let Some(receipt_consumed) = self.receipt_consumed.take()
            {
                let _ = receipt_consumed.send(());
            }
            Ok(read)
        }
    }

    struct ArtifactFlushGateWriter {
        bytes: Vec<u8>,
        artifact_flush_started: Option<SyncSender<()>>,
        receipt_consumed: Receiver<()>,
        gated: bool,
        fail_artifact_flush: bool,
    }

    impl Write for ArtifactFlushGateWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if !self.gated
                && self
                    .bytes
                    .windows(ARTIFACT_BYTES.len())
                    .any(|window| window == ARTIFACT_BYTES)
            {
                self.gated = true;
                if let Some(artifact_flush_started) = self.artifact_flush_started.take() {
                    artifact_flush_started.send(()).map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "receipt reader stopped")
                    })?;
                }
                self.receipt_consumed
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "receipt was not consumed")
                    })?;
                if self.fail_artifact_flush {
                    self.fail_artifact_flush = false;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "artifact flush failed",
                    ));
                }
            }
            Ok(())
        }
    }

    struct BlockingOutputSink {
        release: Receiver<()>,
    }

    impl Write for BlockingOutputSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.release
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "output release stopped"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct StalledReader {
        prefix: Cursor<Vec<u8>>,
        release: Receiver<()>,
        released: bool,
    }

    impl StalledReader {
        fn new(prefix: Vec<u8>, release: Receiver<()>) -> Self {
            Self {
                prefix: Cursor::new(prefix),
                release,
                released: false,
            }
        }
    }

    impl Read for StalledReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let read = self.prefix.read(output)?;
            if read != 0 {
                return Ok(read);
            }
            if !self.released {
                self.release.recv().map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "fixture release channel closed")
                })?;
                self.released = true;
            }
            Ok(0)
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        worker_root: Utf8PathBuf,
        descriptor_bytes: Vec<u8>,
        archive_bytes: Vec<u8>,
        request: IosDeviceBuildRequest,
        start: SnapshotBuildStart,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("fixture root");
            let root = Utf8PathBuf::from_path_buf(directory.path().to_path_buf())
                .expect("UTF-8 fixture root");
            let project = root.join("project");
            fs::create_dir(&project).expect("project root");
            fs::create_dir(project.join("src")).expect("source root");
            fs::write(
                project.join("Cargo.toml"),
                "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n",
            )
            .expect("Cargo.toml");
            fs::write(project.join("Cargo.lock"), "# fixture\n").expect("Cargo.lock");
            fs::write(
                project.join("ferry.toml"),
                "[app]\nname='App'\nidentifier='com.example.app'\n",
            )
            .expect("ferry.toml");
            fs::write(project.join("src/main.rs"), "fn main() {}\n").expect("main.rs");

            let plan = plan_source_bundle(&SourceBundleRequest::new(&project, &project))
                .expect("source plan");
            let archive_path = root.join("source.zip");
            let archive =
                create_source_bundle_archive(&plan, &archive_path, SourceArchiveLimits::default())
                    .expect("source archive");
            let descriptor = SourceBundleDescriptor::new(archive, plan.manifest().clone());
            let descriptor_bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
            let archive_bytes = fs::read(&archive_path).expect("source ZIP bytes");
            let signing = SigningPlan {
                mode: SigningMode::UnsignedCompileOnly,
                signing: None,
                team: None,
                device: None,
                targets: vec![SigningTarget {
                    name: "App".to_owned(),
                    bundle_identifier: BundleIdentifier::new("com.example.app")
                        .expect("bundle identifier"),
                    kind: SigningTargetKind::Application,
                }],
                provisioning: Vec::new(),
                entitlements: Vec::new(),
                allow_provisioning_updates: false,
            };
            let request = IosDeviceBuildRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: "operation-1".to_owned(),
                product_name: "App".to_owned(),
                bundle_identifier: "com.example.app".to_owned(),
                minimum_ios_version: "16.0".to_owned(),
                product: IosDeviceProductExpectation {
                    app_directory_name: "App.app".to_owned(),
                    executable: "App".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    build_number: "1".to_owned(),
                    nested_bundles: Vec::new(),
                },
                profile: BuildProfile::Debug,
                source_mode: SourceMode::Snapshot,
                source_repository: None,
                source_revision: None,
                source: descriptor.manifest.clone(),
                signing,
                requested_artifacts: [IosArtifactType::Xcarchive].into_iter().collect(),
            };
            request.validate().expect("snapshot request");
            let start = SnapshotBuildStart::new(
                SnapshotBuildParameters::from_request(&request).expect("parameters"),
                descriptor_bytes.len() as u64,
                sha256_bytes(&descriptor_bytes),
                descriptor.archive.clone(),
            )
            .expect("build start");
            let worker_root = root.join("worker");
            #[cfg(unix)]
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&worker_root)
                .expect("worker root");
            #[cfg(not(unix))]
            fs::create_dir(&worker_root).expect("worker root");
            Self {
                _directory: directory,
                worker_root,
                descriptor_bytes,
                archive_bytes,
                request,
                start,
            }
        }

        fn successful_input(&self) -> Vec<u8> {
            let mut input = self.upload_input(&self.archive_bytes);
            input.extend_from_slice(&self.receipt_input());
            input
        }

        fn receipt_input(&self) -> Vec<u8> {
            let mut input = Vec::new();
            let offered = fake_artifact_descriptor(&self.request, JOB_ID);
            let receipt = SnapshotArtifactReceipt::new(
                &offered,
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    "/tmp/App-unsigned.xcarchive.zip",
                )
                .expect("receipt path"),
            )
            .expect("artifact receipt");
            write_worker_data_plane_frame(
                &mut input,
                WorkerDataPlaneFrameKind::ArtifactReceipt,
                3,
                &serde_json::to_vec(&receipt).expect("receipt JSON"),
            )
            .expect("receipt frame");
            input
        }

        fn upload_input(&self, archive_bytes: &[u8]) -> Vec<u8> {
            let mut input = Vec::new();
            write_worker_data_plane_frame(
                &mut input,
                WorkerDataPlaneFrameKind::BuildRequest,
                0,
                &serde_json::to_vec(&self.start).expect("start JSON"),
            )
            .expect("start frame");
            write_worker_data_plane_frame(
                &mut input,
                WorkerDataPlaneFrameKind::SourceDescriptor,
                1,
                &self.descriptor_bytes,
            )
            .expect("descriptor frame");
            write_worker_data_plane_frame(
                &mut input,
                WorkerDataPlaneFrameKind::SourceArchive,
                2,
                archive_bytes,
            )
            .expect("archive frame");
            input
        }
    }

    #[derive(Default)]
    struct FakeCompiler {
        called: bool,
    }

    #[derive(Default)]
    struct CancellationCompiler {
        observed: bool,
    }

    impl SnapshotCompiler for CancellationCompiler {
        fn compile(
            &mut self,
            context: SnapshotCompileContext<'_>,
        ) -> Result<SnapshotCompileOutput, SnapshotCompileFailure> {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !context.cancellation().is_cancelled() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            self.observed = context.cancellation().is_cancelled();
            Err(SnapshotCompileFailure::new(
                "fake_compile_cancelled",
                "fixture compile was cancelled",
                true,
            ))
        }
    }

    impl SnapshotCompiler for FakeCompiler {
        fn compile(
            &mut self,
            context: SnapshotCompileContext<'_>,
        ) -> Result<SnapshotCompileOutput, SnapshotCompileFailure> {
            self.called = true;
            let artifact_path = context.output_directory().join(UNSIGNED_ARCHIVE_NAME);
            fs::write(&artifact_path, ARTIFACT_BYTES).expect("fake sealed archive");
            Ok(SnapshotCompileOutput {
                handoff: CompileHandoff {
                    schema_version: COMPILE_HANDOFF_SCHEMA_VERSION,
                    request: context.request().clone(),
                    compile: fake_compile_evidence(context.request(), context.job_id()),
                },
                artifact_path,
            })
        }
    }

    fn fake_artifact_descriptor(
        request: &IosDeviceBuildRequest,
        job_id: &str,
    ) -> SnapshotArtifactDescriptor {
        let transport = SourceArchive {
            size: ARTIFACT_BYTES.len() as u64,
            sha256: sha256_bytes(ARTIFACT_BYTES),
        };
        SnapshotArtifactDescriptor::new(
            request.operation_id.clone(),
            ArtifactRecord {
                artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
                kind: ArtifactKind::Xcarchive,
                file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
                size: transport.size,
                sha256: transport.sha256,
                media_type: Some("application/zip".to_owned()),
            },
            fake_compile_evidence(request, job_id),
        )
        .expect("fake artifact descriptor")
    }

    fn fake_compile_evidence(
        request: &IosDeviceBuildRequest,
        job_id: &str,
    ) -> CompilePhaseEvidence {
        let slice = MachOSliceEvidence {
            architecture: "arm64".to_owned(),
            platform: ApplePlatform::Ios,
            minimum_os: Some("16.0.0".to_owned()),
            sdk: Some("18.5.0".to_owned()),
        };
        let expectation = UnsignedXcarchiveExpectation {
            app_directory_name: "App.app".to_owned(),
            bundle_identifier: request.bundle_identifier.clone(),
            executable: "App".to_owned(),
            app_version: "1.0.0".to_owned(),
            build_number: "1".to_owned(),
            minimum_os: request.minimum_ios_version.clone(),
            sdk_version: "18.5".to_owned(),
            sdk_build_version: "22F76".to_owned(),
            nested_bundles: Vec::new(),
            required_resources: BTreeMap::new(),
        };
        let inspection = UnsignedXcarchiveInspection {
            application_path: "Products/Applications/App.app".to_owned(),
            architectures: vec!["arm64".to_owned()],
            app: UnsignedAppInspection {
                app_directory_name: "App.app".to_owned(),
                bundle_identifier: request.bundle_identifier.clone(),
                executable: "App".to_owned(),
                main_executable: vec![slice],
                nested_executables: BTreeMap::new(),
                extensions: Vec::new(),
                resources: BTreeMap::new(),
                entries: vec!["App".to_owned()],
            },
            entries: vec!["Products/Applications/App.app/App".to_owned()],
        };
        CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: job_id.to_owned(),
            provider: SSH_STDIO_PROVIDER_ID.to_owned(),
            request_sha256: canonical_request_sha256(request).expect("request hash"),
            source_sha256: request.source.sha256.clone(),
            cargo_lock_sha256: "c".repeat(64),
            config_sha256: "d".repeat(64),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 15.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "16.4".to_owned(),
                iphoneos_sdk_version: "18.5".to_owned(),
                iphoneos_sdk_build_version: "22F76".to_owned(),
                developer_directory_sha256: "e".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: rustferry_remote::IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: SourceArchive {
                    size: ARTIFACT_BYTES.len() as u64,
                    sha256: sha256_bytes(ARTIFACT_BYTES),
                },
                contents: request.source.clone(),
                expectation,
            },
            archive_inspection: inspection,
            started_at_unix_seconds: 100,
            finished_at_unix_seconds: 200,
        }
    }

    #[test]
    fn successful_session_streams_artifact_then_confirms_cleanup() {
        let fixture = Fixture::new();
        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        {
            let mut session = Session::new(&mut output, &fixture.worker_root);
            session.job_id_override = Some(JOB_ID.to_owned());
            let reader = PhaseGatedReader {
                prefix: Cursor::new(fixture.upload_input(&fixture.archive_bytes)),
                suffix: Cursor::new(fixture.receipt_input()),
                phase: Arc::clone(&session.control_phase),
            };
            match session.run(reader, &mut compiler) {
                Ok(()) => {}
                Err(failure) => session
                    .finish_failure(failure)
                    .expect("structured session response"),
            }
        }
        assert!(compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );

        let mut input = Cursor::new(output);
        let mut sequence = WorkerDataPlaneSequence::new();
        let mut artifact = Vec::new();
        let mut completed = None;
        loop {
            let header = match read_worker_data_plane_header(&mut input) {
                Ok(header) => header,
                Err(WorkerDataPlaneFrameError::EmptyInput) => break,
                Err(error) => panic!("invalid server frame: {error}"),
            };
            sequence.accept(header).expect("server sequence");
            match header.kind() {
                WorkerDataPlaneFrameKind::Artifact => {
                    copy_worker_data_plane_payload(&mut input, &mut artifact, header)
                        .expect("artifact bytes");
                }
                WorkerDataPlaneFrameKind::Complete => {
                    let complete: SnapshotBuildComplete =
                        decode_json_payload(&mut input, header).expect("completion");
                    completed = Some(complete);
                }
                _ => {
                    let _ = read_worker_data_plane_payload(&mut input, header)
                        .expect("control payload");
                }
            }
        }
        assert_eq!(artifact, ARTIFACT_BYTES);
        let completed = completed.expect("terminal completion");
        completed.validate().expect("cleanup proof");
        assert_eq!(completed.job_id, JOB_ID);
    }

    #[test]
    fn receipt_during_final_artifact_flush_is_queued_until_flush_succeeds() {
        let fixture = Fixture::new();
        let mut compiler = FakeCompiler::default();
        let (artifact_flush_sender, artifact_flush_receiver) = mpsc::sync_channel(1);
        let (receipt_consumed_sender, receipt_consumed_receiver) = mpsc::sync_channel(1);
        let reader = ReceiptDuringArtifactFlushReader {
            prefix: Cursor::new(fixture.upload_input(&fixture.archive_bytes)),
            suffix: Cursor::new(fixture.receipt_input()),
            artifact_flush_started: artifact_flush_receiver,
            receipt_consumed: Some(receipt_consumed_sender),
            released: false,
        };
        let mut output = ArtifactFlushGateWriter {
            bytes: Vec::new(),
            artifact_flush_started: Some(artifact_flush_sender),
            receipt_consumed: receipt_consumed_receiver,
            gated: false,
            fail_artifact_flush: false,
        };
        serve_snapshot_session_with_job_id(
            reader,
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("receipt queued during final flush");

        assert!(compiler.called);
        assert!(output.gated);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        assert_eq!(
            terminal_frame_kind(&output.bytes),
            WorkerDataPlaneFrameKind::Complete
        );
    }

    #[test]
    fn receipt_queued_during_failed_artifact_flush_never_completes_the_job() {
        let fixture = Fixture::new();
        let mut compiler = FakeCompiler::default();
        let (artifact_flush_sender, artifact_flush_receiver) = mpsc::sync_channel(1);
        let (receipt_consumed_sender, receipt_consumed_receiver) = mpsc::sync_channel(1);
        let reader = ReceiptDuringArtifactFlushReader {
            prefix: Cursor::new(fixture.upload_input(&fixture.archive_bytes)),
            suffix: Cursor::new(fixture.receipt_input()),
            artifact_flush_started: artifact_flush_receiver,
            receipt_consumed: Some(receipt_consumed_sender),
            released: false,
        };
        let mut output = ArtifactFlushGateWriter {
            bytes: Vec::new(),
            artifact_flush_started: Some(artifact_flush_sender),
            receipt_consumed: receipt_consumed_receiver,
            gated: false,
            fail_artifact_flush: true,
        };
        serve_snapshot_session_with_job_id(
            reader,
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured output failure");

        let error = terminal_error(&output.bytes);
        assert!(compiler.called, "unexpected failure: {}", error.code);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        assert_eq!(
            terminal_frame_kind(&output.bytes),
            WorkerDataPlaneFrameKind::Error
        );
        assert_eq!(error.code, "output_flush_failed");
        assert!(error.cleanup.is_some());
    }

    #[test]
    fn receipt_before_artifact_stream_cancels_compile_and_cleans_job() {
        let fixture = Fixture::new();
        let mut compiler = CancellationCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(fixture.successful_input()),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured early-receipt rejection");

        assert!(compiler.observed);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "artifact_receipt_too_early");
        assert!(error.cleanup.is_some());
    }

    #[test]
    fn stalled_output_times_out_and_cleans_without_joining_the_blocked_writer() {
        let fixture = Fixture::new();
        let mut compiler = FakeCompiler::default();
        let (input_release_sender, input_release_receiver) = mpsc::sync_channel(1);
        let reader = StalledReader::new(
            fixture.upload_input(&fixture.archive_bytes),
            input_release_receiver,
        );
        let (output_release_sender, output_release_receiver) = mpsc::sync_channel(1);
        let mut output = BoundedSessionOutput::spawn(
            BlockingOutputSink {
                release: output_release_receiver,
            },
            Duration::from_secs(1),
            Duration::from_millis(40),
        )
        .expect("bounded output");
        let started = Instant::now();
        let result = serve_snapshot_session_with_job_id(
            reader,
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        );
        assert_eq!(result, Err(SnapshotSessionServeError::Output));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let _ = output_release_sender.send(());
        let _ = input_release_sender.send(());
    }

    #[test]
    fn source_digest_mismatch_never_calls_compiler_and_cleans_job() {
        let fixture = Fixture::new();
        let mut changed = fixture.archive_bytes.clone();
        let middle = changed.len() / 2;
        changed[middle] ^= 0x55;
        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(fixture.upload_input(&changed)),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured rejection");
        assert!(!compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "source_archive_digest_mismatch");
        assert!(error.cleanup.is_some());
    }

    #[test]
    fn malformed_first_frame_returns_bounded_error_without_allocating_job_root() {
        let fixture = Fixture::new();
        let mut input = Vec::new();
        write_worker_data_plane_frame(&mut input, WorkerDataPlaneFrameKind::Cancel, 0, &[])
            .expect("wrong frame");
        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(input),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured rejection");
        assert!(!compiler.called);
        let error = terminal_error(&output);
        assert_eq!(error.code, "unexpected_frame_kind");
        assert!(error.job_id.is_none());
        assert!(error.cleanup.is_none());
    }

    #[test]
    fn oversized_padded_descriptor_is_rejected_before_payload_read() {
        let fixture = Fixture::new();
        let mut start = fixture.start.clone();
        start.source_descriptor_size = MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES + 1;
        start.source_descriptor_sha256 = "a".repeat(64);
        assert!(start.validate().is_err());
        let mut input = Vec::new();
        write_worker_data_plane_frame(
            &mut input,
            WorkerDataPlaneFrameKind::BuildRequest,
            0,
            &serde_json::to_vec(&start).expect("start JSON"),
        )
        .expect("start frame");
        let header = WorkerDataPlaneFrameHeader::new(
            WorkerDataPlaneFrameKind::SourceDescriptor,
            1,
            start.source_descriptor_size,
        )
        .expect("descriptor header within general wire limit");
        rustferry_remote::write_worker_data_plane_header(&mut input, header)
            .expect("descriptor header");

        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(input),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured oversized-descriptor rejection");

        assert!(!compiler.called);
        let error = terminal_error(&output);
        assert_eq!(error.code, "source_descriptor_too_large");
        assert!(error.job_id.is_none());
        assert!(error.cleanup.is_none());
    }

    #[test]
    fn stalled_initial_header_hits_inactivity_deadline_without_job_root() {
        let fixture = Fixture::new();
        let mut frame = Vec::new();
        write_worker_data_plane_frame(
            &mut frame,
            WorkerDataPlaneFrameKind::BuildRequest,
            0,
            &serde_json::to_vec(&fixture.start).expect("start JSON"),
        )
        .expect("start frame");
        let (release, wait_for_release) = mpsc::channel();
        let reader = StalledReader::new(frame[..8].to_vec(), wait_for_release);
        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        let started = Instant::now();
        serve_snapshot_session_with_input_deadlines(
            reader,
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .expect("structured input-timeout response");
        release.send(()).expect("release stalled reader");

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "session_input_timed_out");
        assert!(error.job_id.is_none());
        assert!(error.cleanup.is_none());
    }

    #[test]
    fn cancellation_reaches_active_compiler_and_cleanup_precedes_error() {
        let fixture = Fixture::new();
        let mut input = fixture.upload_input(&fixture.archive_bytes);
        write_worker_data_plane_frame(&mut input, WorkerDataPlaneFrameKind::Cancel, 3, &[])
            .expect("cancel frame");
        let mut compiler = CancellationCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(input),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured cancellation");
        assert!(compiler.observed);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "snapshot_build_cancelled");
        assert!(error.cleanup.is_some());
    }

    #[test]
    fn truncated_source_payload_is_rejected_and_cleaned() {
        let fixture = Fixture::new();
        let mut input = Vec::new();
        write_worker_data_plane_frame(
            &mut input,
            WorkerDataPlaneFrameKind::BuildRequest,
            0,
            &serde_json::to_vec(&fixture.start).expect("start JSON"),
        )
        .expect("start frame");
        write_worker_data_plane_frame(
            &mut input,
            WorkerDataPlaneFrameKind::SourceDescriptor,
            1,
            &fixture.descriptor_bytes,
        )
        .expect("descriptor frame");
        let header = WorkerDataPlaneFrameHeader::new(
            WorkerDataPlaneFrameKind::SourceArchive,
            2,
            fixture.archive_bytes.len() as u64,
        )
        .expect("archive header");
        rustferry_remote::write_worker_data_plane_header(&mut input, header)
            .expect("encoded archive header");
        input.extend_from_slice(&fixture.archive_bytes[..fixture.archive_bytes.len() / 2]);

        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        serve_snapshot_session_with_job_id(
            Cursor::new(input),
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
        )
        .expect("structured truncation");
        assert!(!compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "session_input_truncated");
        assert!(error.cleanup.is_some());
    }

    #[test]
    fn stalled_source_payload_hits_inactivity_deadline_and_cleans_job() {
        let fixture = Fixture::new();
        let input = fixture.upload_input(&fixture.archive_bytes);
        let archive_offset = input.len() - fixture.archive_bytes.len();
        let stalled_at = archive_offset + fixture.archive_bytes.len() / 2;
        let (release, wait_for_release) = mpsc::channel();
        let reader = StalledReader::new(input[..stalled_at].to_vec(), wait_for_release);
        let mut compiler = FakeCompiler::default();
        let mut output = Vec::new();
        let started = Instant::now();
        serve_snapshot_session_with_input_deadlines(
            reader,
            &mut output,
            &fixture.worker_root,
            &mut compiler,
            JOB_ID,
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .expect("structured source-timeout response");
        release.send(()).expect("release stalled reader");

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!compiler.called);
        assert_eq!(
            fs::read_dir(&fixture.worker_root)
                .expect("worker root")
                .count(),
            0
        );
        let error = terminal_error(&output);
        assert_eq!(error.code, "session_input_timed_out");
        assert!(error.cleanup.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_removes_open_job_root_without_deleting_path_replacement() {
        let fixture = Fixture::new();
        let mut guard = JobRootGuard::create(&fixture.worker_root, JOB_ID, "operation-1")
            .expect("job root guard");
        let original = guard.path().to_owned();
        let displaced = fixture.worker_root.join("displaced-owned-job");
        fs::rename(&original, &displaced).expect("displace owned job directory");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&original)
            .expect("replacement job directory");
        let sentinel = original.join("must-survive.txt");
        fs::write(&sentinel, b"replacement").expect("replacement sentinel");

        assert!(guard.verify().is_err());
        guard.cleanup().expect("handle-relative cleanup");

        assert!(!displaced.exists());
        assert_eq!(
            fs::read(sentinel).expect("replacement preserved"),
            b"replacement"
        );
    }

    fn terminal_error(output: &[u8]) -> SnapshotSessionError {
        let mut input = Cursor::new(output);
        let mut last = None;
        loop {
            let header = match read_worker_data_plane_header(&mut input) {
                Ok(header) => header,
                Err(WorkerDataPlaneFrameError::EmptyInput) => break,
                Err(error) => panic!("invalid error frame: {error}"),
            };
            if header.kind() == WorkerDataPlaneFrameKind::Error {
                last = Some(decode_json_payload(&mut input, header).expect("session error"));
            } else if header.kind() == WorkerDataPlaneFrameKind::Artifact {
                copy_worker_data_plane_payload(&mut input, &mut std::io::sink(), header)
                    .expect("discard artifact");
            } else {
                let _ = read_worker_data_plane_payload(&mut input, header)
                    .expect("discard control payload");
            }
        }
        last.expect("terminal error")
    }

    fn terminal_frame_kind(output: &[u8]) -> WorkerDataPlaneFrameKind {
        let mut input = Cursor::new(output);
        let mut last = None;
        loop {
            let header = match read_worker_data_plane_header(&mut input) {
                Ok(header) => header,
                Err(WorkerDataPlaneFrameError::EmptyInput) => break,
                Err(error) => panic!("invalid terminal frame: {error}"),
            };
            last = Some(header.kind());
            if header.kind() == WorkerDataPlaneFrameKind::Artifact {
                copy_worker_data_plane_payload(&mut input, &mut std::io::sink(), header)
                    .expect("discard artifact");
            } else {
                let _ = read_worker_data_plane_payload(&mut input, header)
                    .expect("discard control payload");
            }
        }
        last.expect("terminal frame")
    }
}
