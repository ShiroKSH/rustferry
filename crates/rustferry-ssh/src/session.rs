//! Pure framed client for one SSH snapshot-build session.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::{
    CURRENT_PROTOCOL_VERSION, ProtocolPath, ProtocolPathSemantics, RemoteBuildEvent,
    SnapshotArtifactDescriptor, SnapshotArtifactReceipt, SnapshotBuildComplete, SnapshotBuildStart,
    SnapshotJobAccepted, SnapshotSessionError, SourceArchiveLimits, SourceBundleDescriptor,
    WorkerDataPlaneFrameError, WorkerDataPlaneFrameHeader, WorkerDataPlaneFrameKind,
    WorkerDataPlaneSequence, canonical_request_sha256, read_worker_data_plane_header,
    read_worker_data_plane_payload, write_worker_data_plane_frame, write_worker_data_plane_header,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::provider::SSH_PROVIDER_ID;

/// Source handles and limits for one snapshot request.
pub struct SnapshotSessionRequest<'a> {
    /// Validated control declaration sent as client frame zero.
    pub start: &'a SnapshotBuildStart,
    /// Exact strict JSON descriptor declared by `start`.
    pub source_descriptor: &'a mut File,
    /// Exact deterministic source archive declared by `start` and the descriptor.
    pub source_archive: &'a mut File,
    /// Limits used while reconstructing the complete request.
    pub source_limits: SourceArchiveLimits,
}

impl<'a> SnapshotSessionRequest<'a> {
    /// Bind one build declaration to already-open source handles.
    #[must_use]
    pub const fn new(
        start: &'a SnapshotBuildStart,
        source_descriptor: &'a mut File,
        source_archive: &'a mut File,
        source_limits: SourceArchiveLimits,
    ) -> Self {
        Self {
            start,
            source_descriptor,
            source_archive,
            source_limits,
        }
    }
}

/// Create-only local file receiving untrusted artifact bytes.
#[derive(Debug)]
pub struct CreateOnlyArtifactSpool {
    path: Utf8PathBuf,
    file: File,
    publication: Option<PublishedArtifact>,
    commit_authorized: bool,
    armed: bool,
}

#[derive(Debug)]
struct PublishedArtifact {
    path: Utf8PathBuf,
    file: File,
    is_staging_link: bool,
    size: u64,
    sha256: String,
}

impl CreateOnlyArtifactSpool {
    /// Create one new private artifact spool without following an existing path.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute or unsafe paths, existing destinations, non-files,
    /// and failures to prove that the opened handle is the newly linked file.
    pub fn create(path: impl Into<Utf8PathBuf>) -> Result<Self, SnapshotSessionClientError> {
        let path = path.into();
        if !path.is_absolute() || path.as_str().chars().any(char::is_control) {
            return Err(SnapshotSessionClientError::ArtifactSpoolPathInvalid);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SnapshotSessionClientError::ArtifactSpoolExists
            } else {
                SnapshotSessionClientError::LocalIo
            }
        })?;
        let spool = Self {
            path,
            file,
            publication: None,
            commit_authorized: false,
            armed: true,
        };
        spool.validate_new_link()?;
        Ok(spool)
    }

    /// Caller-selected local spool path.
    #[must_use]
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Remove every still-uncommitted identity-matching artifact link.
    ///
    /// Calls after successful cleanup are idempotent. A replaced or otherwise
    /// unprovable path is preserved and reported instead of being unlinked.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotSessionClientError::ArtifactCleanupFailed`] when all
    /// operation-owned links cannot be proven removed.
    pub fn abort(&mut self) -> Result<(), SnapshotSessionClientError> {
        self.cleanup_failure()
    }

    /// Commit the already validated publication after all caller-owned output
    /// checks have succeeded.
    ///
    /// When the verifier published through a second hard link, this removes
    /// only the private staging link. Until this method succeeds, dropping the
    /// spool removes both identity-matching links.
    ///
    /// # Errors
    ///
    /// Rejects calls before a complete session, a replaced publication, byte
    /// changes, or a failure to durably remove the private staging link.
    pub fn commit(&mut self) -> Result<(), SnapshotSessionClientError> {
        self.commit_with(|_| {})
    }

    fn commit_with(
        &mut self,
        after_staging_quarantine: impl FnOnce(&Utf8Path),
    ) -> Result<(), SnapshotSessionClientError> {
        let result = self.commit_inner_with(after_staging_quarantine);
        if let Err(error) = result {
            self.cleanup_failure()?;
            return Err(error);
        }
        Ok(())
    }

    fn commit_inner_with(
        &mut self,
        after_staging_quarantine: impl FnOnce(&Utf8Path),
    ) -> Result<(), SnapshotSessionClientError> {
        if !self.commit_authorized {
            return Err(SnapshotSessionClientError::ArtifactCommitNotAuthorized);
        }
        let publication = self
            .publication
            .as_ref()
            .ok_or(SnapshotSessionClientError::ArtifactCommitNotAuthorized)?;
        let path = publication.path.clone();
        let is_staging_link = publication.is_staging_link;
        let size = publication.size;
        let sha256 = publication.sha256.clone();
        validate_published_artifact(&self.file, &publication.file, &path, size, &sha256)?;
        if !is_staging_link {
            self.remove_owned_link_with(&self.path, after_staging_quarantine)?;
            let publication = self
                .publication
                .as_ref()
                .ok_or(SnapshotSessionClientError::ArtifactCommitNotAuthorized)?;
            validate_published_artifact(&self.file, &publication.file, &path, size, &sha256)?;
        }
        self.armed = false;
        Ok(())
    }

    fn validate_new_link(&self) -> Result<(), SnapshotSessionClientError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?;
        let linked = fs::symlink_metadata(&self.path)
            .map_err(|_| SnapshotSessionClientError::ArtifactSpoolInvalid)?;
        let linked_file = open_file_no_follow(&self.path)
            .map_err(|_| SnapshotSessionClientError::ArtifactSpoolInvalid)?;
        if !opened.file_type().is_file()
            || linked.file_type().is_symlink()
            || !linked.file_type().is_file()
            || opened.len() != 0
            || linked.len() != 0
            || !same_file_identity(&self.file, &linked_file)
        {
            return Err(SnapshotSessionClientError::ArtifactSpoolInvalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if opened.mode() & 0o077 != 0 || opened.nlink() != 1 {
                return Err(SnapshotSessionClientError::ArtifactSpoolInvalid);
            }
        }
        Ok(())
    }

    fn register_publication(
        &mut self,
        local_path: &ProtocolPath,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), SnapshotSessionClientError> {
        if local_path.semantics != ProtocolPathSemantics::ClientAbsolute {
            return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
        }
        let path = Utf8PathBuf::from(&local_path.value);
        if !path.is_absolute() || path.as_str().chars().any(char::is_control) {
            return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
        }
        let is_staging_link = same_directory_entry(&self.path, &path);
        let file = open_publication_identity(&self.file, &path)?;
        self.publication = Some(PublishedArtifact {
            path: path.clone(),
            file,
            is_staging_link,
            size: expected_size,
            sha256: expected_sha256.to_owned(),
        });
        let publication = self
            .publication
            .as_ref()
            .ok_or(SnapshotSessionClientError::ArtifactPublicationFailed)?;
        validate_published_artifact(
            &self.file,
            &publication.file,
            &path,
            expected_size,
            expected_sha256,
        )
    }

    pub(crate) fn authorize_commit(&mut self) -> Result<(), SnapshotSessionClientError> {
        if self.publication.is_none() || !self.armed {
            return Err(SnapshotSessionClientError::ArtifactCommitNotAuthorized);
        }
        self.commit_authorized = true;
        Ok(())
    }

    pub(crate) fn cleanup_failure(&mut self) -> Result<(), SnapshotSessionClientError> {
        if !self.armed {
            return Ok(());
        }
        let publication = self
            .publication
            .as_ref()
            .map(|publication| (publication.path.clone(), publication.is_staging_link));
        let mut failed = false;
        if let Some((path, _)) = &publication
            && self.remove_owned_link(path).is_err()
        {
            failed = true;
        }
        if !publication
            .as_ref()
            .is_some_and(|(_, is_staging_link)| *is_staging_link)
            && self.remove_owned_link(&self.path).is_err()
        {
            failed = true;
        }
        if failed {
            Err(SnapshotSessionClientError::ArtifactCleanupFailed)
        } else {
            self.armed = false;
            self.publication = None;
            self.commit_authorized = false;
            Ok(())
        }
    }

    fn remove_owned_link(&self, path: &Utf8Path) -> Result<(), SnapshotSessionClientError> {
        self.remove_owned_link_with(path, |_| {})
    }

    fn remove_owned_link_with(
        &self,
        path: &Utf8Path,
        after_quarantine: impl FnOnce(&Utf8Path),
    ) -> Result<(), SnapshotSessionClientError> {
        let parent = path
            .parent()
            .ok_or(SnapshotSessionClientError::ArtifactCleanupFailed)?;
        let quarantine = tempfile::Builder::new()
            .prefix(".rustferry-artifact-cleanup-")
            .tempdir_in(parent)
            .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed)?;
        let quarantine_root = Utf8PathBuf::from_path_buf(quarantine.path().to_path_buf())
            .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed)?;
        let quarantined = quarantine_root.join("artifact");
        match fs::rename(path, &quarantined) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                quarantine
                    .close()
                    .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed)?;
                return Ok(());
            }
            Err(_) => return Err(SnapshotSessionClientError::ArtifactCleanupFailed),
        }
        after_quarantine(&quarantined);

        let owned = fs::symlink_metadata(&quarantined).is_ok_and(|linked| {
            !linked.file_type().is_symlink()
                && linked.file_type().is_file()
                && open_file_no_follow(&quarantined)
                    .is_ok_and(|linked| same_file_identity(&self.file, &linked))
        });
        let Ok(temporary_path) = tempfile::TempPath::try_from_path(quarantined.to_path_buf())
        else {
            let _ = quarantine.keep();
            return Err(SnapshotSessionClientError::ArtifactCleanupFailed);
        };
        if owned {
            temporary_path
                .close()
                .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed)?;
            quarantine
                .close()
                .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed)?;
            return sync_parent_directory(path)
                .map_err(|_| SnapshotSessionClientError::ArtifactCleanupFailed);
        }

        match temporary_path.persist_noclobber(path) {
            Ok(()) => {
                let _ = quarantine.close();
            }
            Err(mut error) => {
                error.path.disable_cleanup(true);
                drop(error);
                let _ = quarantine.keep();
            }
        }
        Err(SnapshotSessionClientError::ArtifactCleanupFailed)
    }
}

impl Drop for CreateOnlyArtifactSpool {
    fn drop(&mut self) {
        let _ = self.cleanup_failure();
    }
}

/// Validated terminal result of one snapshot session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotSessionOutcome {
    /// Worker job allocation.
    pub accepted: SnapshotJobAccepted,
    /// Exact artifact and compile evidence verified by the client.
    pub artifact: SnapshotArtifactDescriptor,
    /// Client receipt sent only after local verification succeeded.
    pub receipt: SnapshotArtifactReceipt,
    /// Terminal non-retaining worker cleanup proof.
    pub complete: SnapshotBuildComplete,
}

/// Stable fail-closed snapshot-session client failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SnapshotSessionClientError {
    /// Binary framing, sequence, size, or stream I/O failed.
    #[error(transparent)]
    DataPlane(#[from] WorkerDataPlaneFrameError),
    /// Build-start fields or their deterministic encoding are invalid.
    #[error("SSH snapshot build start is invalid")]
    InvalidBuildStart,
    /// Source descriptor JSON or reconstructed request is invalid.
    #[error("SSH snapshot source descriptor is invalid")]
    InvalidSourceDescriptor,
    /// Descriptor bytes do not match the size and digest declared by the start.
    #[error("SSH snapshot source descriptor bytes do not match the build start")]
    SourceDescriptorMismatch,
    /// Archive bytes do not match the descriptor and build-start declaration.
    #[error("SSH snapshot source archive bytes do not match the build start")]
    SourceArchiveMismatch,
    /// A validated source handle changed while its bytes were streamed.
    #[error("SSH snapshot source file changed while it was streamed")]
    SourceFileChanged,
    /// A bounded control payload was not strict valid JSON for its frame kind.
    #[error("SSH snapshot control frame is invalid")]
    InvalidControlFrame,
    /// A server frame appeared outside the only accepted session state.
    #[error("unexpected SSH snapshot server frame {received:?}; expected {expected}")]
    UnexpectedServerFrame {
        /// Required frame or terminal alternatives.
        expected: &'static str,
        /// Received typed frame.
        received: WorkerDataPlaneFrameKind,
    },
    /// Job acknowledgement identity does not match the reconstructed request.
    #[error("SSH snapshot job acknowledgement identity is invalid")]
    JobIdentityMismatch,
    /// Event identity does not match the acknowledged job.
    #[error("SSH snapshot event identity is invalid")]
    EventIdentityMismatch,
    /// Event sequence did not start at zero and increase by exactly one.
    #[error("SSH snapshot event sequence is invalid")]
    EventSequenceMismatch,
    /// No validated progress event preceded artifact verification and receipt.
    #[error("SSH snapshot artifact arrived before any validated progress event")]
    MissingProgressEvent,
    /// Artifact descriptor identity does not match the acknowledged job.
    #[error("SSH snapshot artifact identity is invalid")]
    ArtifactIdentityMismatch,
    /// Compile evidence is not bound to the reconstructed request and source.
    #[error("SSH snapshot compile evidence does not match the submitted request")]
    CompileEvidenceMismatch,
    /// Streamed artifact bytes do not match their descriptor.
    #[error("SSH snapshot artifact bytes do not match the descriptor")]
    ArtifactPayloadMismatch,
    /// The caller's independent artifact verifier rejected bytes or final path.
    #[error("SSH snapshot artifact verification failed")]
    ArtifactVerificationFailed,
    /// Final artifact path was absent, replaced, unrelated, changed, or not durable.
    #[error("SSH snapshot artifact publication could not be proven")]
    ArtifactPublicationFailed,
    /// Publication cannot be committed before protocol and process success.
    #[error("SSH snapshot artifact commit is not authorized")]
    ArtifactCommitNotAuthorized,
    /// Identity-bound removal of an uncommitted artifact failed.
    #[error("SSH snapshot uncommitted artifact cleanup failed")]
    ArtifactCleanupFailed,
    /// Completion identity or cleanup proof does not match the acknowledged job.
    #[error("SSH snapshot completion identity is invalid")]
    CompletionIdentityMismatch,
    /// The worker returned a validated public session error.
    #[error("SSH snapshot worker returned an error")]
    Server(Box<SnapshotSessionError>),
    /// Artifact spool path must be absolute UTF-8 without control bytes.
    #[error("SSH snapshot artifact spool path is invalid")]
    ArtifactSpoolPathInvalid,
    /// Create-only artifact spool destination already exists.
    #[error("SSH snapshot artifact spool already exists")]
    ArtifactSpoolExists,
    /// Artifact spool is not one empty, private, create-only regular file.
    #[error("SSH snapshot artifact spool is invalid")]
    ArtifactSpoolInvalid,
    /// A local file operation failed without exposing path or contents.
    #[error("SSH snapshot local file operation failed")]
    LocalIo,
}

/// Run one pure framed snapshot session over caller-owned duplex streams.
///
/// Source and artifact payloads are streamed with fixed memory. `verify_artifact`
/// runs after the artifact's size and SHA-256 match its descriptor and must
/// return the final client-absolute path. Client receipt frame three is written
/// only after the final path is opened without following a final symlink,
/// proven to be the verified inode, and durably synchronized.
///
/// A successful return authorizes, but does not commit, the artifact. The
/// caller must invoke [`CreateOnlyArtifactSpool::commit`] after its own
/// supporting-output checks; otherwise `Drop` removes the uncommitted output.
///
/// # Errors
///
/// Fails closed on any framing, order, identity, digest, file-stability,
/// verifier, server-error, or cleanup mismatch.
pub fn run_snapshot_session<Reader, Writer, EventSink, Verifier, VerifyError>(
    server_reader: &mut Reader,
    client_writer: &mut Writer,
    request: SnapshotSessionRequest<'_>,
    artifact_spool: &mut CreateOnlyArtifactSpool,
    on_event: EventSink,
    verify_artifact: Verifier,
) -> Result<SnapshotSessionOutcome, SnapshotSessionClientError>
where
    Reader: Read,
    Writer: Write,
    EventSink: FnMut(RemoteBuildEvent),
    Verifier: FnOnce(
        &mut File,
        &Utf8Path,
        &SnapshotArtifactDescriptor,
    ) -> Result<ProtocolPath, VerifyError>,
{
    let mut progress = SnapshotSessionProgress::default();
    let outcome = run_snapshot_session_deferred(
        server_reader,
        client_writer,
        request,
        artifact_spool,
        on_event,
        verify_artifact,
        &mut progress,
    )?;
    if let Err(error) = artifact_spool.authorize_commit() {
        return cleanup_session_error(artifact_spool, error);
    }
    Ok(outcome)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotSessionProgress {
    client_output: ClientOutputState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ClientOutputState {
    #[default]
    Uploading,
    Cancelable,
    ReceiptStarted,
    ReceiptSent,
    CancelSent,
}

impl Default for SnapshotSessionProgress {
    fn default() -> Self {
        Self {
            client_output: ClientOutputState::Uploading,
        }
    }
}

impl SnapshotSessionProgress {
    pub(crate) const fn can_send_cancel(self) -> bool {
        matches!(self.client_output, ClientOutputState::Cancelable)
    }

    pub(crate) fn mark_cancel_sent(&mut self) {
        self.client_output = ClientOutputState::CancelSent;
    }
}

pub(crate) fn run_snapshot_session_deferred<Reader, Writer, EventSink, Verifier, VerifyError>(
    server_reader: &mut Reader,
    client_writer: &mut Writer,
    request: SnapshotSessionRequest<'_>,
    artifact_spool: &mut CreateOnlyArtifactSpool,
    on_event: EventSink,
    verify_artifact: Verifier,
    progress: &mut SnapshotSessionProgress,
) -> Result<SnapshotSessionOutcome, SnapshotSessionClientError>
where
    Reader: Read,
    Writer: Write,
    EventSink: FnMut(RemoteBuildEvent),
    Verifier: FnOnce(
        &mut File,
        &Utf8Path,
        &SnapshotArtifactDescriptor,
    ) -> Result<ProtocolPath, VerifyError>,
{
    let result = run_snapshot_session_uncommitted(
        server_reader,
        client_writer,
        request,
        artifact_spool,
        on_event,
        verify_artifact,
        progress,
    );
    match result {
        Ok(outcome) => Ok(outcome),
        Err(error) => cleanup_session_error(artifact_spool, error),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_snapshot_session_uncommitted<Reader, Writer, EventSink, Verifier, VerifyError>(
    server_reader: &mut Reader,
    client_writer: &mut Writer,
    request: SnapshotSessionRequest<'_>,
    artifact_spool: &mut CreateOnlyArtifactSpool,
    mut on_event: EventSink,
    verify_artifact: Verifier,
    progress: &mut SnapshotSessionProgress,
) -> Result<SnapshotSessionOutcome, SnapshotSessionClientError>
where
    Reader: Read,
    Writer: Write,
    EventSink: FnMut(RemoteBuildEvent),
    Verifier: FnOnce(
        &mut File,
        &Utf8Path,
        &SnapshotArtifactDescriptor,
    ) -> Result<ProtocolPath, VerifyError>,
{
    let mut prepared = prepare_request(request)?;
    artifact_spool.validate_new_link()?;
    write_request_frames(client_writer, &mut prepared)?;
    client_writer
        .flush()
        .map_err(|_| SnapshotSessionClientError::DataPlane(WorkerDataPlaneFrameError::Io))?;
    progress.client_output = ClientOutputState::Cancelable;
    let mut cancel_guard = PreReceiptCancelGuard::new(client_writer, progress);

    let mut server_sequence = WorkerDataPlaneSequence::new();
    let mut next_event_sequence = 0_u64;
    let accepted = read_job_accepted(
        server_reader,
        &mut server_sequence,
        &prepared.operation_id,
        prepared.protocol_version,
    )?;
    let artifact = read_until_artifact_descriptor(
        server_reader,
        &mut server_sequence,
        &prepared,
        &accepted,
        &mut next_event_sequence,
        &mut on_event,
    )?;
    read_artifact_payload(
        server_reader,
        &mut server_sequence,
        &prepared,
        &accepted,
        &artifact,
        artifact_spool,
    )?;
    if next_event_sequence == 0 {
        return Err(SnapshotSessionClientError::MissingProgressEvent);
    }

    artifact_spool
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    let local_path = verify_artifact(
        &mut artifact_spool.file,
        artifact_spool.path.as_path(),
        &artifact,
    )
    .map_err(|_| SnapshotSessionClientError::ArtifactVerificationFailed)?;
    validate_open_file_bytes(
        &mut artifact_spool.file,
        artifact.artifact.size,
        &artifact.artifact.sha256,
        SnapshotSessionClientError::ArtifactVerificationFailed,
    )?;
    let receipt = SnapshotArtifactReceipt::new(&artifact, local_path)
        .map_err(|_| SnapshotSessionClientError::ArtifactVerificationFailed)?;
    artifact_spool.register_publication(
        &receipt.local_path,
        artifact.artifact.size,
        &artifact.artifact.sha256,
    )?;
    cancel_guard.begin_receipt();
    write_json_frame(
        &mut cancel_guard,
        WorkerDataPlaneFrameKind::ArtifactReceipt,
        3,
        &receipt,
    )?;
    cancel_guard
        .flush()
        .map_err(|_| SnapshotSessionClientError::DataPlane(WorkerDataPlaneFrameError::Io))?;
    cancel_guard.receipt_sent();

    let complete = read_until_complete(
        server_reader,
        &mut server_sequence,
        &prepared,
        &accepted,
        &mut next_event_sequence,
        &mut on_event,
    )?;
    Ok(SnapshotSessionOutcome {
        accepted,
        artifact,
        receipt,
        complete,
    })
}

fn cleanup_session_error<T>(
    artifact_spool: &mut CreateOnlyArtifactSpool,
    error: SnapshotSessionClientError,
) -> Result<T, SnapshotSessionClientError> {
    artifact_spool.cleanup_failure()?;
    Err(error)
}

struct PreReceiptCancelGuard<'a, Writer: Write> {
    writer: &'a mut Writer,
    progress: &'a mut SnapshotSessionProgress,
    armed: bool,
}

impl<'a, Writer: Write> PreReceiptCancelGuard<'a, Writer> {
    fn new(writer: &'a mut Writer, progress: &'a mut SnapshotSessionProgress) -> Self {
        Self {
            writer,
            progress,
            armed: true,
        }
    }

    fn begin_receipt(&mut self) {
        self.progress.client_output = ClientOutputState::ReceiptStarted;
        self.armed = false;
    }

    fn receipt_sent(&mut self) {
        self.progress.client_output = ClientOutputState::ReceiptSent;
    }
}

impl<Writer: Write> Write for PreReceiptCancelGuard<'_, Writer> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl<Writer: Write> Drop for PreReceiptCancelGuard<'_, Writer> {
    fn drop(&mut self) {
        if self.armed && self.progress.can_send_cancel() {
            let sent = write_worker_data_plane_frame(
                self.writer,
                WorkerDataPlaneFrameKind::Cancel,
                3,
                &[],
            )
            .and_then(|()| {
                self.writer
                    .flush()
                    .map_err(|_| WorkerDataPlaneFrameError::Io)
            });
            if sent.is_ok() {
                self.progress.mark_cancel_sent();
            }
        }
    }
}

struct PreparedRequest<'a> {
    start: &'a SnapshotBuildStart,
    source_descriptor: &'a mut File,
    source_archive: &'a mut File,
    operation_id: String,
    protocol_version: rustferry_remote::ProtocolVersion,
    request_sha256: String,
    source_sha256: String,
}

fn prepare_request(
    request: SnapshotSessionRequest<'_>,
) -> Result<PreparedRequest<'_>, SnapshotSessionClientError> {
    let SnapshotSessionRequest {
        start,
        source_descriptor,
        source_archive,
        source_limits,
    } = request;
    start
        .validate()
        .map_err(|_| SnapshotSessionClientError::InvalidBuildStart)?;
    validate_open_file_bytes(
        source_descriptor,
        start.source_descriptor_size,
        &start.source_descriptor_sha256,
        SnapshotSessionClientError::SourceDescriptorMismatch,
    )?;
    validate_open_file_bytes(
        source_archive,
        start.source_archive.size,
        &start.source_archive.sha256,
        SnapshotSessionClientError::SourceArchiveMismatch,
    )?;

    let descriptor = parse_validated_descriptor(
        source_descriptor,
        start.source_descriptor_size,
        &start.source_descriptor_sha256,
    )?;
    let reconstructed = start
        .reconstruct_request(&descriptor, source_limits)
        .map_err(|_| SnapshotSessionClientError::InvalidSourceDescriptor)?;
    let request_sha256 = canonical_request_sha256(&reconstructed)
        .map_err(|_| SnapshotSessionClientError::InvalidBuildStart)?;
    let protocol_version = CURRENT_PROTOCOL_VERSION
        .negotiate(reconstructed.protocol_version)
        .map_err(|_| SnapshotSessionClientError::InvalidBuildStart)?;
    source_descriptor
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    source_archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;

    Ok(PreparedRequest {
        start,
        source_descriptor,
        source_archive,
        operation_id: reconstructed.operation_id,
        protocol_version,
        request_sha256,
        source_sha256: reconstructed.source.sha256,
    })
}

fn write_request_frames(
    writer: &mut impl Write,
    prepared: &mut PreparedRequest<'_>,
) -> Result<(), SnapshotSessionClientError> {
    write_json_frame(
        writer,
        WorkerDataPlaneFrameKind::BuildRequest,
        0,
        prepared.start,
    )?;
    stream_validated_file(
        writer,
        WorkerDataPlaneFrameKind::SourceDescriptor,
        1,
        prepared.source_descriptor,
        prepared.start.source_descriptor_size,
        &prepared.start.source_descriptor_sha256,
        &SnapshotSessionClientError::SourceDescriptorMismatch,
    )?;
    stream_validated_file(
        writer,
        WorkerDataPlaneFrameKind::SourceArchive,
        2,
        prepared.source_archive,
        prepared.start.source_archive.size,
        &prepared.start.source_archive.sha256,
        &SnapshotSessionClientError::SourceArchiveMismatch,
    )
}

fn read_job_accepted(
    reader: &mut impl Read,
    sequence: &mut WorkerDataPlaneSequence,
    operation_id: &str,
    protocol_version: rustferry_remote::ProtocolVersion,
) -> Result<SnapshotJobAccepted, SnapshotSessionClientError> {
    let header = read_sequenced_header(reader, sequence)?;
    match header.kind() {
        WorkerDataPlaneFrameKind::JobAccepted => {
            let accepted = read_json_frame::<SnapshotJobAccepted>(reader, header)?;
            accepted
                .validate()
                .map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
            if accepted.operation_id != operation_id
                || accepted.protocol_version != protocol_version
            {
                return Err(SnapshotSessionClientError::JobIdentityMismatch);
            }
            Ok(accepted)
        }
        WorkerDataPlaneFrameKind::Error => Err(SnapshotSessionClientError::Server(Box::new(
            read_server_error(reader, header, operation_id, protocol_version, None)?,
        ))),
        received => Err(SnapshotSessionClientError::UnexpectedServerFrame {
            expected: "job_accepted or error",
            received,
        }),
    }
}

fn read_until_artifact_descriptor(
    reader: &mut impl Read,
    sequence: &mut WorkerDataPlaneSequence,
    prepared: &PreparedRequest<'_>,
    accepted: &SnapshotJobAccepted,
    next_event_sequence: &mut u64,
    on_event: &mut impl FnMut(RemoteBuildEvent),
) -> Result<SnapshotArtifactDescriptor, SnapshotSessionClientError> {
    loop {
        let header = read_sequenced_header(reader, sequence)?;
        match header.kind() {
            WorkerDataPlaneFrameKind::Event => {
                let event = read_event(reader, header, prepared, accepted, next_event_sequence)?;
                on_event(event);
            }
            WorkerDataPlaneFrameKind::ArtifactDescriptor => {
                let artifact = read_json_frame::<SnapshotArtifactDescriptor>(reader, header)?;
                artifact
                    .validate()
                    .map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
                if artifact.operation_id != prepared.operation_id
                    || artifact.job_id != accepted.job_id
                    || artifact.protocol_version != prepared.protocol_version
                {
                    return Err(SnapshotSessionClientError::ArtifactIdentityMismatch);
                }
                if artifact.compile.request_sha256 != prepared.request_sha256
                    || artifact.compile.source_sha256 != prepared.source_sha256
                    || artifact.compile.provider != SSH_PROVIDER_ID
                {
                    return Err(SnapshotSessionClientError::CompileEvidenceMismatch);
                }
                return Ok(artifact);
            }
            WorkerDataPlaneFrameKind::Error => {
                return Err(SnapshotSessionClientError::Server(Box::new(
                    read_server_error(
                        reader,
                        header,
                        &prepared.operation_id,
                        prepared.protocol_version,
                        Some(accepted),
                    )?,
                )));
            }
            received => {
                return Err(SnapshotSessionClientError::UnexpectedServerFrame {
                    expected: "event, artifact_descriptor, or error",
                    received,
                });
            }
        }
    }
}

fn read_artifact_payload(
    reader: &mut impl Read,
    sequence: &mut WorkerDataPlaneSequence,
    prepared: &PreparedRequest<'_>,
    accepted: &SnapshotJobAccepted,
    artifact: &SnapshotArtifactDescriptor,
    spool: &mut CreateOnlyArtifactSpool,
) -> Result<(), SnapshotSessionClientError> {
    let header = read_sequenced_header(reader, sequence)?;
    if header.kind() == WorkerDataPlaneFrameKind::Error {
        return Err(SnapshotSessionClientError::Server(Box::new(
            read_server_error(
                reader,
                header,
                &prepared.operation_id,
                prepared.protocol_version,
                Some(accepted),
            )?,
        )));
    }
    if header.kind() != WorkerDataPlaneFrameKind::Artifact {
        return Err(SnapshotSessionClientError::UnexpectedServerFrame {
            expected: "artifact immediately after artifact_descriptor",
            received: header.kind(),
        });
    }
    if header.payload_bytes() != artifact.artifact.size {
        return Err(SnapshotSessionClientError::ArtifactPayloadMismatch);
    }
    spool.validate_new_link()?;
    spool
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    let digest = copy_exact_hashed(reader, &mut spool.file, header.payload_bytes())?;
    spool
        .file
        .flush()
        .and_then(|()| spool.file.sync_all())
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    if digest != artifact.artifact.sha256
        || spool
            .file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?
            .len()
            != artifact.artifact.size
    {
        return Err(SnapshotSessionClientError::ArtifactPayloadMismatch);
    }
    Ok(())
}

fn read_until_complete(
    reader: &mut impl Read,
    sequence: &mut WorkerDataPlaneSequence,
    prepared: &PreparedRequest<'_>,
    accepted: &SnapshotJobAccepted,
    next_event_sequence: &mut u64,
    on_event: &mut impl FnMut(RemoteBuildEvent),
) -> Result<SnapshotBuildComplete, SnapshotSessionClientError> {
    loop {
        let header = read_sequenced_header(reader, sequence)?;
        match header.kind() {
            WorkerDataPlaneFrameKind::Event => {
                let event = read_event(reader, header, prepared, accepted, next_event_sequence)?;
                on_event(event);
            }
            WorkerDataPlaneFrameKind::Complete => {
                let complete = read_json_frame::<SnapshotBuildComplete>(reader, header)?;
                complete
                    .validate()
                    .map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
                if complete.operation_id != prepared.operation_id
                    || complete.job_id != accepted.job_id
                    || complete.protocol_version != prepared.protocol_version
                {
                    return Err(SnapshotSessionClientError::CompletionIdentityMismatch);
                }
                return Ok(complete);
            }
            WorkerDataPlaneFrameKind::Error => {
                return Err(SnapshotSessionClientError::Server(Box::new(
                    read_server_error(
                        reader,
                        header,
                        &prepared.operation_id,
                        prepared.protocol_version,
                        Some(accepted),
                    )?,
                )));
            }
            received => {
                return Err(SnapshotSessionClientError::UnexpectedServerFrame {
                    expected: "event, complete, or error after artifact receipt",
                    received,
                });
            }
        }
    }
}

fn read_event(
    reader: &mut impl Read,
    header: WorkerDataPlaneFrameHeader,
    prepared: &PreparedRequest<'_>,
    accepted: &SnapshotJobAccepted,
    next_event_sequence: &mut u64,
) -> Result<RemoteBuildEvent, SnapshotSessionClientError> {
    let payload = read_worker_data_plane_payload(reader, header)?;
    let event = RemoteBuildEvent::decode_line_bytes(&payload)
        .map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
    if event.protocol_version != prepared.protocol_version
        || event.operation_id != prepared.operation_id
        || event.job_id != accepted.job_id
        || event.provider != SSH_PROVIDER_ID
    {
        return Err(SnapshotSessionClientError::EventIdentityMismatch);
    }
    if event.sequence != *next_event_sequence {
        return Err(SnapshotSessionClientError::EventSequenceMismatch);
    }
    *next_event_sequence = next_event_sequence
        .checked_add(1)
        .ok_or(SnapshotSessionClientError::EventSequenceMismatch)?;
    Ok(event)
}

fn read_server_error(
    reader: &mut impl Read,
    header: WorkerDataPlaneFrameHeader,
    operation_id: &str,
    protocol_version: rustferry_remote::ProtocolVersion,
    accepted: Option<&SnapshotJobAccepted>,
) -> Result<SnapshotSessionError, SnapshotSessionClientError> {
    let error = read_json_frame::<SnapshotSessionError>(reader, header)?;
    error
        .validate()
        .map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
    if error.protocol_version != protocol_version
        || error
            .operation_id
            .as_deref()
            .is_some_and(|received| received != operation_id)
    {
        return Err(SnapshotSessionClientError::JobIdentityMismatch);
    }
    if let Some(accepted) = accepted {
        if error.operation_id.as_deref() != Some(operation_id)
            || error.job_id.as_deref() != Some(accepted.job_id.as_str())
        {
            return Err(SnapshotSessionClientError::JobIdentityMismatch);
        }
    } else if error.job_id.is_some() {
        return Err(SnapshotSessionClientError::JobIdentityMismatch);
    }
    Ok(error)
}

fn read_sequenced_header(
    reader: &mut impl Read,
    sequence: &mut WorkerDataPlaneSequence,
) -> Result<WorkerDataPlaneFrameHeader, SnapshotSessionClientError> {
    let header = read_worker_data_plane_header(reader)?;
    sequence.accept(header)?;
    Ok(header)
}

fn read_json_frame<T: DeserializeOwned>(
    reader: &mut impl Read,
    header: WorkerDataPlaneFrameHeader,
) -> Result<T, SnapshotSessionClientError> {
    let payload = read_worker_data_plane_payload(reader, header)?;
    serde_json::from_slice(&payload).map_err(|_| SnapshotSessionClientError::InvalidControlFrame)
}

fn write_json_frame<T: Serialize>(
    writer: &mut impl Write,
    kind: WorkerDataPlaneFrameKind,
    sequence: u64,
    value: &T,
) -> Result<(), SnapshotSessionClientError> {
    let payload =
        serde_json::to_vec(value).map_err(|_| SnapshotSessionClientError::InvalidControlFrame)?;
    write_worker_data_plane_frame(writer, kind, sequence, &payload)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stream_validated_file(
    writer: &mut impl Write,
    kind: WorkerDataPlaneFrameKind,
    sequence: u64,
    file: &mut File,
    expected_size: u64,
    expected_sha256: &str,
    mismatch: &SnapshotSessionClientError,
) -> Result<(), SnapshotSessionClientError> {
    validate_open_file_bytes(file, expected_size, expected_sha256, mismatch.clone())?;
    let before = FileState::from_metadata(
        &file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?,
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    let header = WorkerDataPlaneFrameHeader::new(kind, sequence, expected_size)?;
    write_worker_data_plane_header(writer, header)?;
    let digest = copy_exact_hashed(file, writer, expected_size)?;
    let mut extra = [0_u8; 1];
    let has_extra = file
        .read(&mut extra)
        .map_err(|_| SnapshotSessionClientError::LocalIo)?
        != 0;
    let after = FileState::from_metadata(
        &file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?,
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    if has_extra || before != after || digest != expected_sha256 {
        return Err(SnapshotSessionClientError::SourceFileChanged);
    }
    Ok(())
}

fn validate_open_file_bytes(
    file: &mut File,
    expected_size: u64,
    expected_sha256: &str,
    mismatch: SnapshotSessionClientError,
) -> Result<(), SnapshotSessionClientError> {
    let before_metadata = file
        .metadata()
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    if !before_metadata.file_type().is_file() || before_metadata.len() != expected_size {
        return Err(mismatch);
    }
    let before = FileState::from_metadata(&before_metadata);
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    let (size, digest) = hash_to_end(file, expected_size)?;
    let after = FileState::from_metadata(
        &file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?,
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    if before != after || size != expected_size || digest != expected_sha256 {
        return Err(mismatch);
    }
    Ok(())
}

fn parse_validated_descriptor(
    file: &mut File,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<SourceBundleDescriptor, SnapshotSessionClientError> {
    let before = FileState::from_metadata(
        &file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?,
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    let mut reader = HashingReader::new(file);
    let descriptor = serde_json::from_reader::<_, SourceBundleDescriptor>(&mut reader)
        .map_err(|_| SnapshotSessionClientError::InvalidSourceDescriptor)?;
    let (size, digest) = reader.finish();
    let after = FileState::from_metadata(
        &file
            .metadata()
            .map_err(|_| SnapshotSessionClientError::LocalIo)?,
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::LocalIo)?;
    if before != after || size != expected_size || digest != expected_sha256 {
        return Err(SnapshotSessionClientError::SourceDescriptorMismatch);
    }
    Ok(descriptor)
}

fn hash_to_end(
    reader: &mut impl Read,
    expected_size: u64,
) -> Result<(u64, String), SnapshotSessionClientError> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| SnapshotSessionClientError::LocalIo)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(SnapshotSessionClientError::LocalIo)?;
        if total > expected_size {
            return Ok((total, String::new()));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((total, lowercase_hex(&hasher.finalize())))
}

fn copy_exact_hashed(
    reader: &mut impl Read,
    writer: &mut impl Write,
    payload_bytes: u64,
) -> Result<String, SnapshotSessionClientError> {
    let mut remaining = payload_bytes;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| WorkerDataPlaneFrameError::PayloadSizeUnsupported)?;
        let count = reader
            .read(&mut buffer[..chunk])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        if count == 0 {
            return Err(WorkerDataPlaneFrameError::TruncatedPayload.into());
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(lowercase_hex(&hasher.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

struct HashingReader<'a> {
    inner: &'a mut File,
    hasher: Sha256,
    total: u64,
}

impl<'a> HashingReader<'a> {
    fn new(inner: &'a mut File) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            total: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.total, lowercase_hex(&self.hasher.finalize()))
    }
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.total = self.total.saturating_add(count as u64);
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileState {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileState {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }
}

fn same_file_identity(left: &File, right: &File) -> bool {
    let Ok(left) = left.try_clone().and_then(same_file::Handle::from_file) else {
        return false;
    };
    let Ok(right) = right.try_clone().and_then(same_file::Handle::from_file) else {
        return false;
    };
    left == right
}

fn same_directory_entry(left: &Utf8Path, right: &Utf8Path) -> bool {
    left == right
        || fs::canonicalize(left)
            .ok()
            .zip(fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

fn open_publication_identity(
    spool: &File,
    path: &Utf8Path,
) -> Result<File, SnapshotSessionClientError> {
    let published = open_publication_file(path)?;
    let published_metadata = published
        .metadata()
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    if !published_metadata.file_type().is_file() || !same_file_identity(spool, &published) {
        return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
    }
    Ok(published)
}

fn validate_published_artifact(
    spool: &File,
    retained: &File,
    path: &Utf8Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), SnapshotSessionClientError> {
    let mut published = open_publication_file(path)?;
    let published_metadata = published
        .metadata()
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    if !published_metadata.file_type().is_file()
        || published_metadata.len() != expected_size
        || !same_file_identity(spool, &published)
        || !same_file_identity(retained, &published)
    {
        return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
    }
    published
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    let (size, digest) = hash_to_end(&mut published, expected_size)
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    if size != expected_size || digest != expected_sha256 {
        return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
    }
    published
        .sync_all()
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    sync_parent_directory(path).map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)
}

fn open_publication_file(path: &Utf8Path) -> Result<File, SnapshotSessionClientError> {
    let linked = fs::symlink_metadata(path)
        .map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)?;
    if linked.file_type().is_symlink() || !linked.file_type().is_file() {
        return Err(SnapshotSessionClientError::ArtifactPublicationFailed);
    }
    open_file_no_follow(path).map_err(|_| SnapshotSessionClientError::ArtifactPublicationFailed)
}

fn open_file_no_follow(path: &Utf8Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn sync_parent_directory(path: &Utf8Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    #[cfg(unix)]
    return File::open(parent)?.sync_all();
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Cursor,
    };
    #[cfg(unix)]
    use std::{
        ffi::OsString,
        panic::{AssertUnwindSafe, catch_unwind},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(unix)]
    use rustferry_remote::CancellationToken;
    use rustferry_remote::{
        ApplePlatform, ArtifactKind, ArtifactRecord, BuildProfile, BundleIdentifier,
        COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CURRENT_PROTOCOL_VERSION, CleanupConfirmation,
        CompilePhaseEvidence, CompileToolchainEvidence, IOS_DEVICE_RUST_TARGET, IosArtifactType,
        IosDeviceBuildRequest, IosDeviceProductExpectation, JobState, MachOSliceEvidence,
        ProtocolPathSemantics, ProtocolVersion, RemoteBuildEventKind,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningMode, SigningPlan,
        SigningTarget, SigningTargetKind, SnapshotBuildParameters, SourceArchive,
        SourceBundleRequest, SourceMode, UnsignedAppInspection, UnsignedXcarchiveExpectation,
        UnsignedXcarchiveInspection, WorkerDataPlaneFrameError, copy_worker_data_plane_payload,
        plan_source_bundle, write_worker_data_plane_frame,
    };

    use super::*;
    #[cfg(unix)]
    use crate::{
        ProcessSshRunner, SshInvocation, SshSnapshotSessionError, SshTransportError,
        transport::test_invocation,
    };

    struct Fixture {
        _directory: tempfile::TempDir,
        descriptor_path: Utf8PathBuf,
        archive_path: Utf8PathBuf,
        descriptor_bytes: Vec<u8>,
        archive_bytes: Vec<u8>,
        artifact_bytes: Vec<u8>,
        start: SnapshotBuildStart,
        accepted: SnapshotJobAccepted,
        artifact: SnapshotArtifactDescriptor,
        complete: SnapshotBuildComplete,
    }

    impl Fixture {
        fn source_handles(&self) -> (File, File) {
            (
                File::open(&self.descriptor_path).expect("descriptor handle"),
                File::open(&self.archive_path).expect("archive handle"),
            )
        }

        fn spool_path(&self, label: &str) -> Utf8PathBuf {
            self.descriptor_path
                .parent()
                .expect("fixture directory")
                .join(format!("artifact-{label}.zip"))
        }
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = Utf8PathBuf::from_path_buf(directory.path().join("app")).expect("UTF-8 path");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n",
        )
        .expect("Cargo.toml");
        fs::write(root.join("Cargo.lock"), "# fixture\n").expect("Cargo.lock");
        fs::write(root.join("ferry.toml"), "[app]\nname='App'\n").expect("ferry.toml");
        fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
        let plan =
            plan_source_bundle(&SourceBundleRequest::new(&root, &root)).expect("source plan");

        let archive_bytes = b"deterministic source archive fixture".repeat(4);
        let source_archive = SourceArchive {
            size: archive_bytes.len() as u64,
            sha256: sha256(&archive_bytes),
        };
        let descriptor =
            SourceBundleDescriptor::new(source_archive.clone(), plan.manifest().clone());
        descriptor
            .validate(SourceArchiveLimits::default())
            .expect("source descriptor");
        let descriptor_bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
        let descriptor_path = root
            .parent()
            .expect("fixture directory")
            .join("source.json");
        let archive_path = root.parent().expect("fixture directory").join("source.zip");
        fs::write(&descriptor_path, &descriptor_bytes).expect("descriptor file");
        fs::write(&archive_path, &archive_bytes).expect("archive file");

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
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        request.validate().expect("request");
        let start = SnapshotBuildStart::new(
            SnapshotBuildParameters::from_request(&request).expect("parameters"),
            descriptor_bytes.len() as u64,
            sha256(&descriptor_bytes),
            source_archive,
        )
        .expect("build start");
        let accepted =
            SnapshotJobAccepted::new("operation-1", "job-1", 10).expect("job acknowledgement");

        let artifact_bytes = vec![0x5a; 456];
        let artifact_archive = SourceArchive {
            size: artifact_bytes.len() as u64,
            sha256: sha256(&artifact_bytes),
        };
        let expectation = UnsignedXcarchiveExpectation {
            app_directory_name: "App.app".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            executable: "App".to_owned(),
            app_version: "1.0.0".to_owned(),
            build_number: "1".to_owned(),
            minimum_os: "16.0".to_owned(),
            sdk_version: "18.5".to_owned(),
            sdk_build_version: "22F76".to_owned(),
            nested_bundles: Vec::new(),
            required_resources: BTreeMap::new(),
        };
        let slice = MachOSliceEvidence {
            architecture: "arm64".to_owned(),
            platform: ApplePlatform::Ios,
            minimum_os: Some("16.0.0".to_owned()),
            sdk: Some("18.5.0".to_owned()),
        };
        let inspection = UnsignedXcarchiveInspection {
            application_path: "Applications/App.app".to_owned(),
            architectures: vec!["arm64".to_owned()],
            app: UnsignedAppInspection {
                app_directory_name: "App.app".to_owned(),
                bundle_identifier: "com.example.app".to_owned(),
                executable: "App".to_owned(),
                main_executable: vec![slice],
                nested_executables: BTreeMap::new(),
                extensions: Vec::new(),
                resources: BTreeMap::new(),
                entries: vec!["App".to_owned()],
            },
            entries: vec!["Products/Applications/App.app/App".to_owned()],
        };
        let compile = CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: accepted.job_id.clone(),
            provider: "ssh-macos".to_owned(),
            request_sha256: canonical_request_sha256(&request).expect("request hash"),
            source_sha256: request.source.sha256.clone(),
            cargo_lock_sha256: "d".repeat(64),
            config_sha256: "e".repeat(64),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 15.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "16.4".to_owned(),
                iphoneos_sdk_version: "18.5".to_owned(),
                iphoneos_sdk_build_version: "22F76".to_owned(),
                developer_directory_sha256: "f".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: artifact_archive.clone(),
                contents: descriptor.manifest,
                expectation,
            },
            archive_inspection: inspection,
            started_at_unix_seconds: 100,
            finished_at_unix_seconds: 200,
        };
        let artifact = SnapshotArtifactDescriptor::new(
            request.operation_id.clone(),
            ArtifactRecord {
                artifact_id: "archive-1".to_owned(),
                kind: ArtifactKind::Xcarchive,
                file_name: "App-unsigned.xcarchive.zip".to_owned(),
                size: artifact_archive.size,
                sha256: artifact_archive.sha256,
                media_type: Some("application/zip".to_owned()),
            },
            compile,
        )
        .expect("artifact descriptor");
        let complete = SnapshotBuildComplete::new(
            request.operation_id,
            CleanupConfirmation {
                job_id: accepted.job_id.clone(),
                completed_at_ms: 300,
                workspace_removed: true,
                signing_material_removed: true,
                artifacts_retained: false,
            },
        )
        .expect("completion");

        Fixture {
            _directory: directory,
            descriptor_path,
            archive_path,
            descriptor_bytes,
            archive_bytes,
            artifact_bytes,
            start,
            accepted,
            artifact,
            complete,
        }
    }

    fn event(fixture: &Fixture, sequence: u64, kind: RemoteBuildEventKind) -> RemoteBuildEvent {
        RemoteBuildEvent::new(
            fixture.start.parameters.operation_id.clone(),
            fixture.accepted.job_id.clone(),
            20 + sequence,
            "ssh-macos",
            "compile",
            sequence,
            kind,
        )
        .expect("event")
    }

    fn success_transcript(fixture: &Fixture) -> Vec<u8> {
        let first = event(
            fixture,
            0,
            RemoteBuildEventKind::JobCreated {
                state: JobState::Created,
            },
        );
        let second = event(fixture, 1, RemoteBuildEventKind::CleanupStarted);
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(&mut transcript, WorkerDataPlaneFrameKind::Event, 1, &first)
            .expect("first event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            2,
            &fixture.artifact,
        )
        .expect("artifact descriptor");
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            3,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        write_json_frame(&mut transcript, WorkerDataPlaneFrameKind::Event, 4, &second)
            .expect("second event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Complete,
            5,
            &fixture.complete,
        )
        .expect("complete frame");
        transcript
    }

    #[test]
    fn success_transcript_streams_exact_files_and_receipts_verified_artifact() {
        let fixture = fixture();
        let mut server = Cursor::new(success_transcript(&fixture));
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let spool_path = fixture.spool_path("success");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let mut events = Vec::new();
        let outcome = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |event| events.push(event),
            |file, path, offered| {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).expect("verify spool bytes");
                assert_eq!(bytes, fixture.artifact_bytes);
                assert_eq!(offered, &fixture.artifact);
                ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string())
            },
        )
        .expect("successful session");

        assert_eq!(outcome.accepted, fixture.accepted);
        assert_eq!(outcome.artifact, fixture.artifact);
        assert_eq!(outcome.complete, fixture.complete);
        assert_eq!(outcome.receipt.local_path.value, spool_path);
        assert_eq!(events.len(), 2);
        assert_eq!(
            fs::read(&spool_path).expect("spooled artifact"),
            fixture.artifact_bytes
        );
        spool.commit().expect("commit verified publication");

        let mut client = Cursor::new(client);
        let mut sequence = WorkerDataPlaneSequence::new();
        let start_header = read_sequenced_header(&mut client, &mut sequence).expect("start header");
        assert_eq!(start_header.kind(), WorkerDataPlaneFrameKind::BuildRequest);
        assert_eq!(
            read_json_frame::<SnapshotBuildStart>(&mut client, start_header).expect("start JSON"),
            fixture.start
        );
        let descriptor_header =
            read_sequenced_header(&mut client, &mut sequence).expect("descriptor header");
        assert_eq!(
            descriptor_header.kind(),
            WorkerDataPlaneFrameKind::SourceDescriptor
        );
        assert_eq!(
            read_worker_data_plane_payload(&mut client, descriptor_header)
                .expect("descriptor payload"),
            fixture.descriptor_bytes
        );
        let archive_header =
            read_sequenced_header(&mut client, &mut sequence).expect("archive header");
        assert_eq!(
            archive_header.kind(),
            WorkerDataPlaneFrameKind::SourceArchive
        );
        let mut archive_bytes = Vec::new();
        copy_worker_data_plane_payload(&mut client, &mut archive_bytes, archive_header)
            .expect("archive payload");
        assert_eq!(archive_bytes, fixture.archive_bytes);
        let receipt_header =
            read_sequenced_header(&mut client, &mut sequence).expect("receipt header");
        assert_eq!(
            receipt_header.kind(),
            WorkerDataPlaneFrameKind::ArtifactReceipt
        );
        assert_eq!(
            read_json_frame::<SnapshotArtifactReceipt>(&mut client, receipt_header)
                .expect("receipt JSON"),
            outcome.receipt
        );
        assert_eq!(
            read_worker_data_plane_header(&mut client),
            Err(WorkerDataPlaneFrameError::EmptyInput)
        );
    }

    #[test]
    fn bad_server_sequence_and_kind_fail_before_payload_interpretation() {
        let fixture = fixture();
        let mut wrong_sequence = Vec::new();
        write_json_frame(
            &mut wrong_sequence,
            WorkerDataPlaneFrameKind::JobAccepted,
            1,
            &fixture.accepted,
        )
        .expect("wrong sequence frame");
        let (error, _) = run_failure(&fixture, wrong_sequence, "bad-sequence");
        assert_eq!(
            error,
            SnapshotSessionClientError::DataPlane(WorkerDataPlaneFrameError::UnexpectedSequence {
                expected: 0,
                received: 1,
            })
        );

        let mut wrong_kind = Vec::new();
        write_worker_data_plane_frame(&mut wrong_kind, WorkerDataPlaneFrameKind::Event, 0, b"{}")
            .expect("wrong kind frame");
        let (error, _) = run_failure(&fixture, wrong_kind, "bad-kind");
        assert_eq!(
            error,
            SnapshotSessionClientError::UnexpectedServerFrame {
                expected: "job_accepted or error",
                received: WorkerDataPlaneFrameKind::Event,
            }
        );
    }

    #[test]
    fn truncated_or_hash_mismatched_artifact_never_emits_receipt() {
        let fixture = fixture();
        let mut truncated = artifact_prefix(&fixture);
        let header = WorkerDataPlaneFrameHeader::new(
            WorkerDataPlaneFrameKind::Artifact,
            2,
            fixture.artifact_bytes.len() as u64,
        )
        .expect("artifact header");
        write_worker_data_plane_header(&mut truncated, header).expect("artifact header bytes");
        truncated.extend_from_slice(&fixture.artifact_bytes[..32]);
        let (error, client) = run_failure(&fixture, truncated, "truncated");
        assert_eq!(
            error,
            SnapshotSessionClientError::DataPlane(WorkerDataPlaneFrameError::TruncatedPayload)
        );
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));

        let mut wrong_hash = artifact_prefix(&fixture);
        let mismatched = vec![0x3c; fixture.artifact_bytes.len()];
        write_worker_data_plane_frame(
            &mut wrong_hash,
            WorkerDataPlaneFrameKind::Artifact,
            2,
            &mismatched,
        )
        .expect("mismatched artifact");
        let (error, client) = run_failure(&fixture, wrong_hash, "hash-mismatch");
        assert_eq!(error, SnapshotSessionClientError::ArtifactPayloadMismatch);
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
    }

    #[test]
    fn artifact_without_a_validated_progress_event_never_reaches_verifier_or_receipt() {
        let fixture = fixture();
        let mut transcript = artifact_prefix(&fixture);
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            2,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        let mut server = Cursor::new(transcript);
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let spool_path = fixture.spool_path("missing-progress-event");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let mut verifier_called = false;
        let error = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, path, _| {
                verifier_called = true;
                ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string())
            },
        )
        .expect_err("missing progress event");
        assert_eq!(error, SnapshotSessionClientError::MissingProgressEvent);
        assert!(!verifier_called);
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
        assert!(!spool_path.exists());
    }

    #[test]
    fn source_hash_mismatch_is_rejected_before_any_wire_write() {
        let fixture = fixture();
        fs::write(&fixture.archive_path, b"substituted source archive")
            .expect("replace source archive");
        let (error, client) = run_failure(&fixture, Vec::new(), "source-mismatch");
        assert_eq!(error, SnapshotSessionClientError::SourceArchiveMismatch);
        assert!(client.is_empty());
    }

    #[test]
    fn compile_evidence_must_bind_the_reconstructed_request() {
        let fixture = fixture();
        let mut substituted = fixture.artifact.clone();
        substituted.compile.request_sha256 = "0".repeat(64);
        substituted
            .validate()
            .expect("intrinsically valid descriptor");
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            1,
            &substituted,
        )
        .expect("substituted descriptor");
        let (error, client) = run_failure(&fixture, transcript, "evidence-mismatch");
        assert_eq!(error, SnapshotSessionClientError::CompileEvidenceMismatch);
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
    }

    #[test]
    fn verifier_rejection_never_emits_artifact_receipt() {
        let fixture = fixture();
        let mut server = Cursor::new(success_transcript(&fixture));
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let spool_path = fixture.spool_path("verifier-rejected");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, _, _| Err::<ProtocolPath, ()>(()),
        )
        .expect_err("verifier rejection");
        assert_eq!(
            error,
            SnapshotSessionClientError::ArtifactVerificationFailed
        );
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
        assert!(!spool_path.exists());
    }

    #[test]
    fn validated_server_error_is_returned_without_artifact_receipt() {
        let fixture = fixture();
        let failure = SnapshotSessionError::new(
            Some(fixture.start.parameters.operation_id.clone()),
            Some(fixture.accepted.job_id.clone()),
            "worker.build_failed",
            "Unsigned build failed",
            false,
            None,
        )
        .expect("server error");
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Error,
            1,
            &failure,
        )
        .expect("error frame");
        let (error, client) = run_failure(&fixture, transcript, "server-error");
        assert_eq!(error, SnapshotSessionClientError::Server(Box::new(failure)));
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
    }

    #[test]
    fn publication_requires_an_existing_same_inode_final_path() {
        let fixture = fixture();
        let missing = fixture.spool_path("missing-publication");
        let (error, client) = run_with_publication_path(
            &fixture,
            success_transcript(&fixture),
            "missing-publication-spool",
            &missing,
        );
        assert_eq!(error, SnapshotSessionClientError::ArtifactPublicationFailed);
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));

        let unrelated = fixture.spool_path("unrelated-publication");
        fs::write(&unrelated, &fixture.artifact_bytes).expect("unrelated artifact");
        let (error, client) = run_with_publication_path(
            &fixture,
            success_transcript(&fixture),
            "unrelated-publication-spool",
            &unrelated,
        );
        assert_eq!(error, SnapshotSessionClientError::ArtifactPublicationFailed);
        assert!(!client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
        assert_eq!(
            fs::read(&unrelated).expect("preserved unrelated artifact"),
            fixture.artifact_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_publication_commits_only_after_explicit_authorization() {
        let fixture = fixture();
        let final_path = fixture.spool_path("hardlink-final");
        let spool_path = fixture.spool_path("hardlink-staging");
        let mut server = Cursor::new(success_transcript(&fixture));
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, staging, _| {
                fs::hard_link(staging, &final_path).expect("publish hard link");
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    final_path.to_string(),
                )
            },
        )
        .expect("successful hardlink session");
        assert!(spool_path.exists());
        assert!(final_path.exists());
        spool.commit().expect("commit hardlink publication");
        assert!(!spool_path.exists());
        assert_eq!(
            fs::read(final_path).expect("committed final artifact"),
            fixture.artifact_bytes
        );
    }

    #[test]
    fn explicit_abort_removes_staging_and_is_idempotent() {
        let fixture = fixture();
        let spool_path = fixture.spool_path("explicit-abort");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        assert!(spool_path.exists());
        spool.abort().expect("abort staging spool");
        assert!(!spool_path.exists());
        spool.abort().expect("repeat abort");
    }

    #[cfg(unix)]
    #[test]
    fn commit_revalidates_publication_after_removing_staging_link() {
        let fixture = fixture();
        let final_path = fixture.spool_path("commit-race-final");
        let spool_path = fixture.spool_path("commit-race-staging");
        let mut server = Cursor::new(success_transcript(&fixture));
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, staging, _| {
                fs::hard_link(staging, &final_path).expect("publish hard link");
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    final_path.to_string(),
                )
            },
        )
        .expect("successful hardlink session");

        let error = spool
            .commit_with(|_| {
                fs::remove_file(&final_path).expect("remove verified final link");
                fs::write(&final_path, b"concurrent replacement").expect("replace final path");
            })
            .expect_err("replaced publication cannot commit");
        assert_eq!(error, SnapshotSessionClientError::ArtifactCleanupFailed);
        assert!(!spool_path.exists());
        assert_eq!(
            fs::read(final_path).expect("preserved concurrent replacement"),
            b"concurrent replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_abort_preserves_replaced_publication_and_reports_cleanup_failure() {
        let fixture = fixture();
        let final_path = fixture.spool_path("abort-race-final");
        let spool_path = fixture.spool_path("abort-race-staging");
        let mut server = Cursor::new(success_transcript(&fixture));
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, staging, _| {
                fs::hard_link(staging, &final_path).expect("publish hard link");
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    final_path.to_string(),
                )
            },
        )
        .expect("successful hardlink session");
        fs::remove_file(&final_path).expect("remove verified final link");
        fs::write(&final_path, b"concurrent replacement").expect("replace final path");

        let error = spool
            .abort()
            .expect_err("replacement makes cleanup uncertain");
        assert_eq!(error, SnapshotSessionClientError::ArtifactCleanupFailed);
        assert!(!spool_path.exists());
        assert_eq!(
            fs::read(final_path).expect("preserved concurrent replacement"),
            b"concurrent replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uncommitted_success_and_post_receipt_error_remove_all_owned_links() {
        let fixture = fixture();
        let final_path = fixture.spool_path("uncommitted-final");
        let spool_path = fixture.spool_path("uncommitted-staging");
        {
            let mut server = Cursor::new(success_transcript(&fixture));
            let mut client = Vec::new();
            let (mut descriptor, mut archive) = fixture.source_handles();
            let mut spool =
                CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
            run_snapshot_session(
                &mut server,
                &mut client,
                SnapshotSessionRequest::new(
                    &fixture.start,
                    &mut descriptor,
                    &mut archive,
                    SourceArchiveLimits::default(),
                ),
                &mut spool,
                |_| {},
                |_, staging, _| {
                    fs::hard_link(staging, &final_path).expect("publish hard link");
                    ProtocolPath::new(
                        ProtocolPathSemantics::ClientAbsolute,
                        final_path.to_string(),
                    )
                },
            )
            .expect("successful but uncommitted session");
        }
        assert!(!spool_path.exists());
        assert!(!final_path.exists());

        let final_path = fixture.spool_path("terminal-error-final");
        let spool_path = fixture.spool_path("terminal-error-staging");
        let failure = SnapshotSessionError::new(
            Some(fixture.start.parameters.operation_id.clone()),
            Some(fixture.accepted.job_id.clone()),
            "worker.cleanup_failed",
            "Cleanup failed",
            false,
            None,
        )
        .expect("server error");
        let mut transcript = artifact_prefix_with_event(&fixture);
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            3,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Error,
            4,
            &failure,
        )
        .expect("terminal error");
        let mut server = Cursor::new(transcript);
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, staging, _| {
                fs::hard_link(staging, &final_path).expect("publish hard link");
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    final_path.to_string(),
                )
            },
        )
        .expect_err("post-receipt server error");
        assert_eq!(error, SnapshotSessionClientError::Server(Box::new(failure)));
        assert!(client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
        assert!(!spool_path.exists());
        assert!(!final_path.exists());
    }

    #[test]
    fn events_require_ssh_provider_and_one_sequence_across_both_phases() {
        let fixture = fixture();
        let mut wrong_sequence = event(
            &fixture,
            1,
            RemoteBuildEventKind::JobCreated {
                state: JobState::Created,
            },
        );
        wrong_sequence.sequence = 1;
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            1,
            &wrong_sequence,
        )
        .expect("wrong event sequence");
        let (error, _) = run_failure(&fixture, transcript, "event-sequence");
        assert_eq!(error, SnapshotSessionClientError::EventSequenceMismatch);

        let mut wrong_provider = event(
            &fixture,
            0,
            RemoteBuildEventKind::JobCreated {
                state: JobState::Created,
            },
        );
        wrong_provider.provider = "github-actions".to_owned();
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            1,
            &wrong_provider,
        )
        .expect("wrong provider event");
        let (error, _) = run_failure(&fixture, transcript, "event-provider");
        assert_eq!(error, SnapshotSessionClientError::EventIdentityMismatch);

        let first = event(
            &fixture,
            0,
            RemoteBuildEventKind::JobCreated {
                state: JobState::Created,
            },
        );
        let repeated = event(&fixture, 0, RemoteBuildEventKind::CleanupStarted);
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(&mut transcript, WorkerDataPlaneFrameKind::Event, 1, &first)
            .expect("first event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            2,
            &fixture.artifact,
        )
        .expect("artifact descriptor");
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            3,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            4,
            &repeated,
        )
        .expect("repeated event");
        let (error, client) = run_failure(&fixture, transcript, "event-repeated");
        assert_eq!(error, SnapshotSessionClientError::EventSequenceMismatch);
        assert!(client_kinds(&client).contains(&WorkerDataPlaneFrameKind::ArtifactReceipt));
    }

    #[test]
    fn compile_provider_and_post_accept_error_ids_are_exact() {
        let fixture = fixture();
        let mut artifact = fixture.artifact.clone();
        artifact.compile.provider = "github-actions".to_owned();
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            1,
            &event(
                &fixture,
                0,
                RemoteBuildEventKind::JobCreated {
                    state: JobState::Created,
                },
            ),
        )
        .expect("progress event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            2,
            &artifact,
        )
        .expect("artifact descriptor");
        let (error, _) = run_failure(&fixture, transcript, "compile-provider");
        assert_eq!(error, SnapshotSessionClientError::CompileEvidenceMismatch);

        let missing_ids =
            SnapshotSessionError::new(None, None, "worker.failed", "Build failed", false, None)
                .expect("server error");
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Error,
            1,
            &missing_ids,
        )
        .expect("missing-id error");
        let (error, _) = run_failure(&fixture, transcript, "missing-error-ids");
        assert_eq!(error, SnapshotSessionClientError::JobIdentityMismatch);
    }

    #[test]
    fn replies_bind_to_negotiated_version_while_request_hash_keeps_requested_minor() {
        let fixture = fixture();
        let mut start = fixture.start.clone();
        start.parameters.protocol_version = ProtocolVersion::new(1, 1);
        start.validate().expect("future compatible start");
        let descriptor: SourceBundleDescriptor =
            serde_json::from_slice(&fixture.descriptor_bytes).expect("source descriptor");
        let request = start
            .reconstruct_request(&descriptor, SourceArchiveLimits::default())
            .expect("future compatible request");
        let mut artifact = fixture.artifact.clone();
        artifact.compile.request_sha256 =
            canonical_request_sha256(&request).expect("future request hash");
        artifact.validate().expect("future-bound artifact");
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            1,
            &event(
                &fixture,
                0,
                RemoteBuildEventKind::JobCreated {
                    state: JobState::Created,
                },
            ),
        )
        .expect("progress event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            2,
            &artifact,
        )
        .expect("artifact descriptor");
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            3,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Complete,
            4,
            &fixture.complete,
        )
        .expect("complete frame");
        let mut server = Cursor::new(transcript);
        let mut client = Vec::new();
        let (mut source_descriptor, mut source_archive) = fixture.source_handles();
        let spool_path = fixture.spool_path("future-minor");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let outcome = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &start,
                &mut source_descriptor,
                &mut source_archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, path, _| ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string()),
        )
        .expect("negotiated future-minor session");
        assert_eq!(outcome.accepted.protocol_version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(
            outcome.artifact.compile.request_sha256,
            artifact.compile.request_sha256
        );
        spool.commit().expect("commit future-minor artifact");
    }

    #[test]
    fn cleanup_quarantine_never_unlinks_a_replacement_path_occupant() {
        let fixture = fixture();
        let spool_path = fixture.spool_path("cleanup-race");
        {
            let spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
            spool
                .remove_owned_link_with(&spool_path, |_| {
                    fs::write(&spool_path, b"concurrent replacement").expect("install replacement");
                })
                .expect("remove only quarantined spool inode");
        }
        assert_eq!(
            fs::read(spool_path).expect("preserved replacement"),
            b"concurrent replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_snapshot_session_requires_protocol_and_zero_exit() {
        let fixture = fixture();
        let helper = ProcessHelper::new(&fixture);
        let invocation = helper.invocation("success", Duration::from_secs(5));
        let spool_path = fixture.spool_path("process-success");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let outcome =
            run_process_fixture(&fixture, &invocation, &CancellationToken::new(), &mut spool)
                .expect("successful process session");
        assert_eq!(outcome.complete, fixture.complete);
        assert!(spool_path.exists());
        spool.commit().expect("commit process artifact");
        assert_eq!(
            fs::read(spool_path).expect("committed process artifact"),
            fixture.artifact_bytes
        );

        let invocation = helper.invocation("nonzero", Duration::from_secs(5));
        let spool_path = fixture.spool_path("process-nonzero");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error =
            run_process_fixture(&fixture, &invocation, &CancellationToken::new(), &mut spool)
                .expect_err("nonzero OpenSSH status");
        assert_eq!(
            error,
            SshSnapshotSessionError::Transport(SshTransportError::ProcessFailed {
                status: Some(7)
            })
        );
        assert!(!spool_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn process_snapshot_session_preserves_validated_server_error_on_nonzero_exit() {
        let fixture = fixture();
        let helper = ProcessHelper::new(&fixture);
        let failure = SnapshotSessionError::new(
            Some(fixture.start.parameters.operation_id.clone()),
            Some(fixture.accepted.job_id.clone()),
            "worker.cleanup_failed",
            "Cleanup failed",
            false,
            None,
        )
        .expect("server error");
        let mut transcript = artifact_prefix_with_event(&fixture);
        write_worker_data_plane_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Artifact,
            3,
            &fixture.artifact_bytes,
        )
        .expect("artifact frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Error,
            4,
            &failure,
        )
        .expect("terminal error");
        helper.write_response(&transcript);
        let invocation = helper.invocation("semantic-nonzero", Duration::from_secs(5));
        let spool_path = fixture.spool_path("process-semantic-error");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error =
            run_process_fixture(&fixture, &invocation, &CancellationToken::new(), &mut spool)
                .expect_err("validated server error");
        assert_eq!(
            error,
            SshSnapshotSessionError::Session(SnapshotSessionClientError::Server(Box::new(failure)))
        );
        assert!(!spool_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn process_snapshot_session_reaps_child_when_event_callback_panics() {
        let fixture = fixture();
        let helper = ProcessHelper::new(&fixture);
        let invocation = helper.invocation("panic", Duration::from_secs(5));
        let spool_path = fixture.spool_path("process-panic");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let started = Instant::now();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let (mut descriptor, mut archive) = fixture.source_handles();
            let _ = ProcessSshRunner.run_snapshot_session(
                &invocation,
                SnapshotSessionRequest::new(
                    &fixture.start,
                    &mut descriptor,
                    &mut archive,
                    SourceArchiveLimits::default(),
                ),
                &mut spool,
                &CancellationToken::new(),
                |_| panic!("event callback panic"),
                |_, path, _| {
                    ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string())
                },
            );
        }));
        assert!(panic.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!spool_path.exists());
        let pid = fs::read_to_string(&helper.pid).expect("helper pid");
        let mut process_exists = true;
        for _ in 0..20 {
            process_exists = Command::new("kill")
                .args(["-0", pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !process_exists {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_exists, "panicking session left its child alive");
        assert!(!helper.marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn process_snapshot_session_timeout_and_cancellation_are_bounded() {
        let fixture = fixture();
        let helper = ProcessHelper::new(&fixture);
        let invocation = helper.invocation("timeout", Duration::from_millis(120));
        let spool_path = fixture.spool_path("process-timeout");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let started = Instant::now();
        let error =
            run_process_fixture(&fixture, &invocation, &CancellationToken::new(), &mut spool)
                .expect_err("session timeout");
        assert_eq!(
            error,
            SshSnapshotSessionError::Transport(SshTransportError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!spool_path.exists());

        let invocation = helper.invocation("timeout", Duration::from_secs(5));
        let cancellation = CancellationToken::new();
        let request = cancellation.clone();
        let cancel_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _ = request.cancel();
        });
        let spool_path = fixture.spool_path("process-cancelled");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let started = Instant::now();
        let error = run_process_fixture(&fixture, &invocation, &cancellation, &mut spool)
            .expect_err("session cancellation");
        cancel_thread.join().expect("cancellation thread");
        assert_eq!(
            error,
            SshSnapshotSessionError::Transport(SshTransportError::Cancelled)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!spool_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn process_snapshot_session_does_not_wait_for_descendant_held_pipes() {
        let fixture = fixture();
        let helper = ProcessHelper::new(&fixture);
        let invocation = helper.invocation("descendant", Duration::from_secs(5));
        let spool_path = fixture.spool_path("process-descendant");
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let started = Instant::now();
        run_process_fixture(&fixture, &invocation, &CancellationToken::new(), &mut spool)
            .expect("session with descendant-held pipes");
        assert!(started.elapsed() < Duration::from_secs(1));
        spool.commit().expect("commit descendant fixture artifact");
    }

    #[cfg(unix)]
    struct ProcessHelper {
        _directory: tempfile::TempDir,
        script: Utf8PathBuf,
        response: Utf8PathBuf,
        marker: Utf8PathBuf,
        pid: Utf8PathBuf,
    }

    #[cfg(unix)]
    impl ProcessHelper {
        fn new(fixture: &Fixture) -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let directory = tempfile::tempdir().expect("process helper directory");
            let root = Utf8PathBuf::from_path_buf(directory.path().to_path_buf())
                .expect("UTF-8 helper path");
            let script = root.join("session-helper.sh");
            let response = root.join("response.bin");
            let marker = root.join("completed");
            let pid = root.join("pid");
            fs::write(&response, success_transcript(fixture)).expect("helper response");
            fs::write(
                &script,
                concat!(
                    "#!/bin/sh\n",
                    "mode=$1\n",
                    "response=$2\n",
                    "marker=$3\n",
                    "pid=$4\n",
                    "printf '%s' \"$$\" > \"$pid\"\n",
                    "printf '%s' 'private-worker-stderr' >&2\n",
                    "case \"$mode\" in\n",
                    "  success) dd if=\"$response\" bs=16384 2>/dev/null; cat >/dev/null; exit 0 ;;\n",
                    "  descendant) sleep 2 & dd if=\"$response\" bs=16384 2>/dev/null; cat >/dev/null; exit 0 ;;\n",
                    "  timeout) sleep 2; exit 0 ;;\n",
                    "  nonzero) exit 7 ;;\n",
                    "  semantic-nonzero) dd if=\"$response\" bs=16384 2>/dev/null; cat >/dev/null; exit 1 ;;\n",
                    "  panic) dd if=\"$response\" bs=16384 2>/dev/null; sleep 2; printf '%s' completed > \"$marker\"; exit 0 ;;\n",
                    "  *) exit 9 ;;\n",
                    "esac\n",
                ),
            )
            .expect("helper script");
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .expect("helper permissions");
            Self {
                _directory: directory,
                script,
                response,
                marker,
                pid,
            }
        }

        fn write_response(&self, bytes: &[u8]) {
            fs::write(&self.response, bytes).expect("replace helper response");
        }

        fn invocation(&self, mode: &str, timeout: Duration) -> SshInvocation {
            test_invocation(
                "/bin/sh",
                [
                    OsString::from(self.script.as_str()),
                    OsString::from(mode),
                    OsString::from(self.response.as_str()),
                    OsString::from(self.marker.as_str()),
                    OsString::from(self.pid.as_str()),
                ],
                timeout,
            )
        }
    }

    #[cfg(unix)]
    fn run_process_fixture(
        fixture: &Fixture,
        invocation: &SshInvocation,
        cancellation: &CancellationToken,
        spool: &mut CreateOnlyArtifactSpool,
    ) -> Result<SnapshotSessionOutcome, SshSnapshotSessionError> {
        let (mut descriptor, mut archive) = fixture.source_handles();
        ProcessSshRunner.run_snapshot_session(
            invocation,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            spool,
            cancellation,
            |_| {},
            |_, path, _| ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string()),
        )
    }

    fn artifact_prefix(fixture: &Fixture) -> Vec<u8> {
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            1,
            &fixture.artifact,
        )
        .expect("artifact descriptor");
        transcript
    }

    fn artifact_prefix_with_event(fixture: &Fixture) -> Vec<u8> {
        let mut transcript = Vec::new();
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::JobAccepted,
            0,
            &fixture.accepted,
        )
        .expect("accepted frame");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::Event,
            1,
            &event(
                fixture,
                0,
                RemoteBuildEventKind::JobCreated {
                    state: JobState::Created,
                },
            ),
        )
        .expect("progress event");
        write_json_frame(
            &mut transcript,
            WorkerDataPlaneFrameKind::ArtifactDescriptor,
            2,
            &fixture.artifact,
        )
        .expect("artifact descriptor");
        transcript
    }

    fn run_with_publication_path(
        fixture: &Fixture,
        transcript: Vec<u8>,
        label: &str,
        publication_path: &Utf8Path,
    ) -> (SnapshotSessionClientError, Vec<u8>) {
        let mut server = Cursor::new(transcript);
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let spool_path = fixture.spool_path(label);
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, _, _| {
                ProtocolPath::new(
                    ProtocolPathSemantics::ClientAbsolute,
                    publication_path.to_string(),
                )
            },
        )
        .expect_err("publication failure");
        assert!(!spool_path.exists());
        (error, client)
    }

    fn run_failure(
        fixture: &Fixture,
        transcript: Vec<u8>,
        label: &str,
    ) -> (SnapshotSessionClientError, Vec<u8>) {
        let mut server = Cursor::new(transcript);
        let mut client = Vec::new();
        let (mut descriptor, mut archive) = fixture.source_handles();
        let spool_path = fixture.spool_path(label);
        let mut spool = CreateOnlyArtifactSpool::create(&spool_path).expect("create-only spool");
        let error = run_snapshot_session(
            &mut server,
            &mut client,
            SnapshotSessionRequest::new(
                &fixture.start,
                &mut descriptor,
                &mut archive,
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            |_| {},
            |_, path, _| ProtocolPath::new(ProtocolPathSemantics::ClientAbsolute, path.to_string()),
        )
        .expect_err("session failure");
        assert!(!spool_path.exists(), "failed session retained its spool");
        (error, client)
    }

    fn client_kinds(encoded: &[u8]) -> Vec<WorkerDataPlaneFrameKind> {
        let mut reader = Cursor::new(encoded);
        let mut kinds = Vec::new();
        loop {
            let header = match read_worker_data_plane_header(&mut reader) {
                Ok(header) => header,
                Err(WorkerDataPlaneFrameError::EmptyInput) => break,
                Err(error) => panic!("invalid client transcript: {error}"),
            };
            kinds.push(header.kind());
            if matches!(
                header.kind(),
                WorkerDataPlaneFrameKind::SourceArchive | WorkerDataPlaneFrameKind::Artifact
            ) {
                copy_worker_data_plane_payload(&mut reader, &mut std::io::sink(), header)
                    .expect("raw client payload");
            } else {
                read_worker_data_plane_payload(&mut reader, header).expect("client payload");
            }
        }
        kinds
    }

    fn sha256(bytes: &[u8]) -> String {
        lowercase_hex(&Sha256::digest(bytes))
    }
}
