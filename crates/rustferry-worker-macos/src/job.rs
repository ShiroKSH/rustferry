//! Versioned, bounded orchestration for one isolated physical-iPhone worker job.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_apple::IosDeviceArchiveOutcome;
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactKind, ArtifactManifest, ArtifactRecord,
    ArtifactSigningEvidence, BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION,
    CancellationToken, CleanupConfirmation, CleanupStatus, IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK,
    IosArtifactType, IosDeviceBuildRequest, IosDeviceBuildResult, JobState, RemoteBuildEvent,
    RemoteBuildEventKind, RemoteErrorInfo, SecretBytes, SecretReference, SigningStatus,
    SourceArchive, SourceArchiveLimits, SourceMode, ValidationLevel,
    verify_and_extract_source_bundle, verify_downloaded_file, verify_materialized_bundle,
};
use same_file::Handle;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// Current worker job manifest, state, evidence, and report schema.
pub const WORKER_JOB_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted or emitted worker job manifest JSON.
pub const MAX_WORKER_JOB_MANIFEST_BYTES: usize = 1024 * 1024;

/// Maximum accepted or emitted worker state JSON.
pub const MAX_WORKER_JOB_STATE_BYTES: usize = 512 * 1024;

/// Maximum emitted worker report JSON.
pub const MAX_WORKER_JOB_REPORT_BYTES: usize = 4 * 1024 * 1024;

const MAX_WORKER_PATH_BYTES: usize = 1024;
const MAX_WORKER_PATH_COMPONENT_BYTES: usize = 128;
const MAX_PHASE_TIMINGS: usize = 16;
const MAX_ARTIFACT_CANDIDATES: usize = 32;
const MAX_ARTIFACT_MANIFESTS: usize = 16;
const MAX_ARTIFACT_RECORDS: usize = 64;
const MAX_ARTIFACT_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_PUBLIC_ERROR_CODE_BYTES: usize = 96;
const MAX_PUBLIC_ERROR_MESSAGE_BYTES: usize = 512;

/// Lexically safe path below one isolated worker job root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkerRelativePath(String);

impl WorkerRelativePath {
    /// Construct a normalized ASCII worker-relative path.
    ///
    /// # Errors
    ///
    /// Rejects absolute paths, traversal, empty components, backslashes,
    /// control bytes, oversized values, and non-portable component bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkerJobError> {
        let value = value.into();
        validate_worker_relative_path(&value)?;
        Ok(Self(value))
    }

    /// Derive a worker-relative path from an absolute path already below the job root.
    ///
    /// # Errors
    ///
    /// Rejects paths outside the job root or paths that do not satisfy worker
    /// relative-path rules.
    pub fn from_absolute_under(
        job_root: &Utf8Path,
        absolute: &Utf8Path,
    ) -> Result<Self, WorkerJobError> {
        if !job_root.is_absolute() || !absolute.is_absolute() {
            return Err(WorkerJobError::InvalidWorkerPath);
        }
        let relative = absolute
            .strip_prefix(job_root)
            .map_err(|_| WorkerJobError::InvalidWorkerPath)?;
        Self::new(relative.as_str())
    }

    /// Return the normalized slash-separated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Resolve below a caller-validated absolute job root.
    pub fn resolve(&self, job_root: &Utf8Path) -> Utf8PathBuf {
        job_root.join(&self.0)
    }

    /// Return whether this path is strictly below another worker-relative path.
    pub fn is_descendant_of(&self, parent: &Self) -> bool {
        self.0
            .strip_prefix(parent.as_str())
            .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
    }
}

impl<'de> Deserialize<'de> for WorkerRelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Fixed worker-owned locations for one job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Stable manifest field names distinguish each directory role.
pub struct WorkerJobPaths {
    source_directory: WorkerRelativePath,
    artifacts_directory: WorkerRelativePath,
    temporary_directory: WorkerRelativePath,
    logs_directory: WorkerRelativePath,
}

impl WorkerJobPaths {
    /// Construct four non-overlapping job directories.
    ///
    /// # Errors
    ///
    /// Rejects equal paths and ancestor/descendant overlap.
    pub fn new(
        source_directory: WorkerRelativePath,
        artifacts_directory: WorkerRelativePath,
        temporary_directory: WorkerRelativePath,
        logs_directory: WorkerRelativePath,
    ) -> Result<Self, WorkerJobError> {
        let values = [
            &source_directory,
            &artifacts_directory,
            &temporary_directory,
            &logs_directory,
        ];
        for (index, left) in values.iter().enumerate() {
            for right in values.iter().skip(index + 1) {
                if paths_overlap(left, right) {
                    return Err(WorkerJobError::OverlappingWorkerPaths);
                }
            }
        }
        Ok(Self {
            source_directory,
            artifacts_directory,
            temporary_directory,
            logs_directory,
        })
    }

    /// Extracted or checked-out source root.
    pub fn source_directory(&self) -> &WorkerRelativePath {
        &self.source_directory
    }

    /// Final transport-artifact directory.
    pub fn artifacts_directory(&self) -> &WorkerRelativePath {
        &self.artifacts_directory
    }

    /// Private signing and transient-work directory.
    pub fn temporary_directory(&self) -> &WorkerRelativePath {
        &self.temporary_directory
    }

    /// Sanitized log directory.
    pub fn logs_directory(&self) -> &WorkerRelativePath {
        &self.logs_directory
    }
}

impl Default for WorkerJobPaths {
    fn default() -> Self {
        Self::new(
            WorkerRelativePath::new("workspace/source").expect("static path is valid"),
            WorkerRelativePath::new("output/artifacts").expect("static path is valid"),
            WorkerRelativePath::new("private/temporary").expect("static path is valid"),
            WorkerRelativePath::new("output/logs").expect("static path is valid"),
        )
        .expect("static job paths do not overlap")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Must mirror the public manifest wire fields during validation.
struct UncheckedWorkerJobPaths {
    source_directory: WorkerRelativePath,
    artifacts_directory: WorkerRelativePath,
    temporary_directory: WorkerRelativePath,
    logs_directory: WorkerRelativePath,
}

impl<'de> Deserialize<'de> for WorkerJobPaths {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedWorkerJobPaths::deserialize(deserializer)?;
        Self::new(
            unchecked.source_directory,
            unchecked.artifacts_directory,
            unchecked.temporary_directory,
            unchecked.logs_directory,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Immutable source transport accepted by a worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WorkerSourceInput {
    /// Separately described deterministic source ZIP.
    Snapshot {
        /// Worker-relative uploaded ZIP path.
        archive_path: WorkerRelativePath,
        /// Exact archive hash and byte size.
        archive: SourceArchive,
    },
    /// Exact repository and revision from the remote request.
    Git,
}

impl WorkerSourceInput {
    /// Construct a bounded snapshot source descriptor.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or malformed archive descriptors.
    pub fn snapshot(
        archive_path: WorkerRelativePath,
        archive: SourceArchive,
    ) -> Result<Self, WorkerJobError> {
        validate_source_archive(&archive)?;
        Ok(Self::Snapshot {
            archive_path,
            archive,
        })
    }

    /// Construct an exact-revision Git source descriptor.
    pub const fn git() -> Self {
        Self::Git
    }

    /// Snapshot archive descriptor when snapshot mode is selected.
    pub fn archive(&self) -> Option<&SourceArchive> {
        match self {
            Self::Snapshot { archive, .. } => Some(archive),
            Self::Git => None,
        }
    }

    /// Snapshot archive path when snapshot mode is selected.
    pub fn archive_path(&self) -> Option<&WorkerRelativePath> {
        match self {
            Self::Snapshot { archive_path, .. } => Some(archive_path),
            Self::Git => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum UncheckedWorkerSourceInput {
    Snapshot {
        archive_path: WorkerRelativePath,
        archive: SourceArchive,
    },
    Git,
}

impl<'de> Deserialize<'de> for WorkerSourceInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match UncheckedWorkerSourceInput::deserialize(deserializer)? {
            UncheckedWorkerSourceInput::Snapshot {
                archive_path,
                archive,
            } => Self::snapshot(archive_path, archive).map_err(serde::de::Error::custom),
            UncheckedWorkerSourceInput::Git => Ok(Self::git()),
        }
    }
}

/// Artifact-retention policy; source and signing material are always removed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCleanupPolicy {
    retain_artifacts_on_success: bool,
    retain_artifacts_on_failure: bool,
}

impl WorkerCleanupPolicy {
    /// Construct an explicit artifact-retention policy.
    pub const fn new(retain_artifacts_on_success: bool, retain_artifacts_on_failure: bool) -> Self {
        Self {
            retain_artifacts_on_success,
            retain_artifacts_on_failure,
        }
    }

    /// Whether successful artifacts remain provider-owned after cleanup.
    pub const fn retain_artifacts_on_success(self) -> bool {
        self.retain_artifacts_on_success
    }

    /// Whether partial artifacts remain after failure or cancellation.
    pub const fn retain_artifacts_on_failure(self) -> bool {
        self.retain_artifacts_on_failure
    }

    const fn retain_for(self, state: JobState) -> bool {
        if matches!(state, JobState::Succeeded) {
            self.retain_artifacts_on_success
        } else {
            self.retain_artifacts_on_failure
        }
    }
}

impl Default for WorkerCleanupPolicy {
    fn default() -> Self {
        Self::new(true, false)
    }
}

/// Validated, immutable worker job manifest.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJobManifest {
    schema_version: u32,
    job_id: String,
    worker_id: String,
    provider: String,
    request: IosDeviceBuildRequest,
    source_input: WorkerSourceInput,
    paths: WorkerJobPaths,
    cleanup_policy: WorkerCleanupPolicy,
}

impl WorkerJobManifest {
    /// Bind one validated remote request to one isolated worker job.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identifiers, invalid requests, source-mode mismatches,
    /// archive/path overlap, and unsupported schema invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        worker_id: impl Into<String>,
        provider: impl Into<String>,
        request: IosDeviceBuildRequest,
        source_input: WorkerSourceInput,
        paths: WorkerJobPaths,
        cleanup_policy: WorkerCleanupPolicy,
    ) -> Result<Self, WorkerJobError> {
        let manifest = Self {
            schema_version: WORKER_JOB_SCHEMA_VERSION,
            job_id: job_id.into(),
            worker_id: worker_id.into(),
            provider: provider.into(),
            request,
            source_input,
            paths,
            cleanup_policy,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Stable worker schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Provider-owned job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Non-secret worker identifier.
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Provider identifier used in remote events.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Immutable remote build request.
    pub fn request(&self) -> &IosDeviceBuildRequest {
        &self.request
    }

    /// Immutable source input descriptor.
    pub fn source_input(&self) -> &WorkerSourceInput {
        &self.source_input
    }

    /// Worker-owned relative paths.
    pub fn paths(&self) -> &WorkerJobPaths {
        &self.paths
    }

    /// Cleanup and artifact-retention policy.
    pub const fn cleanup_policy(&self) -> WorkerCleanupPolicy {
        self.cleanup_policy
    }

    /// Canonical SHA-256 of the immutable remote request JSON.
    ///
    /// # Errors
    ///
    /// Returns a fixed serialization error when the request cannot be encoded
    /// within the worker manifest limit.
    pub fn request_sha256(&self) -> Result<String, WorkerJobError> {
        let bytes = serde_json::to_vec(&self.request).map_err(|_| WorkerJobError::Serialization)?;
        if bytes.len() > MAX_WORKER_JOB_MANIFEST_BYTES {
            return Err(WorkerJobError::ManifestTooLarge);
        }
        Ok(sha256_hex(&bytes))
    }

    /// Encode bounded JSON for persistence or provider transport.
    ///
    /// # Errors
    ///
    /// Rejects invalid in-memory values and output beyond the fixed limit.
    pub fn encode_json(&self) -> Result<Vec<u8>, WorkerJobError> {
        self.validate()?;
        encode_bounded_json(self, MAX_WORKER_JOB_MANIFEST_BYTES).map_err(|error| match error {
            BoundedJsonError::TooLarge => WorkerJobError::ManifestTooLarge,
            BoundedJsonError::Serialization => WorkerJobError::Serialization,
        })
    }

    fn validate(&self) -> Result<(), WorkerJobError> {
        if self.schema_version != WORKER_JOB_SCHEMA_VERSION {
            return Err(WorkerJobError::UnsupportedSchema);
        }
        for identifier in [&self.job_id, &self.worker_id, &self.provider] {
            validate_identifier(identifier)?;
        }
        self.request
            .validate()
            .map_err(|_| WorkerJobError::InvalidRequest)?;
        match (&self.request.source_mode, &self.source_input) {
            (
                SourceMode::Snapshot,
                WorkerSourceInput::Snapshot {
                    archive_path,
                    archive,
                },
            ) => {
                validate_source_archive(archive)?;
                if [
                    self.paths.source_directory(),
                    self.paths.artifacts_directory(),
                    self.paths.temporary_directory(),
                    self.paths.logs_directory(),
                ]
                .iter()
                .any(|directory| paths_overlap(archive_path, directory))
                {
                    return Err(WorkerJobError::OverlappingWorkerPaths);
                }
            }
            (SourceMode::Git, WorkerSourceInput::Git) => {}
            _ => return Err(WorkerJobError::SourceModeMismatch),
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWorkerJobManifest {
    schema_version: u32,
    job_id: String,
    worker_id: String,
    provider: String,
    request: IosDeviceBuildRequest,
    source_input: WorkerSourceInput,
    paths: WorkerJobPaths,
    cleanup_policy: WorkerCleanupPolicy,
}

impl<'de> Deserialize<'de> for WorkerJobManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedWorkerJobManifest::deserialize(deserializer)?;
        if unchecked.schema_version != WORKER_JOB_SCHEMA_VERSION {
            return Err(serde::de::Error::custom("unsupported worker job schema"));
        }
        Self::new(
            unchecked.job_id,
            unchecked.worker_id,
            unchecked.provider,
            unchecked.request,
            unchecked.source_input,
            unchecked.paths,
            unchecked.cleanup_policy,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Decode one bounded, fully validated worker job manifest.
///
/// # Errors
///
/// Rejects empty/oversized JSON, unknown fields, malformed values, and any
/// manifest invariant violation without returning parser-controlled text.
pub fn decode_worker_job_manifest(bytes: &[u8]) -> Result<WorkerJobManifest, WorkerJobError> {
    if bytes.is_empty() || bytes.len() > MAX_WORKER_JOB_MANIFEST_BYTES {
        return Err(WorkerJobError::ManifestTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| WorkerJobError::MalformedManifest)
}

/// Stable worker execution phases.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerJobPhase {
    /// Manifest accepted, no source material accessed.
    Accepted,
    /// Source hash, size, shape, and materialized contents are being verified.
    SourceVerification,
    /// Unsigned physical-iPhone compilation and archive.
    Build,
    /// Profile, certificate, entitlements, and code signing.
    Sign,
    /// IPA or other transport output export.
    Export,
    /// Independent output validation and hash binding.
    Validate,
    /// Mandatory source and signing-material cleanup.
    Cleanup,
    /// No further job work remains.
    Complete,
}

impl WorkerJobPhase {
    const fn event_id(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::SourceVerification => "source",
            Self::Build => "build",
            Self::Sign => "sign",
            Self::Export => "export",
            Self::Validate => "validate",
            Self::Cleanup => "cleanup",
            Self::Complete => "complete",
        }
    }

    const fn safe_message(self) -> &'static str {
        match self {
            Self::Accepted => "Worker job accepted",
            Self::SourceVerification => "Verifying exact source",
            Self::Build => "Building physical iPhone archive",
            Self::Sign => "Applying development signing",
            Self::Export => "Exporting requested artifacts",
            Self::Validate => "Independently validating artifacts",
            Self::Cleanup => "Removing source and signing material",
            Self::Complete => "Worker job complete",
        }
    }
}

/// Monotonic timing evidence for one completed phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPhaseTiming {
    /// Completed phase.
    pub phase: WorkerJobPhase,
    /// Monotonic offset from job start.
    pub started_after_ms: u64,
    /// Monotonic phase duration.
    pub duration_ms: u64,
}

/// Safe failure copied into persisted state and public reports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPublicFailure {
    /// Stable machine-readable code.
    pub code: String,
    /// Fixed, sanitized summary.
    pub message: String,
    /// Whether an unchanged request may succeed on retry.
    pub retryable: bool,
}

impl WorkerPublicFailure {
    fn validate(&self) -> Result<(), WorkerJobError> {
        validate_public_error_code(&self.code)?;
        validate_public_message(&self.message)
    }
}

/// Versioned persisted state for one job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJobState {
    schema_version: u32,
    job_id: String,
    request_sha256: String,
    state: JobState,
    phase: WorkerJobPhase,
    sequence: u64,
    started_at_ms: u64,
    updated_at_ms: u64,
    source_sha256: Option<String>,
    timings: Vec<WorkerPhaseTiming>,
    failure: Option<WorkerPublicFailure>,
}

impl WorkerJobState {
    /// Provider job state.
    pub const fn state(&self) -> JobState {
        self.state
    }

    /// Current worker phase.
    pub const fn phase(&self) -> WorkerJobPhase {
        self.phase
    }

    /// Last emitted remote event sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Immutable request digest.
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    /// Verified source-manifest digest, once known.
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    /// Completed phase timings.
    pub fn timings(&self) -> &[WorkerPhaseTiming] {
        &self.timings
    }

    /// Sanitized failure, if any.
    pub fn failure(&self) -> Option<&WorkerPublicFailure> {
        self.failure.as_ref()
    }

    /// Encode bounded state JSON.
    ///
    /// # Errors
    ///
    /// Rejects invalid state or output beyond the fixed state limit.
    pub fn encode_json(&self) -> Result<Vec<u8>, WorkerJobError> {
        self.validate()?;
        encode_bounded_json(self, MAX_WORKER_JOB_STATE_BYTES).map_err(|error| match error {
            BoundedJsonError::TooLarge => WorkerJobError::StateTooLarge,
            BoundedJsonError::Serialization => WorkerJobError::Serialization,
        })
    }

    fn validate(&self) -> Result<(), WorkerJobError> {
        if self.schema_version != WORKER_JOB_SCHEMA_VERSION {
            return Err(WorkerJobError::UnsupportedSchema);
        }
        validate_identifier(&self.job_id)?;
        validate_sha256(&self.request_sha256)?;
        if let Some(source) = &self.source_sha256 {
            validate_sha256(source)?;
        }
        if self.updated_at_ms < self.started_at_ms || self.timings.len() > MAX_PHASE_TIMINGS {
            return Err(WorkerJobError::InvalidState);
        }
        let mut phases = BTreeSet::new();
        for timing in &self.timings {
            if !phases.insert(timing.phase) {
                return Err(WorkerJobError::InvalidState);
            }
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWorkerJobState {
    schema_version: u32,
    job_id: String,
    request_sha256: String,
    state: JobState,
    phase: WorkerJobPhase,
    sequence: u64,
    started_at_ms: u64,
    updated_at_ms: u64,
    source_sha256: Option<String>,
    timings: Vec<WorkerPhaseTiming>,
    failure: Option<WorkerPublicFailure>,
}

impl<'de> Deserialize<'de> for WorkerJobState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedWorkerJobState::deserialize(deserializer)?;
        let state = Self {
            schema_version: unchecked.schema_version,
            job_id: unchecked.job_id,
            request_sha256: unchecked.request_sha256,
            state: unchecked.state,
            phase: unchecked.phase,
            sequence: unchecked.sequence,
            started_at_ms: unchecked.started_at_ms,
            updated_at_ms: unchecked.updated_at_ms,
            source_sha256: unchecked.source_sha256,
            timings: unchecked.timings,
            failure: unchecked.failure,
        };
        state.validate().map_err(serde::de::Error::custom)?;
        Ok(state)
    }
}

/// Decode one bounded, validated worker state snapshot.
///
/// # Errors
///
/// Rejects oversized, malformed, unknown-field, or internally inconsistent state.
pub fn decode_worker_job_state(bytes: &[u8]) -> Result<WorkerJobState, WorkerJobError> {
    if bytes.is_empty() || bytes.len() > MAX_WORKER_JOB_STATE_BYTES {
        return Err(WorkerJobError::StateTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| WorkerJobError::MalformedState)
}

/// Sanitized build evidence returned by a build hook.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBuildEvidence {
    /// Rust physical-device target.
    pub rust_target: String,
    /// Xcode physical-device SDK.
    pub sdk: String,
    /// Physical-device Mach-O evidence was present.
    pub device_binary_proven: bool,
    /// Full unsigned archive inspection was present.
    pub archive_inspected: bool,
}

/// Safe paths plus public evidence returned by a build hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerBuildOutput {
    archive_path: WorkerRelativePath,
    app_path: WorkerRelativePath,
    evidence: WorkerBuildEvidence,
}

impl WorkerBuildOutput {
    /// Construct a physical-device build result from worker-relative paths.
    ///
    /// # Errors
    ///
    /// Requires the exact physical-iOS Rust target and SDK, distinct output
    /// paths, device Mach-O proof, and archive inspection.
    pub fn new(
        archive_path: WorkerRelativePath,
        app_path: WorkerRelativePath,
        evidence: WorkerBuildEvidence,
    ) -> Result<Self, WorkerJobError> {
        if archive_path == app_path
            || evidence.rust_target != IOS_DEVICE_RUST_TARGET
            || evidence.sdk != IOS_DEVICE_SDK
            || !evidence.device_binary_proven
            || !evidence.archive_inspected
        {
            return Err(WorkerJobError::InvalidBuildOutput);
        }
        Ok(Self {
            archive_path,
            app_path,
            evidence,
        })
    }

    /// Convert a concrete rustferry-apple unsigned archive outcome.
    ///
    /// # Errors
    ///
    /// Rejects dry-run or incomplete outcomes and paths outside the job root.
    pub fn from_apple_outcome(
        job_root: &Utf8Path,
        outcome: &IosDeviceArchiveOutcome,
    ) -> Result<Self, WorkerJobError> {
        let archive = outcome
            .archive
            .as_deref()
            .ok_or(WorkerJobError::InvalidBuildOutput)?;
        let app = outcome
            .app
            .as_deref()
            .ok_or(WorkerJobError::InvalidBuildOutput)?;
        Self::new(
            WorkerRelativePath::from_absolute_under(job_root, archive)?,
            WorkerRelativePath::from_absolute_under(job_root, app)?,
            WorkerBuildEvidence {
                rust_target: outcome.plan.rust_target.clone(),
                sdk: outcome.plan.sdk.clone(),
                device_binary_proven: outcome.macho_validation.is_some(),
                archive_inspected: outcome.archive_inspection.is_some(),
            },
        )
    }

    /// Unsigned archive path below the job root.
    pub fn archive_path(&self) -> &WorkerRelativePath {
        &self.archive_path
    }

    /// Unsigned application path below the job root.
    pub fn app_path(&self) -> &WorkerRelativePath {
        &self.app_path
    }

    /// Public device-build evidence.
    pub fn evidence(&self) -> &WorkerBuildEvidence {
        &self.evidence
    }
}

/// Public output from a signing hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSignOutput {
    signed_archive_path: WorkerRelativePath,
    signing: ArtifactSigningEvidence,
}

impl WorkerSignOutput {
    /// Construct redacted signing output.
    ///
    /// # Errors
    ///
    /// Requires at least application-signature evidence and no secret values.
    pub fn new(
        signed_archive_path: WorkerRelativePath,
        signing: ArtifactSigningEvidence,
    ) -> Result<Self, WorkerJobError> {
        if !matches!(
            signing.status,
            SigningStatus::ApplicationSigned
                | SigningStatus::IpaExported
                | SigningStatus::ArtifactValidated
        ) {
            return Err(WorkerJobError::InvalidSigningOutput);
        }
        Ok(Self {
            signed_archive_path,
            signing,
        })
    }

    /// Signed archive below the job root.
    pub fn signed_archive_path(&self) -> &WorkerRelativePath {
        &self.signed_archive_path
    }

    /// Public signing evidence.
    pub fn signing(&self) -> &ArtifactSigningEvidence {
        &self.signing
    }
}

/// One exported candidate awaiting independent validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerArtifactCandidate {
    artifact_id: String,
    artifact_type: IosArtifactType,
    path: WorkerRelativePath,
}

impl WorkerArtifactCandidate {
    /// Construct one safely identified candidate.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identifiers.
    pub fn new(
        artifact_id: impl Into<String>,
        artifact_type: IosArtifactType,
        path: WorkerRelativePath,
    ) -> Result<Self, WorkerJobError> {
        let artifact_id = artifact_id.into();
        validate_identifier(&artifact_id)?;
        Ok(Self {
            artifact_id,
            artifact_type,
            path,
        })
    }

    /// Immutable artifact identifier.
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Requested protocol artifact type.
    pub const fn artifact_type(&self) -> IosArtifactType {
        self.artifact_type
    }

    /// Worker-relative candidate path.
    pub fn path(&self) -> &WorkerRelativePath {
        &self.path
    }
}

/// Bounded export-hook output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerExportOutput {
    candidates: Vec<WorkerArtifactCandidate>,
}

impl WorkerExportOutput {
    /// Construct a deterministic candidate set.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, duplicate-ID, duplicate-type, or unsorted sets.
    pub fn new(candidates: Vec<WorkerArtifactCandidate>) -> Result<Self, WorkerJobError> {
        if candidates.is_empty() || candidates.len() > MAX_ARTIFACT_CANDIDATES {
            return Err(WorkerJobError::InvalidExportOutput);
        }
        let mut identifiers = BTreeSet::new();
        let mut types = BTreeSet::new();
        let mut previous = None;
        for candidate in &candidates {
            if !identifiers.insert(candidate.artifact_id())
                || !types.insert(candidate.artifact_type())
                || previous.is_some_and(|value: &str| value >= candidate.artifact_id())
            {
                return Err(WorkerJobError::InvalidExportOutput);
            }
            previous = Some(candidate.artifact_id());
        }
        Ok(Self { candidates })
    }

    /// Ordered exported candidates.
    pub fn candidates(&self) -> &[WorkerArtifactCandidate] {
        &self.candidates
    }
}

/// Independently validated artifact manifests from the validation hook.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkerValidationOutput {
    manifests: Vec<ArtifactManifest>,
}

impl WorkerValidationOutput {
    /// Construct a bounded manifest collection.
    ///
    /// Cross-object identity and artifact-byte checks run in the job engine.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized collections.
    pub fn new(manifests: Vec<ArtifactManifest>) -> Result<Self, WorkerJobError> {
        if manifests.is_empty() || manifests.len() > MAX_ARTIFACT_MANIFESTS {
            return Err(WorkerJobError::InvalidArtifactEvidence);
        }
        Ok(Self { manifests })
    }

    /// Independently validated artifact manifests.
    pub fn manifests(&self) -> &[ArtifactManifest] {
        &self.manifests
    }
}

/// Fixed, secret-free failure returned by a trusted worker hook or event sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerHookFailure {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl WorkerHookFailure {
    /// Construct a hook failure from compile-time text.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or oversized code/message text. Runtime command output,
    /// paths, environment values, and secret values must never be supplied.
    pub fn new(
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Result<Self, WorkerJobError> {
        validate_public_error_code(code)?;
        validate_public_message(message)?;
        Ok(Self {
            code,
            message,
            retryable,
        })
    }

    /// Stable machine-readable failure code.
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Fixed sanitized message.
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Whether an unchanged request may succeed on retry.
    pub const fn retryable(self) -> bool {
        self.retryable
    }
}

impl fmt::Display for WorkerHookFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for WorkerHookFailure {}

/// Explicit secret-reference resolver supplied by the trusted worker host.
///
/// No implementation is provided that reads process environment variables.
/// Secret bytes remain non-cloneable, non-debuggable, and non-serializable.
pub trait WorkerSecretResolver {
    /// Resolve one validated opaque reference at the narrow signing boundary.
    ///
    /// # Errors
    ///
    /// Returns a fixed secret-free hook failure.
    fn resolve(&mut self, reference: &SecretReference) -> Result<SecretBytes, WorkerHookFailure>;
}

/// Resolver that rejects every secret reference.
#[derive(Default)]
pub struct RejectingSecretResolver;

impl WorkerSecretResolver for RejectingSecretResolver {
    fn resolve(&mut self, _reference: &SecretReference) -> Result<SecretBytes, WorkerHookFailure> {
        Err(static_hook_failure(
            "secret.unavailable",
            "Requested signing material is unavailable",
            false,
        ))
    }
}

/// Sink for already-sanitized, validated remote events.
pub trait WorkerEventSink {
    /// Persist or forward one event.
    ///
    /// # Errors
    ///
    /// Returns a fixed secret-free failure. The sink must not rewrite events.
    fn emit(&mut self, event: &RemoteBuildEvent) -> Result<(), WorkerHookFailure>;
}

/// In-memory event sink useful for local adapters and tests.
#[derive(Default)]
pub struct MemoryEventSink {
    events: Vec<RemoteBuildEvent>,
}

impl MemoryEventSink {
    /// Borrow all accepted events in sequence order.
    pub fn events(&self) -> &[RemoteBuildEvent] {
        &self.events
    }
}

impl WorkerEventSink for MemoryEventSink {
    fn emit(&mut self, event: &RemoteBuildEvent) -> Result<(), WorkerHookFailure> {
        self.events.push(event.clone());
        Ok(())
    }
}

/// Wall and monotonic clocks used for event and duration evidence.
pub trait WorkerClock {
    /// Current Unix epoch milliseconds for protocol timestamps.
    fn unix_time_ms(&mut self) -> u64;

    /// Monotonic milliseconds from a clock-specific origin.
    fn monotonic_time_ms(&mut self) -> u64;
}

/// Cross-platform system clock.
pub struct SystemWorkerClock {
    monotonic_origin: Instant,
}

impl Default for SystemWorkerClock {
    fn default() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl WorkerClock for SystemWorkerClock {
    fn unix_time_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn monotonic_time_ms(&mut self) -> u64 {
        u64::try_from(self.monotonic_origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Read-only job context exposed to build, sign, export, and validation hooks.
pub struct WorkerHookContext<'a> {
    job_id: &'a str,
    worker_id: &'a str,
    provider: &'a str,
    job_root: &'a Utf8Path,
    source_directory: &'a Utf8Path,
    project_directory: &'a Utf8Path,
    artifacts_directory: &'a Utf8Path,
    temporary_directory: &'a Utf8Path,
    logs_directory: &'a Utf8Path,
    request: &'a IosDeviceBuildRequest,
    cancellation: &'a CancellationToken,
}

impl WorkerHookContext<'_> {
    /// Stable provider-owned job identifier.
    pub fn job_id(&self) -> &str {
        self.job_id
    }

    /// Stable non-secret worker identifier.
    pub fn worker_id(&self) -> &str {
        self.worker_id
    }

    /// Provider identifier copied into public evidence.
    pub fn provider(&self) -> &str {
        self.provider
    }

    /// Canonical isolated job root.
    pub fn job_root(&self) -> &Utf8Path {
        self.job_root
    }

    /// Verified source root.
    pub fn source_directory(&self) -> &Utf8Path {
        self.source_directory
    }

    /// Verified `RustFerry` project root.
    pub fn project_directory(&self) -> &Utf8Path {
        self.project_directory
    }

    /// Worker-owned artifact publication directory.
    pub fn artifacts_directory(&self) -> &Utf8Path {
        self.artifacts_directory
    }

    /// Private transient/signing directory.
    pub fn temporary_directory(&self) -> &Utf8Path {
        self.temporary_directory
    }

    /// Sanitized log directory.
    pub fn logs_directory(&self) -> &Utf8Path {
        self.logs_directory
    }

    /// Immutable remote request and source revision.
    pub fn request(&self) -> &IosDeviceBuildRequest {
        self.request
    }

    /// Cooperative cancellation token for bounded checks inside long hooks.
    pub fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
}

/// Mandatory cleanup request supplied after every started job.
pub struct WorkerCleanupRequest<'a> {
    /// Stable provider-owned job identifier copied into cleanup proof.
    pub job_id: &'a str,
    /// Canonical isolated job root.
    pub job_root: &'a Utf8Path,
    /// Fixed worker-owned paths.
    pub paths: &'a WorkerJobPaths,
    /// Immutable source input, including uploaded snapshot path when present.
    pub source_input: &'a WorkerSourceInput,
    /// Build-terminal state before cleanup.
    pub build_state: JobState,
    /// Whether final artifact bytes must be removed.
    pub remove_artifacts: bool,
}

/// Trusted side-effect hooks used by the runtime-neutral job engine.
///
/// Hook failures carry fixed public text only. Build/sign/export outputs carry
/// worker-relative paths and public evidence only.
pub trait WorkerJobHooks {
    /// Materialize one normalized GitHub repository at the exact requested revision.
    ///
    /// The engine verifies the complete materialized tree against the immutable
    /// source manifest immediately afterward.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if checkout or materialization fails.
    fn materialize_git_source(
        &mut self,
        context: &WorkerHookContext<'_>,
        repository: &str,
        revision: &str,
        destination: &Utf8Path,
    ) -> Result<(), WorkerHookFailure>;

    /// Build and independently inspect an unsigned physical-iPhone archive.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if build or inspection fails.
    fn build(
        &mut self,
        context: &WorkerHookContext<'_>,
    ) -> Result<WorkerBuildOutput, WorkerHookFailure>;

    /// Apply profiles, entitlements, and development signing.
    ///
    /// Environment-backed and provider-backed secret values are available only
    /// through the explicit resolver argument.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if signing fails.
    fn sign(
        &mut self,
        context: &WorkerHookContext<'_>,
        build: &WorkerBuildOutput,
        secrets: &mut dyn WorkerSecretResolver,
    ) -> Result<WorkerSignOutput, WorkerHookFailure>;

    /// Export exactly the requested transport artifacts.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if export fails.
    fn export(
        &mut self,
        context: &WorkerHookContext<'_>,
        build: &WorkerBuildOutput,
        signing: Option<&WorkerSignOutput>,
    ) -> Result<WorkerExportOutput, WorkerHookFailure>;

    /// Independently validate candidate bytes and construct public manifests.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if validation fails.
    fn validate(
        &mut self,
        context: &WorkerHookContext<'_>,
        build: &WorkerBuildOutput,
        signing: Option<&WorkerSignOutput>,
        export: &WorkerExportOutput,
    ) -> Result<WorkerValidationOutput, WorkerHookFailure>;

    /// Remove source, signing material, temporary keychains, and policy-selected artifacts.
    ///
    /// # Errors
    ///
    /// Returns a fixed public hook failure if mandatory cleanup cannot be proven.
    fn cleanup(
        &mut self,
        request: WorkerCleanupRequest<'_>,
    ) -> Result<CleanupConfirmation, WorkerHookFailure>;
}

/// Cross-platform fallback that performs no build or signing side effects.
#[derive(Default)]
pub struct UnsupportedWorkerJobHooks;

impl WorkerJobHooks for UnsupportedWorkerJobHooks {
    fn materialize_git_source(
        &mut self,
        _context: &WorkerHookContext<'_>,
        _repository: &str,
        _revision: &str,
        _destination: &Utf8Path,
    ) -> Result<(), WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }

    fn build(
        &mut self,
        _context: &WorkerHookContext<'_>,
    ) -> Result<WorkerBuildOutput, WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }

    fn sign(
        &mut self,
        _context: &WorkerHookContext<'_>,
        _build: &WorkerBuildOutput,
        _secrets: &mut dyn WorkerSecretResolver,
    ) -> Result<WorkerSignOutput, WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }

    fn export(
        &mut self,
        _context: &WorkerHookContext<'_>,
        _build: &WorkerBuildOutput,
        _signing: Option<&WorkerSignOutput>,
    ) -> Result<WorkerExportOutput, WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }

    fn validate(
        &mut self,
        _context: &WorkerHookContext<'_>,
        _build: &WorkerBuildOutput,
        _signing: Option<&WorkerSignOutput>,
        _export: &WorkerExportOutput,
    ) -> Result<WorkerValidationOutput, WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }

    fn cleanup(
        &mut self,
        _request: WorkerCleanupRequest<'_>,
    ) -> Result<CleanupConfirmation, WorkerHookFailure> {
        Err(unsupported_platform_failure())
    }
}

/// Overall job outcome after mandatory cleanup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerJobOutcome {
    /// Build, validation, and required cleanup succeeded.
    Succeeded,
    /// Build or validation failed; required cleanup succeeded.
    Failed,
    /// Cancellation was observed; required cleanup succeeded.
    Cancelled,
    /// Cleanup could not be independently confirmed.
    CleanupFailed,
}

/// Redacted public evidence from one worker execution.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJobEvidence {
    /// SHA-256 of the immutable remote request.
    pub request_sha256: String,
    /// Verified source-manifest digest.
    pub source_manifest_sha256: String,
    /// Verified snapshot archive descriptor when snapshot mode was used.
    pub source_archive: Option<SourceArchive>,
    /// Device build evidence when build completed.
    pub build: Option<WorkerBuildEvidence>,
    /// Public signing evidence when signing completed.
    pub signing: Option<ArtifactSigningEvidence>,
    /// Monotonic completed-phase timings.
    pub timings: Vec<WorkerPhaseTiming>,
    /// Cleanup proof when cleanup completed.
    pub cleanup: Option<CleanupConfirmation>,
}

/// Versioned redacted worker report.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJobReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Overall job and cleanup outcome.
    pub outcome: WorkerJobOutcome,
    /// Remote protocol result.
    pub result: IosDeviceBuildResult,
    /// Public execution evidence.
    pub evidence: WorkerJobEvidence,
    /// Fixed public failure when outcome is not success.
    pub failure: Option<WorkerPublicFailure>,
    /// Final persisted state snapshot.
    pub state: WorkerJobState,
}

impl WorkerJobReport {
    /// Encode bounded redacted report JSON.
    ///
    /// # Errors
    ///
    /// Rejects reports beyond the fixed output limit.
    pub fn encode_json(&self) -> Result<Vec<u8>, WorkerJobError> {
        encode_bounded_json(self, MAX_WORKER_JOB_REPORT_BYTES).map_err(|error| match error {
            BoundedJsonError::TooLarge => WorkerJobError::ReportTooLarge,
            BoundedJsonError::Serialization => WorkerJobError::Serialization,
        })
    }
}

/// Typed secret-free job-engine failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerJobError {
    /// Manifest JSON is empty or oversized.
    ManifestTooLarge,
    /// Manifest JSON is malformed or invalid.
    MalformedManifest,
    /// State JSON is empty or oversized.
    StateTooLarge,
    /// State JSON is malformed or invalid.
    MalformedState,
    /// Report JSON exceeded the public output bound.
    ReportTooLarge,
    /// Worker schema version is unsupported.
    UnsupportedSchema,
    /// A job or worker identifier is unsafe.
    InvalidIdentifier,
    /// A worker-relative path is unsafe.
    InvalidWorkerPath,
    /// Worker-owned paths overlap.
    OverlappingWorkerPaths,
    /// Remote request is invalid.
    InvalidRequest,
    /// Request source mode and worker input differ.
    SourceModeMismatch,
    /// Snapshot archive descriptor is invalid.
    InvalidSourceArchive,
    /// JSON serialization failed.
    Serialization,
    /// Persisted state is inconsistent.
    InvalidState,
    /// Job root is absent, unsafe, or not a directory.
    InvalidJobRoot,
    /// Job root identity changed while work was running.
    JobRootChanged,
    /// A fixed worker directory is unsafe.
    InvalidWorkerDirectory,
    /// Source verification or extraction failed.
    SourceVerificationFailed,
    /// Source project directory is unsafe.
    InvalidProjectDirectory,
    /// Cancellation was observed at a worker checkpoint.
    Cancelled,
    /// A remote event could not be constructed.
    InvalidEvent,
    /// Event sink rejected a sanitized event.
    EventSink {
        /// Fixed sink failure.
        failure: WorkerHookFailure,
    },
    /// Monotonic clock moved backward.
    ClockRegressed,
    /// Remote state transition was invalid.
    InvalidStateTransition,
    /// Build hook returned incomplete or non-device evidence.
    InvalidBuildOutput,
    /// Signing hook returned incomplete evidence.
    InvalidSigningOutput,
    /// Export hook returned an unsafe or inconsistent set.
    InvalidExportOutput,
    /// Artifact evidence, identity, bytes, or requested set was invalid.
    InvalidArtifactEvidence,
    /// Cleanup proof was absent or inconsistent.
    InvalidCleanupProof,
    /// A trusted hook failed with fixed public text.
    Hook {
        /// Phase that invoked the hook.
        phase: WorkerJobPhase,
        /// Fixed hook failure.
        failure: WorkerHookFailure,
    },
}

impl WorkerJobError {
    /// Stable public error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ManifestTooLarge => "worker.manifest_size",
            Self::MalformedManifest => "worker.manifest_invalid",
            Self::StateTooLarge => "worker.state_size",
            Self::MalformedState => "worker.state_invalid",
            Self::ReportTooLarge => "worker.report_size",
            Self::UnsupportedSchema => "worker.schema_unsupported",
            Self::InvalidIdentifier => "worker.identifier_invalid",
            Self::InvalidWorkerPath => "worker.path_invalid",
            Self::OverlappingWorkerPaths => "worker.path_overlap",
            Self::InvalidRequest => "worker.request_invalid",
            Self::SourceModeMismatch => "worker.source_mode_mismatch",
            Self::InvalidSourceArchive => "worker.source_archive_invalid",
            Self::Serialization => "worker.serialization_failed",
            Self::InvalidState => "worker.state_inconsistent",
            Self::InvalidJobRoot => "worker.root_invalid",
            Self::JobRootChanged => "worker.root_changed",
            Self::InvalidWorkerDirectory => "worker.directory_invalid",
            Self::SourceVerificationFailed => "worker.source_verification_failed",
            Self::InvalidProjectDirectory => "worker.project_directory_invalid",
            Self::Cancelled => "worker.cancelled",
            Self::InvalidEvent => "worker.event_invalid",
            Self::EventSink { .. } => "worker.event_sink_failed",
            Self::ClockRegressed => "worker.clock_regressed",
            Self::InvalidStateTransition => "worker.state_transition_invalid",
            Self::InvalidBuildOutput => "worker.build_output_invalid",
            Self::InvalidSigningOutput => "worker.signing_output_invalid",
            Self::InvalidExportOutput => "worker.export_output_invalid",
            Self::InvalidArtifactEvidence => "worker.artifact_evidence_invalid",
            Self::InvalidCleanupProof => "worker.cleanup_proof_invalid",
            Self::Hook { failure, .. } => failure.code(),
        }
    }

    /// Whether retrying an unchanged request may succeed.
    pub const fn retryable(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::EventSink { failure } | Self::Hook { failure, .. } => failure.retryable(),
            Self::ManifestTooLarge
            | Self::MalformedManifest
            | Self::StateTooLarge
            | Self::MalformedState
            | Self::ReportTooLarge
            | Self::UnsupportedSchema
            | Self::InvalidIdentifier
            | Self::InvalidWorkerPath
            | Self::OverlappingWorkerPaths
            | Self::InvalidRequest
            | Self::SourceModeMismatch
            | Self::InvalidSourceArchive
            | Self::Serialization
            | Self::InvalidState
            | Self::InvalidJobRoot
            | Self::JobRootChanged
            | Self::InvalidWorkerDirectory
            | Self::SourceVerificationFailed
            | Self::InvalidProjectDirectory
            | Self::InvalidEvent
            | Self::ClockRegressed
            | Self::InvalidStateTransition
            | Self::InvalidBuildOutput
            | Self::InvalidSigningOutput
            | Self::InvalidExportOutput
            | Self::InvalidArtifactEvidence
            | Self::InvalidCleanupProof => false,
        }
    }

    fn public_failure(&self) -> WorkerPublicFailure {
        let message = match self {
            Self::Hook { failure, .. } | Self::EventSink { failure } => failure.message(),
            _ => self.safe_message(),
        };
        WorkerPublicFailure {
            code: self.code().to_owned(),
            message: message.to_owned(),
            retryable: self.retryable(),
        }
    }

    const fn safe_message(&self) -> &'static str {
        match self {
            Self::ManifestTooLarge => "Worker job manifest exceeds its limit",
            Self::MalformedManifest => "Worker job manifest is invalid",
            Self::StateTooLarge => "Worker job state exceeds its limit",
            Self::MalformedState => "Worker job state is invalid",
            Self::ReportTooLarge => "Worker job report exceeds its limit",
            Self::UnsupportedSchema => "Worker job schema is unsupported",
            Self::InvalidIdentifier => "Worker identifier is invalid",
            Self::InvalidWorkerPath => "Worker-relative path is invalid",
            Self::OverlappingWorkerPaths => "Worker-owned paths overlap",
            Self::InvalidRequest => "Remote build request is invalid",
            Self::SourceModeMismatch => "Worker source mode does not match the request",
            Self::InvalidSourceArchive => "Source archive descriptor is invalid",
            Self::Serialization => "Worker protocol serialization failed",
            Self::InvalidState => "Persisted worker state is inconsistent",
            Self::InvalidJobRoot => "Isolated worker root is invalid",
            Self::JobRootChanged => "Isolated worker root changed during execution",
            Self::InvalidWorkerDirectory => "Worker-owned directory is invalid",
            Self::SourceVerificationFailed => "Exact source verification failed",
            Self::InvalidProjectDirectory => "Verified project directory is invalid",
            Self::Cancelled => "Worker job was cancelled",
            Self::InvalidEvent => "Worker event is invalid",
            Self::EventSink { .. } => "Worker event sink failed",
            Self::ClockRegressed => "Worker monotonic clock regressed",
            Self::InvalidStateTransition => "Worker state transition is invalid",
            Self::InvalidBuildOutput => "Physical-iPhone build evidence is incomplete",
            Self::InvalidSigningOutput => "Signing evidence is incomplete",
            Self::InvalidExportOutput => "Exported artifact set is invalid",
            Self::InvalidArtifactEvidence => "Artifact validation evidence is invalid",
            Self::InvalidCleanupProof => "Worker cleanup could not be confirmed",
            Self::Hook { failure, .. } => failure.message(),
        }
    }
}

impl fmt::Display for WorkerJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl Error for WorkerJobError {}

/// Execute one validated job with explicit side-effect, secret, event, and clock adapters.
///
/// Source extraction and manifest verification are performed by the engine.
/// Every started job attempts cleanup, including hook failures, cancellation,
/// clock/event failures, and source-verification failures.
///
/// # Errors
///
/// Returns an engine-level error only when the manifest/root cannot safely
/// start, a terminal event cannot be delivered, or the final report cannot be
/// represented. Normal build, signing, validation, cancellation, and cleanup
/// failures are returned as a redacted report.
#[allow(clippy::too_many_arguments)]
pub fn execute_worker_job(
    manifest: WorkerJobManifest,
    job_root: &Utf8Path,
    hooks: &mut dyn WorkerJobHooks,
    secrets: &mut dyn WorkerSecretResolver,
    events: &mut dyn WorkerEventSink,
    clock: &mut dyn WorkerClock,
    cancellation: CancellationToken,
) -> Result<WorkerJobReport, WorkerJobError> {
    manifest.validate()?;
    let root = JobRootBinding::open(job_root)?;
    let mut runner =
        WorkerJobRunner::new(manifest, root, hooks, secrets, events, clock, cancellation)?;
    runner.run()
}

struct WorkerJobRunner<'a> {
    manifest: WorkerJobManifest,
    root: JobRootBinding,
    hooks: &'a mut dyn WorkerJobHooks,
    secrets: &'a mut dyn WorkerSecretResolver,
    events: &'a mut dyn WorkerEventSink,
    clock: &'a mut dyn WorkerClock,
    cancellation: CancellationToken,
    state: WorkerJobState,
    monotonic_start_ms: u64,
    active_phase: Option<(WorkerJobPhase, u64)>,
    source_directory: Utf8PathBuf,
    project_directory: Utf8PathBuf,
    artifacts_directory: Utf8PathBuf,
    temporary_directory: Utf8PathBuf,
    logs_directory: Utf8PathBuf,
    source_archive: Option<SourceArchive>,
    build_evidence: Option<WorkerBuildEvidence>,
    signing_evidence: Option<ArtifactSigningEvidence>,
}

impl<'a> WorkerJobRunner<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        manifest: WorkerJobManifest,
        root: JobRootBinding,
        hooks: &'a mut dyn WorkerJobHooks,
        secrets: &'a mut dyn WorkerSecretResolver,
        events: &'a mut dyn WorkerEventSink,
        clock: &'a mut dyn WorkerClock,
        cancellation: CancellationToken,
    ) -> Result<Self, WorkerJobError> {
        let started_at_ms = clock.unix_time_ms();
        let monotonic_start_ms = clock.monotonic_time_ms();
        let request_sha256 = manifest.request_sha256()?;
        let source_directory = manifest.paths.source_directory.resolve(&root.path);
        let project_directory = if manifest.request.source.project_path == "." {
            source_directory.clone()
        } else {
            source_directory.join(&manifest.request.source.project_path)
        };
        let artifacts_directory = manifest.paths.artifacts_directory.resolve(&root.path);
        let temporary_directory = manifest.paths.temporary_directory.resolve(&root.path);
        let logs_directory = manifest.paths.logs_directory.resolve(&root.path);
        let state = WorkerJobState {
            schema_version: WORKER_JOB_SCHEMA_VERSION,
            job_id: manifest.job_id.clone(),
            request_sha256,
            state: JobState::Created,
            phase: WorkerJobPhase::Accepted,
            sequence: 0,
            started_at_ms,
            updated_at_ms: started_at_ms,
            source_sha256: None,
            timings: Vec::new(),
            failure: None,
        };
        state.validate()?;
        Ok(Self {
            manifest,
            root,
            hooks,
            secrets,
            events,
            clock,
            cancellation,
            state,
            monotonic_start_ms,
            active_phase: None,
            source_directory,
            project_directory,
            artifacts_directory,
            temporary_directory,
            logs_directory,
            source_archive: None,
            build_evidence: None,
            signing_evidence: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn run(&mut self) -> Result<WorkerJobReport, WorkerJobError> {
        let mut pipeline = self.run_pipeline();
        if self.active_phase.is_some()
            && let Err(error) = self.finish_phase()
        {
            pipeline = Err(error);
        }

        let (build_state, mut failure, cancelled, manifests) = match pipeline {
            Ok(manifests) => {
                self.transition(JobState::Succeeded)?;
                (JobState::Succeeded, None, false, manifests)
            }
            Err(WorkerJobError::Cancelled) => {
                self.transition_for_cancellation()?;
                (
                    JobState::Cancelled,
                    None,
                    true,
                    Vec::<ArtifactManifest>::new(),
                )
            }
            Err(error) => {
                self.transition(JobState::Failed)?;
                (
                    JobState::Failed,
                    Some(error.public_failure()),
                    false,
                    Vec::<ArtifactManifest>::new(),
                )
            }
        };

        let cleanup = self.run_cleanup(build_state);
        let cleanup_confirmation = cleanup.confirmation;
        if let Some(error) = cleanup.error {
            failure = Some(error.public_failure());
        }

        let outcome = if cleanup_confirmation.is_none() {
            WorkerJobOutcome::CleanupFailed
        } else if failure.is_some() {
            WorkerJobOutcome::Failed
        } else if cancelled {
            WorkerJobOutcome::Cancelled
        } else if build_state == JobState::Succeeded {
            WorkerJobOutcome::Succeeded
        } else {
            WorkerJobOutcome::Failed
        };

        self.state.phase = WorkerJobPhase::Complete;
        self.state.failure.clone_from(&failure);
        self.state.updated_at_ms = self.clock.unix_time_ms().max(self.state.updated_at_ms);
        self.state.validate()?;

        let result = IosDeviceBuildResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: self.manifest.request.operation_id.clone(),
            job_id: self.manifest.job_id.clone(),
            state: build_state,
            artifacts: manifests,
            cleanup: cleanup_confirmation.clone(),
        };
        result
            .validate()
            .map_err(|_| WorkerJobError::InvalidArtifactEvidence)?;

        let mut report = WorkerJobReport {
            schema_version: WORKER_JOB_SCHEMA_VERSION,
            outcome,
            result: result.clone(),
            evidence: WorkerJobEvidence {
                request_sha256: self.state.request_sha256.clone(),
                source_manifest_sha256: self.manifest.request.source.sha256.clone(),
                source_archive: self.source_archive.clone(),
                build: self.build_evidence.clone(),
                signing: self.signing_evidence.clone(),
                timings: self.state.timings.clone(),
                cleanup: cleanup_confirmation,
            },
            failure: failure.clone(),
            state: self.state.clone(),
        };
        let duration_ms = self.elapsed_from_start()?;
        if cancelled && failure.is_none() {
            self.emit(RemoteBuildEventKind::OperationCancelled {
                reason: "user_requested".to_owned(),
                duration_ms,
            })?;
        } else {
            let success = outcome == WorkerJobOutcome::Succeeded;
            self.emit(RemoteBuildEventKind::OperationFinished {
                success,
                duration_ms,
                result: Some(result),
                error: failure.map(|failure| RemoteErrorInfo {
                    code: failure.code,
                    message: failure.message,
                    help: None,
                    retryable: failure.retryable,
                }),
            })?;
        }

        report.state = self.state.clone();
        report.encode_json()?;
        Ok(report)
    }

    fn run_pipeline(&mut self) -> Result<Vec<ArtifactManifest>, WorkerJobError> {
        self.emit(RemoteBuildEventKind::OperationStarted {
            command: "worker.ios_device_build".to_owned(),
        })?;
        self.emit(RemoteBuildEventKind::JobCreated {
            state: JobState::Created,
        })?;
        self.emit(RemoteBuildEventKind::WorkerAssigned {
            worker_id: self.manifest.worker_id.clone(),
        })?;
        self.transition(JobState::Running)?;
        self.prepare_fixed_directories()?;
        self.prepare_source()?;
        let build = self.run_build()?;
        let signing = self.run_sign(&build)?;
        let export = self.run_export(&build, signing.as_ref())?;
        self.run_validation(&build, signing.as_ref(), &export)
    }

    fn prepare_fixed_directories(&mut self) -> Result<(), WorkerJobError> {
        self.root.verify()?;
        prepare_parent_for_fresh_directory(&self.root, &self.source_directory)?;
        prepare_owned_directory(&self.root, &self.logs_directory)?;
        self.root.verify()
    }

    fn prepare_source(&mut self) -> Result<(), WorkerJobError> {
        self.start_phase(WorkerJobPhase::SourceVerification)?;
        self.emit(RemoteBuildEventKind::SourcePrepared {
            file_count: u64::try_from(self.manifest.request.source.entries.len())
                .map_err(|_| WorkerJobError::SourceVerificationFailed)?,
            total_bytes: self.manifest.request.source.total_size,
        })?;

        let source_input = self.manifest.source_input.clone();
        let result = match source_input {
            WorkerSourceInput::Snapshot {
                archive_path,
                archive,
            } => {
                let archive_path = archive_path.resolve(&self.root.path);
                validate_input_file(&self.root, &archive_path)?;
                verify_and_extract_source_bundle(
                    &archive_path,
                    &archive,
                    &self.manifest.request.source,
                    &self.source_directory,
                    SourceArchiveLimits::default(),
                )
                .map_err(|_| WorkerJobError::SourceVerificationFailed)
                .and_then(|verified| {
                    remove_verified_input_file(&self.root, &archive_path)?;
                    self.source_archive = Some(verified);
                    Ok(())
                })
            }
            WorkerSourceInput::Git => {
                let repository = self
                    .manifest
                    .request
                    .source_repository
                    .as_deref()
                    .ok_or(WorkerJobError::InvalidRequest)?;
                let revision = self
                    .manifest
                    .request
                    .source_revision
                    .as_deref()
                    .ok_or(WorkerJobError::InvalidRequest)?;
                let context = WorkerHookContext {
                    job_id: &self.manifest.job_id,
                    worker_id: &self.manifest.worker_id,
                    provider: &self.manifest.provider,
                    job_root: &self.root.path,
                    source_directory: &self.source_directory,
                    project_directory: &self.project_directory,
                    artifacts_directory: &self.artifacts_directory,
                    temporary_directory: &self.temporary_directory,
                    logs_directory: &self.logs_directory,
                    request: &self.manifest.request,
                    cancellation: &self.cancellation,
                };
                self.hooks
                    .materialize_git_source(&context, repository, revision, &self.source_directory)
                    .map_err(|failure| WorkerJobError::Hook {
                        phase: WorkerJobPhase::SourceVerification,
                        failure,
                    })?;
                verify_materialized_bundle(
                    &self.source_directory,
                    &self.manifest.request.source,
                    SourceArchiveLimits::default().source,
                )
                .map_err(|_| WorkerJobError::SourceVerificationFailed)
            }
        };

        let after = self.finish_phase();
        result?;
        after?;
        self.check_cancelled()?;
        self.root.verify()?;
        validate_project_directory(&self.root, &self.source_directory, &self.project_directory)?;
        self.state.source_sha256 = Some(self.manifest.request.source.sha256.clone());
        self.emit(RemoteBuildEventKind::SourceVerified {
            sha256: self.manifest.request.source.sha256.clone(),
        })
    }

    fn run_build(&mut self) -> Result<WorkerBuildOutput, WorkerJobError> {
        self.start_phase(WorkerJobPhase::Build)?;
        let context = WorkerHookContext {
            job_id: &self.manifest.job_id,
            worker_id: &self.manifest.worker_id,
            provider: &self.manifest.provider,
            job_root: &self.root.path,
            source_directory: &self.source_directory,
            project_directory: &self.project_directory,
            artifacts_directory: &self.artifacts_directory,
            temporary_directory: &self.temporary_directory,
            logs_directory: &self.logs_directory,
            request: &self.manifest.request,
            cancellation: &self.cancellation,
        };
        let result = self
            .hooks
            .build(&context)
            .map_err(|failure| WorkerJobError::Hook {
                phase: WorkerJobPhase::Build,
                failure,
            });
        let after = self.finish_phase();
        let output = result?;
        after?;
        self.check_cancelled()?;
        self.root.verify()?;
        if !output
            .archive_path
            .is_descendant_of(self.manifest.paths.source_directory())
            || !output.app_path.is_descendant_of(&output.archive_path)
        {
            return Err(WorkerJobError::InvalidBuildOutput);
        }
        validate_output_directory(&self.root, &output.archive_path.resolve(&self.root.path))?;
        validate_output_directory(&self.root, &output.app_path.resolve(&self.root.path))?;
        self.build_evidence = Some(output.evidence.clone());
        Ok(output)
    }

    fn run_sign(
        &mut self,
        build: &WorkerBuildOutput,
    ) -> Result<Option<WorkerSignOutput>, WorkerJobError> {
        if !self.manifest.request.signing.mode.is_signed() {
            return Ok(None);
        }
        self.start_phase(WorkerJobPhase::Sign)?;
        prepare_fresh_directory(&self.root, &self.temporary_directory)?;
        self.emit(RemoteBuildEventKind::SigningStarted {
            mode: self.manifest.request.signing.mode,
        })?;
        let context = WorkerHookContext {
            job_id: &self.manifest.job_id,
            worker_id: &self.manifest.worker_id,
            provider: &self.manifest.provider,
            job_root: &self.root.path,
            source_directory: &self.source_directory,
            project_directory: &self.project_directory,
            artifacts_directory: &self.artifacts_directory,
            temporary_directory: &self.temporary_directory,
            logs_directory: &self.logs_directory,
            request: &self.manifest.request,
            cancellation: &self.cancellation,
        };
        let result = self
            .hooks
            .sign(&context, build, self.secrets)
            .map_err(|failure| WorkerJobError::Hook {
                phase: WorkerJobPhase::Sign,
                failure,
            });
        let after = self.finish_phase();
        let output = result?;
        after?;
        self.check_cancelled()?;
        self.root.verify()?;
        if !output
            .signed_archive_path
            .is_descendant_of(self.manifest.paths.source_directory())
            || output.signing.mode != self.manifest.request.signing.mode
        {
            return Err(WorkerJobError::InvalidSigningOutput);
        }
        validate_output_directory(
            &self.root,
            &output.signed_archive_path.resolve(&self.root.path),
        )?;
        self.signing_evidence = Some(output.signing.clone());
        Ok(Some(output))
    }

    fn run_export(
        &mut self,
        build: &WorkerBuildOutput,
        signing: Option<&WorkerSignOutput>,
    ) -> Result<WorkerExportOutput, WorkerJobError> {
        self.start_phase(WorkerJobPhase::Export)?;
        prepare_fresh_directory(&self.root, &self.artifacts_directory)?;
        let context = WorkerHookContext {
            job_id: &self.manifest.job_id,
            worker_id: &self.manifest.worker_id,
            provider: &self.manifest.provider,
            job_root: &self.root.path,
            source_directory: &self.source_directory,
            project_directory: &self.project_directory,
            artifacts_directory: &self.artifacts_directory,
            temporary_directory: &self.temporary_directory,
            logs_directory: &self.logs_directory,
            request: &self.manifest.request,
            cancellation: &self.cancellation,
        };
        let result = self
            .hooks
            .export(&context, build, signing)
            .map_err(|failure| WorkerJobError::Hook {
                phase: WorkerJobPhase::Export,
                failure,
            });
        let after = self.finish_phase();
        let output = result?;
        after?;
        self.check_cancelled()?;
        self.root.verify()?;

        let actual_types = output
            .candidates
            .iter()
            .map(WorkerArtifactCandidate::artifact_type)
            .collect::<BTreeSet<_>>();
        if actual_types != self.manifest.request.requested_artifacts {
            return Err(WorkerJobError::InvalidExportOutput);
        }
        for candidate in &output.candidates {
            if !candidate
                .path
                .is_descendant_of(self.manifest.paths.artifacts_directory())
            {
                return Err(WorkerJobError::InvalidExportOutput);
            }
            validate_output_file(&self.root, &candidate.path.resolve(&self.root.path))?;
            self.emit(RemoteBuildEventKind::ArtifactCreated {
                artifact_id: candidate.artifact_id.clone(),
                artifact_type: candidate.artifact_type,
            })?;
        }
        Ok(output)
    }

    fn run_validation(
        &mut self,
        build: &WorkerBuildOutput,
        signing: Option<&WorkerSignOutput>,
        export: &WorkerExportOutput,
    ) -> Result<Vec<ArtifactManifest>, WorkerJobError> {
        self.start_phase(WorkerJobPhase::Validate)?;
        let context = WorkerHookContext {
            job_id: &self.manifest.job_id,
            worker_id: &self.manifest.worker_id,
            provider: &self.manifest.provider,
            job_root: &self.root.path,
            source_directory: &self.source_directory,
            project_directory: &self.project_directory,
            artifacts_directory: &self.artifacts_directory,
            temporary_directory: &self.temporary_directory,
            logs_directory: &self.logs_directory,
            request: &self.manifest.request,
            cancellation: &self.cancellation,
        };
        let result = self
            .hooks
            .validate(&context, build, signing, export)
            .map_err(|failure| WorkerJobError::Hook {
                phase: WorkerJobPhase::Validate,
                failure,
            });
        let after = self.finish_phase();
        let output = result?;
        after?;
        self.check_cancelled()?;
        self.root.verify()?;
        validate_artifact_output(&self.manifest, &self.root, export, output.manifests())?;
        for artifact in output.manifests() {
            self.emit(RemoteBuildEventKind::ArtifactValidated {
                artifact: artifact.clone(),
            })?;
        }
        Ok(output.manifests)
    }

    fn run_cleanup(&mut self, build_state: JobState) -> CleanupRun {
        let mut first_error = None;
        if let Err(error) = self.transition(JobState::Cleaning) {
            first_error = Some(error);
        }
        if let Err(error) = self.start_cleanup_phase() {
            first_error.get_or_insert(error);
        }

        let retain_artifacts = self.manifest.cleanup_policy.retain_for(build_state);
        let confirmation = if self.root.verify().is_err() {
            first_error.get_or_insert(WorkerJobError::JobRootChanged);
            None
        } else {
            let request = WorkerCleanupRequest {
                job_id: &self.manifest.job_id,
                job_root: &self.root.path,
                paths: &self.manifest.paths,
                source_input: &self.manifest.source_input,
                build_state,
                remove_artifacts: !retain_artifacts,
            };
            match self.hooks.cleanup(request) {
                Ok(confirmation)
                    if validate_cleanup_confirmation(
                        &confirmation,
                        &self.manifest.job_id,
                        retain_artifacts,
                    )
                    .is_ok()
                        && self.root.verify().is_ok()
                        && validate_cleanup_filesystem(
                            &self.root,
                            &self.manifest,
                            retain_artifacts,
                        )
                        .is_ok() =>
                {
                    Some(confirmation)
                }
                Ok(_) => {
                    first_error.get_or_insert(WorkerJobError::InvalidCleanupProof);
                    None
                }
                Err(failure) => {
                    first_error.get_or_insert(WorkerJobError::Hook {
                        phase: WorkerJobPhase::Cleanup,
                        failure,
                    });
                    None
                }
            }
        };

        if self.active_phase.is_some()
            && let Err(error) = self.finish_phase()
        {
            first_error.get_or_insert(error);
        }
        let terminal = if confirmation.is_some() {
            JobState::Cleaned
        } else {
            JobState::CleanupFailed
        };
        if let Err(error) = self.transition(terminal) {
            first_error.get_or_insert(error);
        }
        if let Some(confirmation) = &confirmation
            && let Err(error) = self.emit(RemoteBuildEventKind::CleanupFinished {
                confirmation: confirmation.clone(),
            })
        {
            first_error.get_or_insert(error);
        }
        CleanupRun {
            confirmation,
            error: first_error,
        }
    }

    fn start_cleanup_phase(&mut self) -> Result<(), WorkerJobError> {
        self.start_phase_without_cancellation(WorkerJobPhase::Cleanup)?;
        self.emit(RemoteBuildEventKind::CleanupStarted)
    }

    fn start_phase(&mut self, phase: WorkerJobPhase) -> Result<(), WorkerJobError> {
        self.check_cancelled()?;
        self.start_phase_without_cancellation(phase)
    }

    fn start_phase_without_cancellation(
        &mut self,
        phase: WorkerJobPhase,
    ) -> Result<(), WorkerJobError> {
        if self.active_phase.is_some() || self.state.timings.len() >= MAX_PHASE_TIMINGS {
            return Err(WorkerJobError::InvalidState);
        }
        self.root.verify()?;
        let started = self.clock.monotonic_time_ms();
        if started < self.monotonic_start_ms {
            return Err(WorkerJobError::ClockRegressed);
        }
        self.active_phase = Some((phase, started));
        self.state.phase = phase;
        self.emit(RemoteBuildEventKind::PhaseStarted {
            message: Some(phase.safe_message().to_owned()),
        })
    }

    fn finish_phase(&mut self) -> Result<(), WorkerJobError> {
        let (phase, started) = self
            .active_phase
            .take()
            .ok_or(WorkerJobError::InvalidState)?;
        let finished = self.clock.monotonic_time_ms();
        let duration_ms = finished
            .checked_sub(started)
            .ok_or(WorkerJobError::ClockRegressed)?;
        let started_after_ms = started
            .checked_sub(self.monotonic_start_ms)
            .ok_or(WorkerJobError::ClockRegressed)?;
        self.state.timings.push(WorkerPhaseTiming {
            phase,
            started_after_ms,
            duration_ms,
        });
        self.state.updated_at_ms = self.clock.unix_time_ms().max(self.state.updated_at_ms);
        self.root.verify()
    }

    fn elapsed_from_start(&mut self) -> Result<u64, WorkerJobError> {
        self.clock
            .monotonic_time_ms()
            .checked_sub(self.monotonic_start_ms)
            .ok_or(WorkerJobError::ClockRegressed)
    }

    fn check_cancelled(&self) -> Result<(), WorkerJobError> {
        if self.cancellation.is_cancelled() {
            Err(WorkerJobError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn transition(&mut self, next: JobState) -> Result<(), WorkerJobError> {
        self.state.state = self
            .state
            .state
            .transition_to(next)
            .map_err(|_| WorkerJobError::InvalidStateTransition)?;
        self.state.updated_at_ms = self.clock.unix_time_ms().max(self.state.updated_at_ms);
        Ok(())
    }

    fn transition_for_cancellation(&mut self) -> Result<(), WorkerJobError> {
        if self.state.state != JobState::Cancelling {
            self.transition(JobState::Cancelling)?;
        }
        self.transition(JobState::Cancelled)
    }

    fn emit(&mut self, kind: RemoteBuildEventKind) -> Result<(), WorkerJobError> {
        let sequence = self
            .state
            .sequence
            .checked_add(1)
            .ok_or(WorkerJobError::InvalidState)?;
        let timestamp_ms = self.clock.unix_time_ms();
        let event = RemoteBuildEvent::new(
            self.manifest.request.operation_id.clone(),
            self.manifest.job_id.clone(),
            timestamp_ms,
            self.manifest.provider.clone(),
            self.state.phase.event_id(),
            sequence,
            kind,
        )
        .map_err(|_| WorkerJobError::InvalidEvent)?;
        self.state.sequence = sequence;
        self.state.updated_at_ms = timestamp_ms.max(self.state.updated_at_ms);
        self.events
            .emit(&event)
            .map_err(|failure| WorkerJobError::EventSink { failure })
    }
}

struct CleanupRun {
    confirmation: Option<CleanupConfirmation>,
    error: Option<WorkerJobError>,
}

struct JobRootBinding {
    path: Utf8PathBuf,
    identity: Handle,
}

impl JobRootBinding {
    fn open(path: &Utf8Path) -> Result<Self, WorkerJobError> {
        if !path.is_absolute() {
            return Err(WorkerJobError::InvalidJobRoot);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| WorkerJobError::InvalidJobRoot)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WorkerJobError::InvalidJobRoot);
        }
        let canonical = fs::canonicalize(path).map_err(|_| WorkerJobError::InvalidJobRoot)?;
        let path =
            Utf8PathBuf::from_path_buf(canonical).map_err(|_| WorkerJobError::InvalidJobRoot)?;
        let identity = Handle::from_path(&path).map_err(|_| WorkerJobError::InvalidJobRoot)?;
        let binding = Self { path, identity };
        binding.verify()?;
        Ok(binding)
    }

    fn verify(&self) -> Result<(), WorkerJobError> {
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|_| WorkerJobError::JobRootChanged)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WorkerJobError::JobRootChanged);
        }
        let current = Handle::from_path(&self.path).map_err(|_| WorkerJobError::JobRootChanged)?;
        if current != self.identity {
            return Err(WorkerJobError::JobRootChanged);
        }
        Ok(())
    }
}

fn validate_worker_relative_path(value: &str) -> Result<(), WorkerJobError> {
    if value.is_empty()
        || value.len() > MAX_WORKER_PATH_BYTES
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return Err(WorkerJobError::InvalidWorkerPath);
    }
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.len() > MAX_WORKER_PATH_COMPONENT_BYTES
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || component.starts_with('.')
            || component.ends_with('.')
            || component.contains("..")
        {
            return Err(WorkerJobError::InvalidWorkerPath);
        }
    }
    Ok(())
}

fn paths_overlap(left: &WorkerRelativePath, right: &WorkerRelativePath) -> bool {
    left == right || left.is_descendant_of(right) || right.is_descendant_of(left)
}

fn validate_identifier(value: &str) -> Result<(), WorkerJobError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(WorkerJobError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_source_archive(archive: &SourceArchive) -> Result<(), WorkerJobError> {
    if archive.size == 0 || archive.size > SourceArchiveLimits::default().max_archive_size {
        return Err(WorkerJobError::InvalidSourceArchive);
    }
    validate_sha256(&archive.sha256).map_err(|_| WorkerJobError::InvalidSourceArchive)
}

fn validate_sha256(value: &str) -> Result<(), WorkerJobError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(WorkerJobError::InvalidState)
    }
}

fn validate_public_error_code(value: &str) -> Result<(), WorkerJobError> {
    if value.is_empty()
        || value.len() > MAX_PUBLIC_ERROR_CODE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        || value.starts_with('.')
        || value.ends_with('.')
    {
        Err(WorkerJobError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_public_message(value: &str) -> Result<(), WorkerJobError> {
    if value.is_empty()
        || value.len() > MAX_PUBLIC_ERROR_MESSAGE_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        Err(WorkerJobError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

enum BoundedJsonError {
    TooLarge,
    Serialization,
}

fn encode_bounded_json(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, BoundedJsonError> {
    let encoded = serde_json::to_vec(value).map_err(|_| BoundedJsonError::Serialization)?;
    if encoded.len() > maximum {
        Err(BoundedJsonError::TooLarge)
    } else {
        Ok(encoded)
    }
}

fn static_hook_failure(
    code: &'static str,
    message: &'static str,
    retryable: bool,
) -> WorkerHookFailure {
    WorkerHookFailure {
        code,
        message,
        retryable,
    }
}

fn unsupported_platform_failure() -> WorkerHookFailure {
    static_hook_failure(
        "worker.unsupported_platform",
        "Physical-iPhone worker hooks are unavailable on this host",
        false,
    )
}

fn prepare_parent_for_fresh_directory(
    root: &JobRootBinding,
    destination: &Utf8Path,
) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, destination)?;
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(WorkerJobError::InvalidWorkerDirectory),
    }
    let parent = destination
        .parent()
        .ok_or(WorkerJobError::InvalidWorkerDirectory)?;
    if parent != root.path {
        prepare_owned_directory(root, parent)?;
    }
    root.verify()
}

fn prepare_owned_directory(
    root: &JobRootBinding,
    directory: &Utf8Path,
) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, directory)?;
    let relative = directory
        .strip_prefix(&root.path)
        .map_err(|_| WorkerJobError::InvalidWorkerDirectory)?;
    let mut current = root.path.clone();
    for component in relative.as_str().split('/') {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                validate_bound_directory(root, &current, WorkerJobError::InvalidWorkerDirectory)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                root.verify()?;
                fs::create_dir(&current).map_err(|_| WorkerJobError::InvalidWorkerDirectory)?;
                validate_bound_directory(root, &current, WorkerJobError::InvalidWorkerDirectory)?;
            }
            Ok(_) | Err(_) => return Err(WorkerJobError::InvalidWorkerDirectory),
        }
    }
    validate_bound_directory(root, directory, WorkerJobError::InvalidWorkerDirectory)
}

fn prepare_fresh_directory(
    root: &JobRootBinding,
    directory: &Utf8Path,
) -> Result<(), WorkerJobError> {
    prepare_parent_for_fresh_directory(root, directory)?;
    root.verify()?;
    fs::create_dir(directory).map_err(|_| WorkerJobError::InvalidWorkerDirectory)?;
    validate_bound_directory(root, directory, WorkerJobError::InvalidWorkerDirectory)
}

fn validate_project_directory(
    root: &JobRootBinding,
    source_directory: &Utf8Path,
    project_directory: &Utf8Path,
) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, source_directory)?;
    if project_directory != source_directory && !project_directory.starts_with(source_directory) {
        return Err(WorkerJobError::InvalidProjectDirectory);
    }
    validate_bound_directory(
        root,
        source_directory,
        WorkerJobError::InvalidProjectDirectory,
    )?;
    validate_bound_directory(
        root,
        project_directory,
        WorkerJobError::InvalidProjectDirectory,
    )
}

fn validate_output_directory(
    root: &JobRootBinding,
    directory: &Utf8Path,
) -> Result<(), WorkerJobError> {
    validate_bound_directory(root, directory, WorkerJobError::InvalidBuildOutput)
}

fn validate_output_file(root: &JobRootBinding, path: &Utf8Path) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkerJobError::InvalidExportOutput)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(WorkerJobError::InvalidExportOutput);
    }
    let canonical = canonical_utf8(path, WorkerJobError::InvalidExportOutput)?;
    if canonical != path || !canonical.starts_with(&root.path) {
        return Err(WorkerJobError::InvalidExportOutput);
    }
    root.verify()
}

fn validate_input_file(root: &JobRootBinding, path: &Utf8Path) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, path).map_err(|_| WorkerJobError::SourceVerificationFailed)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| WorkerJobError::SourceVerificationFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(WorkerJobError::SourceVerificationFailed);
    }
    let canonical = canonical_utf8(path, WorkerJobError::SourceVerificationFailed)?;
    if canonical != path || !canonical.starts_with(&root.path) {
        return Err(WorkerJobError::SourceVerificationFailed);
    }
    root.verify()
}

fn remove_verified_input_file(
    root: &JobRootBinding,
    path: &Utf8Path,
) -> Result<(), WorkerJobError> {
    validate_input_file(root, path)?;
    fs::remove_file(path).map_err(|_| WorkerJobError::SourceVerificationFailed)?;
    require_path_absent(path).map_err(|_| WorkerJobError::SourceVerificationFailed)?;
    root.verify()
}

fn validate_bound_directory(
    root: &JobRootBinding,
    directory: &Utf8Path,
    error: WorkerJobError,
) -> Result<(), WorkerJobError> {
    ensure_lexically_below(root, directory).map_err(|_| error.clone())?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| error.clone())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(error);
    }
    let canonical = canonical_utf8(directory, error.clone())?;
    if canonical != directory || !canonical.starts_with(&root.path) {
        return Err(error);
    }
    root.verify().map_err(|_| WorkerJobError::JobRootChanged)
}

fn ensure_lexically_below(root: &JobRootBinding, path: &Utf8Path) -> Result<(), WorkerJobError> {
    if !path.is_absolute() || path == root.path || !path.starts_with(&root.path) {
        Err(WorkerJobError::InvalidWorkerDirectory)
    } else {
        Ok(())
    }
}

fn canonical_utf8(path: &Utf8Path, error: WorkerJobError) -> Result<Utf8PathBuf, WorkerJobError> {
    let canonical = fs::canonicalize(path).map_err(|_| error.clone())?;
    Utf8PathBuf::from_path_buf(canonical).map_err(|_| error)
}

fn validate_cleanup_confirmation(
    confirmation: &CleanupConfirmation,
    job_id: &str,
    artifacts_retained: bool,
) -> Result<(), WorkerJobError> {
    if confirmation.job_id != job_id
        || confirmation.completed_at_ms == 0
        || !confirmation.workspace_removed
        || !confirmation.signing_material_removed
        || confirmation.artifacts_retained != artifacts_retained
    {
        Err(WorkerJobError::InvalidCleanupProof)
    } else {
        Ok(())
    }
}

fn validate_cleanup_filesystem(
    root: &JobRootBinding,
    manifest: &WorkerJobManifest,
    artifacts_retained: bool,
) -> Result<(), WorkerJobError> {
    root.verify()?;
    for path in [
        manifest.paths.source_directory.resolve(&root.path),
        manifest.paths.temporary_directory.resolve(&root.path),
    ] {
        require_path_absent(&path)?;
    }
    if let WorkerSourceInput::Snapshot { archive_path, .. } = &manifest.source_input {
        require_path_absent(&archive_path.resolve(&root.path))?;
    }
    let artifacts = manifest.paths.artifacts_directory.resolve(&root.path);
    if artifacts_retained {
        validate_bound_directory(root, &artifacts, WorkerJobError::InvalidCleanupProof)?;
    } else {
        require_path_absent(&artifacts)?;
    }
    root.verify()
}

fn require_path_absent(path: &Utf8Path) -> Result<(), WorkerJobError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(WorkerJobError::InvalidCleanupProof),
    }
}

fn validate_artifact_output(
    job: &WorkerJobManifest,
    root: &JobRootBinding,
    export: &WorkerExportOutput,
    manifests: &[ArtifactManifest],
) -> Result<(), WorkerJobError> {
    if manifests.is_empty() || manifests.len() > MAX_ARTIFACT_MANIFESTS {
        return Err(WorkerJobError::InvalidArtifactEvidence);
    }

    let expected_snapshot = job.request.source_mode == SourceMode::Snapshot;
    let signed = job.request.signing.mode.is_signed();
    let mut records = BTreeMap::<String, &ArtifactRecord>::new();
    for manifest in manifests {
        let encoded =
            serde_json::to_vec(manifest).map_err(|_| WorkerJobError::InvalidArtifactEvidence)?;
        if encoded.len() > MAX_ARTIFACT_MANIFEST_BYTES
            || manifest.schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION
            || manifest.operation_id != job.request.operation_id
            || manifest.job_id != job.job_id
            || manifest.provider != job.provider
            || manifest.source_repository != job.request.source_repository
            || manifest.source_revision != job.request.source_revision
            || manifest.source_snapshot != expected_snapshot
            || manifest.source_sha256 != job.request.source.sha256
            || validate_identifier(&manifest.project_id).is_err()
            || validate_sha256(&manifest.cargo_lock_sha256).is_err()
            || validate_sha256(&manifest.config_sha256).is_err()
            || !is_safe_manifest_text(&manifest.rustferry_version, 128)
            || !is_safe_manifest_text(&manifest.worker_version, 128)
            || manifest.bundle_identifier != job.request.bundle_identifier
            || manifest.app_name != job.request.product_name
            || manifest.build_profile != expected_build_profile(job.request.profile)
            || manifest.architecture != "arm64"
            || manifest.toolchain.rust_target != IOS_DEVICE_RUST_TARGET
            || !validate_toolchain_evidence(manifest)
            || !validate_artifact_signing(job, &manifest.signing)
            || !validate_manifest_extensions(&manifest.extensions)
            || !is_safe_manifest_text(&manifest.app_version, 128)
            || !is_safe_manifest_text(&manifest.build_number, 128)
            || !is_safe_manifest_text(&manifest.started_at, 128)
            || !is_safe_manifest_text(&manifest.finished_at, 128)
            || manifest.cleanup_status != CleanupStatus::Pending
            || manifest.artifacts.is_empty()
            || manifest.artifacts.len() > MAX_ARTIFACT_RECORDS
            || !manifest
                .validation_levels
                .contains(&ValidationLevel::SourceValidated)
            || !manifest
                .validation_levels
                .contains(&ValidationLevel::ArtifactValidated)
            || (signed && manifest.signing.status != SigningStatus::ArtifactValidated)
        {
            return Err(WorkerJobError::InvalidArtifactEvidence);
        }

        for record in &manifest.artifacts {
            validate_artifact_record(record)?;
            if records.insert(record.artifact_id.clone(), record).is_some() {
                return Err(WorkerJobError::InvalidArtifactEvidence);
            }
        }
    }

    if records.len() != export.candidates().len() {
        return Err(WorkerJobError::InvalidArtifactEvidence);
    }

    for candidate in export.candidates() {
        let record = records
            .get(candidate.artifact_id())
            .ok_or(WorkerJobError::InvalidArtifactEvidence)?;
        if record.kind != artifact_kind(candidate.artifact_type())
            || candidate.path().as_str().rsplit('/').next() != Some(record.file_name.as_str())
        {
            return Err(WorkerJobError::InvalidArtifactEvidence);
        }
        let path = candidate.path.resolve(&root.path);
        verify_downloaded_file(&path, record)
            .map_err(|_| WorkerJobError::InvalidArtifactEvidence)?;
        root.verify()?;
    }
    Ok(())
}

fn validate_artifact_record(record: &ArtifactRecord) -> Result<(), WorkerJobError> {
    validate_identifier(&record.artifact_id)
        .map_err(|_| WorkerJobError::InvalidArtifactEvidence)?;
    if record.file_name.is_empty()
        || record.file_name.len() > 255
        || record.file_name.contains('/')
        || record.file_name.contains('\\')
        || record.file_name.chars().any(char::is_control)
        || matches!(record.file_name.as_str(), "." | "..")
        || record.size == 0
        || validate_sha256(&record.sha256).is_err()
        || record.media_type.as_deref().is_some_and(|media_type| {
            media_type.is_empty()
                || media_type.len() > 128
                || media_type.chars().any(char::is_control)
        })
    {
        Err(WorkerJobError::InvalidArtifactEvidence)
    } else {
        Ok(())
    }
}

const fn expected_build_profile(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Debug => "debug",
        BuildProfile::Release => "release",
    }
}

fn is_safe_manifest_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_toolchain_evidence(manifest: &ArtifactManifest) -> bool {
    let toolchain = &manifest.toolchain;
    is_safe_manifest_text(&toolchain.worker_os, 128)
        && is_safe_manifest_text(&toolchain.worker_architecture, 64)
        && is_safe_manifest_text(&toolchain.xcode_version, 128)
        && is_safe_manifest_text(&toolchain.iphoneos_sdk_version, 128)
        && is_safe_manifest_text(&toolchain.rust_version, 128)
}

fn validate_artifact_signing(job: &WorkerJobManifest, signing: &ArtifactSigningEvidence) -> bool {
    if signing.mode != job.request.signing.mode {
        return false;
    }
    if !signing.mode.is_signed() {
        return signing.status == SigningStatus::Unsigned
            && signing.team_id.is_none()
            && signing.certificate_fingerprint.is_none()
            && signing.profile_uuid.is_none()
            && signing.profile_expiration.is_none()
            && signing.entitlements_sha256.is_none();
    }

    let expected_team = job
        .request
        .signing
        .team
        .as_ref()
        .map(|team| team.expected.id());
    signing.status == SigningStatus::ArtifactValidated
        && signing.team_id.as_deref() == expected_team
        && signing
            .certificate_fingerprint
            .as_deref()
            .is_some_and(is_sha256_any_case)
        && signing
            .profile_uuid
            .as_deref()
            .is_some_and(|value| validate_identifier(value).is_ok())
        && signing
            .profile_expiration
            .as_deref()
            .is_some_and(|value| is_safe_manifest_text(value, 128))
        && signing
            .entitlements_sha256
            .as_deref()
            .is_some_and(|value| validate_sha256(value).is_ok())
}

fn is_sha256_any_case(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_manifest_extensions(extensions: &[String]) -> bool {
    if extensions.len() > MAX_ARTIFACT_RECORDS {
        return false;
    }
    let mut previous = None;
    for extension in extensions {
        if BundleIdentifier::new(extension.clone()).is_err()
            || previous.is_some_and(|value: &str| value >= extension.as_str())
        {
            return false;
        }
        previous = Some(extension.as_str());
    }
    true
}

const fn artifact_kind(artifact_type: IosArtifactType) -> ArtifactKind {
    match artifact_type {
        IosArtifactType::Ipa => ArtifactKind::Ipa,
        IosArtifactType::Xcarchive => ArtifactKind::Xcarchive,
        IosArtifactType::AppBundle => ArtifactKind::App,
        IosArtifactType::SigningReport => ArtifactKind::SigningReport,
        IosArtifactType::ProvisioningReport => ArtifactKind::ValidationReport,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use camino::Utf8PathBuf;
    use rustferry_remote::{
        AppleToolchainEvidence, SigningMode, SigningPlan, SigningTarget, SigningTargetKind,
        SourceBundleRequest, create_source_bundle_archive, plan_source_bundle,
    };
    use tempfile::TempDir;

    use super::*;

    struct WorkerFixture {
        _temporary: TempDir,
        job_root: Utf8PathBuf,
        manifest: WorkerJobManifest,
    }

    fn worker_fixture() -> WorkerFixture {
        let temporary = tempfile::tempdir().expect("temporary worker fixture");
        let temporary_root = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
            .expect("UTF-8 temporary path");
        let fixture_source = temporary_root.join("fixture");
        fs::create_dir_all(fixture_source.join("src")).expect("fixture source directory");
        fs::write(
            fixture_source.join("Cargo.toml"),
            b"[package]\nname = \"weather\"\nversion = \"0.1.0\"\n",
        )
        .expect("fixture manifest");
        fs::write(fixture_source.join("src/lib.rs"), b"pub fn weather() {}\n")
            .expect("fixture Rust source");

        let source_request = SourceBundleRequest::new(&fixture_source, &fixture_source);
        let source_plan = plan_source_bundle(&source_request).expect("source plan");
        let source_manifest = source_plan.manifest().clone();
        let job_root = temporary_root.join("job");
        fs::create_dir_all(job_root.join("input")).expect("job input directory");
        let archive_path = job_root.join("input/source.zip");
        let archive = create_source_bundle_archive(
            &source_plan,
            &archive_path,
            SourceArchiveLimits::default(),
        )
        .expect("deterministic source archive");

        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "Weather".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.weather")
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
            product_name: "Weather".to_owned(),
            bundle_identifier: "com.example.weather".to_owned(),
            minimum_ios_version: "16.0".to_owned(),
            product: rustferry_remote::IosDeviceProductExpectation {
                app_directory_name: "Weather.app".to_owned(),
                executable: "Weather".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Debug,
            source_mode: SourceMode::Snapshot,
            source_repository: None,
            source_revision: None,
            source: source_manifest,
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        let source_input = WorkerSourceInput::snapshot(
            WorkerRelativePath::new("input/source.zip").expect("archive path"),
            archive,
        )
        .expect("snapshot input");
        let manifest = WorkerJobManifest::new(
            "job-1",
            "worker-1",
            "fake",
            request,
            source_input,
            WorkerJobPaths::default(),
            WorkerCleanupPolicy::default(),
        )
        .expect("worker manifest");

        WorkerFixture {
            _temporary: temporary,
            job_root,
            manifest,
        }
    }

    #[derive(Default)]
    struct FakeSecrets {
        resolve_calls: usize,
    }

    impl WorkerSecretResolver for FakeSecrets {
        fn resolve(
            &mut self,
            _reference: &SecretReference,
        ) -> Result<SecretBytes, WorkerHookFailure> {
            self.resolve_calls += 1;
            Ok(SecretBytes::new(
                b"fixture-secret-must-not-serialize".to_vec(),
            ))
        }
    }

    #[derive(Default)]
    struct FakeClock {
        wall_ms: u64,
        monotonic_ms: u64,
    }

    impl WorkerClock for FakeClock {
        fn unix_time_ms(&mut self) -> u64 {
            self.wall_ms += 1;
            self.wall_ms
        }

        fn monotonic_time_ms(&mut self) -> u64 {
            self.monotonic_ms += 10;
            self.monotonic_ms
        }
    }

    #[derive(Default)]
    struct FakeHooks {
        build_calls: usize,
        sign_calls: usize,
        export_calls: usize,
        validation_calls: usize,
        cleanup_calls: usize,
        fail_build: bool,
        fail_cleanup: bool,
    }

    impl WorkerJobHooks for FakeHooks {
        fn materialize_git_source(
            &mut self,
            _context: &WorkerHookContext<'_>,
            _repository: &str,
            _revision: &str,
            _destination: &Utf8Path,
        ) -> Result<(), WorkerHookFailure> {
            Err(fake_hook_failure())
        }

        fn build(
            &mut self,
            context: &WorkerHookContext<'_>,
        ) -> Result<WorkerBuildOutput, WorkerHookFailure> {
            self.build_calls += 1;
            if self.fail_build {
                return Err(static_hook_failure(
                    "fake.build_failed",
                    "Fixture build failed",
                    false,
                ));
            }
            let archive = context
                .source_directory()
                .join("target/ferry/Weather.xcarchive");
            let app = archive.join("Products/Applications/Weather.app");
            fs::create_dir_all(&app).map_err(|_| fake_hook_failure())?;
            WorkerBuildOutput::new(
                WorkerRelativePath::from_absolute_under(context.job_root(), &archive)
                    .map_err(|_| fake_hook_failure())?,
                WorkerRelativePath::from_absolute_under(context.job_root(), &app)
                    .map_err(|_| fake_hook_failure())?,
                WorkerBuildEvidence {
                    rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
                    sdk: IOS_DEVICE_SDK.to_owned(),
                    device_binary_proven: true,
                    archive_inspected: true,
                },
            )
            .map_err(|_| fake_hook_failure())
        }

        fn sign(
            &mut self,
            _context: &WorkerHookContext<'_>,
            _build: &WorkerBuildOutput,
            _secrets: &mut dyn WorkerSecretResolver,
        ) -> Result<WorkerSignOutput, WorkerHookFailure> {
            self.sign_calls += 1;
            Err(fake_hook_failure())
        }

        fn export(
            &mut self,
            context: &WorkerHookContext<'_>,
            _build: &WorkerBuildOutput,
            _signing: Option<&WorkerSignOutput>,
        ) -> Result<WorkerExportOutput, WorkerHookFailure> {
            self.export_calls += 1;
            let path = context.artifacts_directory().join("Weather.xcarchive.zip");
            fs::write(&path, b"validated unsigned archive fixture")
                .map_err(|_| fake_hook_failure())?;
            let candidate = WorkerArtifactCandidate::new(
                "artifact-xcarchive",
                IosArtifactType::Xcarchive,
                WorkerRelativePath::from_absolute_under(context.job_root(), &path)
                    .map_err(|_| fake_hook_failure())?,
            )
            .map_err(|_| fake_hook_failure())?;
            WorkerExportOutput::new(vec![candidate]).map_err(|_| fake_hook_failure())
        }

        fn validate(
            &mut self,
            context: &WorkerHookContext<'_>,
            _build: &WorkerBuildOutput,
            _signing: Option<&WorkerSignOutput>,
            export: &WorkerExportOutput,
        ) -> Result<WorkerValidationOutput, WorkerHookFailure> {
            self.validation_calls += 1;
            let candidate = export.candidates().first().ok_or(fake_hook_failure())?;
            let path = candidate.path().resolve(context.job_root());
            let bytes = fs::read(&path).map_err(|_| fake_hook_failure())?;
            let file_name = path.file_name().ok_or(fake_hook_failure())?.to_owned();
            let record = ArtifactRecord {
                artifact_id: candidate.artifact_id().to_owned(),
                kind: ArtifactKind::Xcarchive,
                file_name,
                size: u64::try_from(bytes.len()).map_err(|_| fake_hook_failure())?,
                sha256: sha256_hex(&bytes),
                media_type: Some("application/zip".to_owned()),
            };
            let mut manifest = ArtifactManifest::new(
                context.request().operation_id.clone(),
                context.job_id().to_owned(),
            );
            manifest.project_id = "project.weather".to_owned();
            manifest.source_repository = context.request().source_repository.clone();
            manifest.source_revision = context.request().source_revision.clone();
            manifest.source_snapshot = context.request().source_mode == SourceMode::Snapshot;
            manifest.source_sha256 = context.request().source.sha256.clone();
            manifest.cargo_lock_sha256 = "a".repeat(64);
            manifest.config_sha256 = "b".repeat(64);
            manifest.rustferry_version = "0.1.0".to_owned();
            manifest.worker_version = "0.1.0".to_owned();
            manifest.provider = context.provider().to_owned();
            manifest.toolchain = AppleToolchainEvidence {
                worker_os: "macOS 15.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "16.0".to_owned(),
                iphoneos_sdk_version: "18.0".to_owned(),
                rust_version: "rustc 1.88.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            };
            manifest.app_name = context.request().product_name.clone();
            manifest.app_version = "1.0.0".to_owned();
            manifest.build_number = "1".to_owned();
            manifest.bundle_identifier = context.request().bundle_identifier.clone();
            manifest.build_profile = expected_build_profile(context.request().profile).to_owned();
            manifest.architecture = "arm64".to_owned();
            manifest.artifacts = vec![record];
            manifest.validation_levels = BTreeSet::from([
                ValidationLevel::SourceValidated,
                ValidationLevel::RemoteBuilderValidated,
                ValidationLevel::DeviceTargetCompiled,
                ValidationLevel::DeviceBinaryBuilt,
                ValidationLevel::AppBundleBuilt,
                ValidationLevel::ArchiveBuilt,
                ValidationLevel::ArtifactValidated,
            ]);
            manifest.started_at = "2026-08-01T00:00:00Z".to_owned();
            manifest.finished_at = "2026-08-01T00:00:01Z".to_owned();
            manifest.cleanup_status = CleanupStatus::Pending;
            WorkerValidationOutput::new(vec![manifest]).map_err(|_| fake_hook_failure())
        }

        fn cleanup(
            &mut self,
            request: WorkerCleanupRequest<'_>,
        ) -> Result<CleanupConfirmation, WorkerHookFailure> {
            self.cleanup_calls += 1;
            if self.fail_cleanup {
                return Err(static_hook_failure(
                    "fake.cleanup_failed",
                    "Fixture cleanup failed",
                    false,
                ));
            }
            remove_directory_if_present(
                &request.paths.source_directory().resolve(request.job_root),
            )?;
            remove_directory_if_present(
                &request
                    .paths
                    .temporary_directory()
                    .resolve(request.job_root),
            )?;
            if let Some(archive) = request.source_input.archive_path() {
                remove_file_if_present(&archive.resolve(request.job_root))?;
            }
            if request.remove_artifacts {
                remove_directory_if_present(
                    &request
                        .paths
                        .artifacts_directory()
                        .resolve(request.job_root),
                )?;
            }
            Ok(CleanupConfirmation {
                job_id: request.job_id.to_owned(),
                completed_at_ms: 1,
                workspace_removed: true,
                signing_material_removed: true,
                artifacts_retained: !request.remove_artifacts,
            })
        }
    }

    fn fake_hook_failure() -> WorkerHookFailure {
        static_hook_failure("fake.fixture_failed", "Fixture operation failed", false)
    }

    fn remove_directory_if_present(path: &Utf8Path) -> Result<(), WorkerHookFailure> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(fake_hook_failure()),
        }
    }

    fn remove_file_if_present(path: &Utf8Path) -> Result<(), WorkerHookFailure> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(fake_hook_failure()),
        }
    }

    #[test]
    fn relative_paths_and_job_directories_reject_escape_and_overlap() {
        for invalid in [
            "",
            ".",
            "..",
            "/absolute",
            "C:/absolute",
            "parent/../escape",
            "double//separator",
            "windows\\separator",
            ".hidden",
            "trailing.",
            "non-ascii-ñ",
        ] {
            assert_eq!(
                WorkerRelativePath::new(invalid),
                Err(WorkerJobError::InvalidWorkerPath),
                "accepted unsafe path: {invalid}"
            );
        }
        assert!(WorkerRelativePath::new("output/Weather.xcarchive.zip").is_ok());

        let overlap = WorkerJobPaths::new(
            WorkerRelativePath::new("workspace").expect("path"),
            WorkerRelativePath::new("workspace/artifacts").expect("path"),
            WorkerRelativePath::new("private").expect("path"),
            WorkerRelativePath::new("logs").expect("path"),
        );
        assert_eq!(overlap, Err(WorkerJobError::OverlappingWorkerPaths));
    }

    #[test]
    fn manifest_json_is_bounded_strict_and_revision_bound() {
        let fixture = worker_fixture();
        let request_hash = fixture.manifest.request_sha256().expect("request hash");
        let encoded = fixture.manifest.encode_json().expect("encoded manifest");
        let decoded = decode_worker_job_manifest(&encoded).expect("decoded manifest");
        assert_eq!(decoded, fixture.manifest);
        assert_eq!(
            decoded.request_sha256().expect("decoded request hash"),
            request_hash
        );

        let mut value = serde_json::to_value(&fixture.manifest).expect("manifest JSON value");
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        let unknown = serde_json::to_vec(&value).expect("unknown-field manifest");
        assert_eq!(
            decode_worker_job_manifest(&unknown),
            Err(WorkerJobError::MalformedManifest)
        );
        assert_eq!(
            decode_worker_job_manifest(&vec![b' '; MAX_WORKER_JOB_MANIFEST_BYTES + 1]),
            Err(WorkerJobError::ManifestTooLarge)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fake_snapshot_job_verifies_source_artifact_events_and_cleanup() {
        let fixture = worker_fixture();
        let manifest_json = fixture.manifest.encode_json().expect("manifest JSON");
        let mut hooks = FakeHooks::default();
        let mut secrets = FakeSecrets::default();
        let mut events = MemoryEventSink::default();
        let mut clock = FakeClock::default();
        let report = execute_worker_job(
            fixture.manifest,
            &fixture.job_root,
            &mut hooks,
            &mut secrets,
            &mut events,
            &mut clock,
            CancellationToken::new(),
        )
        .expect("successful fake worker job");

        assert_eq!(report.outcome, WorkerJobOutcome::Succeeded);
        assert_eq!(report.result.state, JobState::Succeeded);
        assert_eq!(report.state.state(), JobState::Cleaned);
        assert_eq!(report.state.phase(), WorkerJobPhase::Complete);
        assert!(report.failure.is_none());
        assert_eq!(report.result.artifacts.len(), 1);
        assert_eq!(hooks.build_calls, 1);
        assert_eq!(hooks.sign_calls, 0);
        assert_eq!(hooks.export_calls, 1);
        assert_eq!(hooks.validation_calls, 1);
        assert_eq!(hooks.cleanup_calls, 1);
        assert_eq!(secrets.resolve_calls, 0);
        assert!(!fixture.job_root.join("workspace/source").exists());
        assert!(!fixture.job_root.join("private/temporary").exists());
        assert!(!fixture.job_root.join("input/source.zip").exists());
        assert!(fixture.job_root.join("output/artifacts").is_dir());

        let phases = report
            .state
            .timings()
            .iter()
            .map(|timing| timing.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                WorkerJobPhase::SourceVerification,
                WorkerJobPhase::Build,
                WorkerJobPhase::Export,
                WorkerJobPhase::Validate,
                WorkerJobPhase::Cleanup,
            ]
        );
        let names = events
            .events()
            .iter()
            .map(|event| event.kind.event_name())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "operation_started",
                "job_created",
                "worker_assigned",
                "phase_started",
                "source_prepared",
                "source_verified",
                "phase_started",
                "phase_started",
                "artifact_created",
                "phase_started",
                "artifact_validated",
                "phase_started",
                "cleanup_started",
                "cleanup_finished",
                "operation_finished",
            ]
        );
        assert!(
            events
                .events()
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        assert_eq!(
            report.state.sequence(),
            u64::try_from(events.events().len()).expect("event count fits u64")
        );

        let state_json = report.state.encode_json().expect("state JSON");
        assert_eq!(
            decode_worker_job_state(&state_json).expect("decoded state"),
            report.state
        );
        let report_json = report.encode_json().expect("report JSON");
        assert!(
            !report_json
                .windows(b"fixture-secret-must-not-serialize".len())
                .any(|window| window == b"fixture-secret-must-not-serialize")
        );
        assert!(
            !manifest_json
                .windows(b"fixture-secret-must-not-serialize".len())
                .any(|window| window == b"fixture-secret-must-not-serialize")
        );
    }

    #[test]
    fn cancellation_before_source_still_cleans_every_private_location() {
        let fixture = worker_fixture();
        let cancellation = CancellationToken::new();
        assert!(cancellation.cancel());
        let mut hooks = FakeHooks::default();
        let mut secrets = FakeSecrets::default();
        let mut events = MemoryEventSink::default();
        let mut clock = FakeClock::default();
        let report = execute_worker_job(
            fixture.manifest,
            &fixture.job_root,
            &mut hooks,
            &mut secrets,
            &mut events,
            &mut clock,
            cancellation,
        )
        .expect("cancelled fake worker job");

        assert_eq!(report.outcome, WorkerJobOutcome::Cancelled);
        assert_eq!(report.result.state, JobState::Cancelled);
        assert_eq!(report.state.state(), JobState::Cleaned);
        assert!(report.failure.is_none());
        assert_eq!(hooks.build_calls, 0);
        assert_eq!(hooks.cleanup_calls, 1);
        assert_eq!(secrets.resolve_calls, 0);
        assert!(!fixture.job_root.join("workspace/source").exists());
        assert!(!fixture.job_root.join("private/temporary").exists());
        assert!(!fixture.job_root.join("output/artifacts").exists());
        assert!(!fixture.job_root.join("input/source.zip").exists());
        assert_eq!(
            events.events().last().map(|event| event.kind.event_name()),
            Some("operation_cancelled")
        );
    }

    #[test]
    fn hook_failure_is_redacted_and_cleanup_remains_mandatory() {
        let fixture = worker_fixture();
        let mut hooks = FakeHooks {
            fail_build: true,
            ..FakeHooks::default()
        };
        let mut secrets = FakeSecrets::default();
        let mut events = MemoryEventSink::default();
        let mut clock = FakeClock::default();
        let report = execute_worker_job(
            fixture.manifest,
            &fixture.job_root,
            &mut hooks,
            &mut secrets,
            &mut events,
            &mut clock,
            CancellationToken::new(),
        )
        .expect("failed fake worker report");

        assert_eq!(report.outcome, WorkerJobOutcome::Failed);
        assert_eq!(report.result.state, JobState::Failed);
        assert_eq!(report.state.state(), JobState::Cleaned);
        assert_eq!(hooks.build_calls, 1);
        assert_eq!(hooks.cleanup_calls, 1);
        assert_eq!(
            report.failure.as_ref().map(|failure| failure.code.as_str()),
            Some("fake.build_failed")
        );
        assert!(!fixture.job_root.join("workspace/source").exists());
        assert!(!fixture.job_root.join("private/temporary").exists());
        assert!(!fixture.job_root.join("output/artifacts").exists());
        assert!(!fixture.job_root.join("input/source.zip").exists());
    }

    #[test]
    fn cleanup_failure_cannot_be_reported_as_success() {
        let fixture = worker_fixture();
        let mut hooks = FakeHooks {
            fail_cleanup: true,
            ..FakeHooks::default()
        };
        let mut secrets = FakeSecrets::default();
        let mut events = MemoryEventSink::default();
        let mut clock = FakeClock::default();
        let report = execute_worker_job(
            fixture.manifest,
            &fixture.job_root,
            &mut hooks,
            &mut secrets,
            &mut events,
            &mut clock,
            CancellationToken::new(),
        )
        .expect("cleanup failure report");

        assert_eq!(report.outcome, WorkerJobOutcome::CleanupFailed);
        assert_eq!(report.result.state, JobState::Succeeded);
        assert_eq!(report.state.state(), JobState::CleanupFailed);
        assert!(report.result.cleanup.is_none());
        assert_eq!(
            report.failure.as_ref().map(|failure| failure.code.as_str()),
            Some("fake.cleanup_failed")
        );
        assert_eq!(
            events.events().last().map(|event| event.kind.event_name()),
            Some("operation_finished")
        );
    }
}
