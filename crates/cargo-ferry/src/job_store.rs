//! Persistent, append-only machine records for remote build jobs.

mod admin;

pub use admin::*;

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::path::Prefix;

use directories::BaseDirs;
use rustferry_core::{
    DirectoryFilesystemIdentity, RegularFileFilesystemIdentity, RetainedDirectoryIdentity,
};
use rustferry_github::provider::{
    GITHUB_JOB_RESUME_MAX_BYTES, GITHUB_PROVIDER_ID, GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS,
    GithubDurableIdentityV1, GithubGitSnapshotPhaseV1, GithubJobCheckpointSink, GithubJobResumeV1,
    GithubPrincipalIdentityV1, GithubRunConclusionV1, GithubRunEventV1, GithubRunStatusV1,
    GithubSignedCleanupEvidenceV1, validate_github_compile_phase_evidence,
};
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactManifest, ArtifactRecord, BuildProfile,
    CompilePhaseEvidence, GitSnapshotDescriptor, IosDeviceBuildRequest, JobState, RemoteBuildError,
    RemoteBuildEventKind, RemoteBuildResult, SigningMode, SourceBundleDescriptor, SourceMode,
    canonical_request_sha256, canonical_retry_template_sha256_v1,
};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Logical schema of the public [`StoredJobV1`] payload.
pub const JOB_STORE_SCHEMA_VERSION: u32 = 1;
/// Current schema of the immutable on-disk revision envelope.
pub const JOB_REVISION_SCHEMA_VERSION: u32 = 2;
const LEGACY_JOB_REVISION_SCHEMA_VERSION: u32 = 1;
/// Maximum encoded size of one legacy v1 job revision.
pub const MAX_LEGACY_JOB_REVISION_BYTES: u64 =
    (2 * GITHUB_JOB_RESUME_MAX_BYTES + 1024 * 1024) as u64;
/// Maximum encoded size of one current immutable job revision.
pub const MAX_JOB_REVISION_BYTES: u64 = MAX_LEGACY_JOB_REVISION_BYTES + 512;
/// Maximum number of immutable revisions retained for one job.
pub const MAX_REVISIONS_PER_JOB: usize = 4_096;
/// Maximum number of job directories considered by one list operation.
pub const MAX_STORED_JOBS: usize = 10_000;
/// Maximum number of jobs returned by one list operation.
pub const MAX_LISTED_JOBS: usize = 1_000;

const MAX_IDENTIFIER_BYTES: usize = 160;
const MAX_SAFE_TEXT_BYTES: usize = 4_096;
const MAX_ARTIFACTS: usize = 128;
const MAX_RETRY_CHILDREN: usize = 256;
const REVISION_DIGITS: usize = 20;
const SHA256_HEX_BYTES: usize = 64;
const JOBS_DIRECTORY: &str = "jobs";
const VERSION_DIRECTORY: &str = "v1";
const REVISIONS_DIRECTORY: &str = "revisions";
const LOCK_FILE: &str = "lock";

/// Stable local identifier used as a single safe path component.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalJobId(String);

impl LocalJobId {
    /// Generate a new local identifier independent of provider and operation identifiers.
    #[must_use]
    pub fn generate() -> Self {
        Self(format!("job-{}", Uuid::new_v4().simple()))
    }

    /// Validate and construct a local job identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JobStoreError::InvalidIdentifier`] if the value is empty, oversized, not
    /// lowercase ASCII, or could escape its single path component.
    pub fn new(value: impl Into<String>) -> Result<Self, JobStoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            && !is_windows_reserved_component(&value);
        if !valid {
            return Err(JobStoreError::InvalidIdentifier {
                field: "local_job_id",
                reason: "must be 1-160 lowercase ASCII letters, digits, hyphens, or underscores and start/end alphanumeric",
            });
        }
        Ok(Self(value))
    }

    /// Return the validated identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LocalJobId {
    type Error = JobStoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LocalJobId> for String {
    fn from(value: LocalJobId) -> Self {
        value.0
    }
}

/// Local lifecycle, intentionally more detailed than the remote wire `JobState`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredJobState {
    /// Local record allocated.
    Created,
    /// Source is being validated or snapshotted.
    SourcePreparing,
    /// Exact source is ready for submission.
    SourceReady,
    /// Provider submission is in progress or being reconciled.
    Submitting,
    /// Provider accepted the job and it awaits a worker.
    Queued,
    /// Provider reports general execution.
    Running,
    /// Physical-iPhone compilation is running.
    CompileRunning,
    /// Compile phase finished and protected signing is waiting.
    SigningWaiting,
    /// Protected signing is running.
    SigningRunning,
    /// Worker is publishing artifacts.
    ArtifactUploading,
    /// Validated artifact records are available.
    ArtifactReady,
    /// Client download is in progress.
    Downloading,
    /// Expected artifacts were downloaded create-only.
    Downloaded,
    /// Local independent validation is in progress.
    Validating,
    /// Build, download, validation, and cleanup policy succeeded.
    Succeeded,
    /// Build or client processing failed.
    Failed,
    /// A durable cancellation intent exists.
    CancellationRequested,
    /// Provider cancellation reached a confirmed terminal state.
    Cancelled,
    /// Required remote or local cleanup is pending.
    CleanupPending,
    /// Required cleanup could not be proven.
    CleanupFailed,
    /// Provider artifacts or resumable identity expired.
    Expired,
    /// Provider status is currently unknown without changing the last confirmed state.
    Unknown,
}

impl StoredJobState {
    /// Return whether one direct local lifecycle transition is structurally valid.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive lifecycle table is clearer as one auditable match"
    )]
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Created => matches!(
                next,
                Self::SourcePreparing
                    | Self::SourceReady
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Unknown
            ),
            Self::SourcePreparing => matches!(
                next,
                Self::SourceReady | Self::Failed | Self::CancellationRequested | Self::Unknown
            ),
            Self::SourceReady => matches!(
                next,
                Self::Submitting
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::Submitting => matches!(
                next,
                Self::Queued
                    | Self::Running
                    | Self::CompileRunning
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::Queued => matches!(
                next,
                Self::Running
                    | Self::CompileRunning
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::Running | Self::CompileRunning => matches!(
                next,
                Self::CompileRunning
                    | Self::SigningWaiting
                    | Self::SigningRunning
                    | Self::ArtifactUploading
                    | Self::ArtifactReady
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::SigningWaiting => matches!(
                next,
                Self::SigningRunning
                    | Self::ArtifactUploading
                    | Self::ArtifactReady
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::SigningRunning => matches!(
                next,
                Self::ArtifactUploading
                    | Self::ArtifactReady
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::ArtifactUploading => matches!(
                next,
                Self::ArtifactReady
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::Cancelled
                    | Self::Unknown
            ),
            Self::ArtifactReady => matches!(
                next,
                Self::Downloading
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::CleanupPending
                    | Self::CleanupFailed
                    | Self::Expired
                    | Self::Unknown
            ),
            Self::Downloading => matches!(
                next,
                Self::Downloaded
                    | Self::Failed
                    | Self::CancellationRequested
                    | Self::CleanupPending
                    | Self::CleanupFailed
                    | Self::Expired
                    | Self::Unknown
            ),
            Self::Downloaded => matches!(
                next,
                Self::Validating
                    | Self::Succeeded
                    | Self::Failed
                    | Self::CleanupPending
                    | Self::CleanupFailed
                    | Self::Unknown
            ),
            Self::Validating => matches!(
                next,
                Self::Succeeded
                    | Self::CleanupPending
                    | Self::CleanupFailed
                    | Self::Failed
                    | Self::Unknown
            ),
            Self::CancellationRequested => matches!(
                next,
                Self::Cancelled
                    | Self::Failed
                    | Self::CleanupPending
                    | Self::CleanupFailed
                    | Self::Unknown
            ),
            Self::CleanupPending => matches!(
                next,
                Self::ArtifactReady
                    | Self::Downloading
                    | Self::Downloaded
                    | Self::Validating
                    | Self::Succeeded
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Expired
                    | Self::CleanupFailed
                    | Self::Unknown
            ),
            Self::Failed | Self::Cancelled | Self::Expired => {
                matches!(next, Self::CleanupPending | Self::CleanupFailed)
            }
            Self::CleanupFailed => matches!(next, Self::CleanupPending | Self::Unknown),
            Self::Unknown | Self::Succeeded => false,
        }
    }

    /// Return whether the state requires at least one artifact record.
    #[must_use]
    pub const fn requires_artifacts(self) -> bool {
        matches!(
            self,
            Self::ArtifactReady
                | Self::Downloading
                | Self::Downloaded
                | Self::Validating
                | Self::Succeeded
        )
    }
}

/// Immutable build outcome, separate from cleanup and observation state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredBuildOutcome {
    /// Provider build and remote artifact validation succeeded; local validation may be pending.
    Succeeded,
    /// Build or client validation failed.
    Failed,
    /// Provider confirmed cancellation.
    Cancelled,
    /// Required resumable provider state expired.
    Expired,
}

/// Durable cleanup policy status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredCleanupStatus {
    /// Cleanup has not started.
    NotStarted,
    /// Cleanup is required and pending.
    Pending,
    /// Required cleanup was independently confirmed.
    Confirmed,
    /// Cleanup failed.
    Failed,
    /// Current cleanup status cannot be proven.
    Uncertain,
}

impl StoredCleanupStatus {
    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::NotStarted | Self::Pending | Self::Uncertain,
                    Self::Pending | Self::Confirmed | Self::Failed | Self::Uncertain
                ) | (
                    Self::Failed,
                    Self::Pending | Self::Confirmed | Self::Uncertain
                )
            )
    }
}

/// Durable cancellation status, distinct from a provider acknowledgement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredCancellationStatus {
    /// No cancellation requested.
    NotRequested,
    /// Intent persisted before provider mutation.
    Requested,
    /// Provider cancellation call was acknowledged.
    Dispatched,
    /// Provider terminal cancellation was confirmed.
    Confirmed,
    /// Cancellation failed without a terminal confirmation.
    Failed,
    /// Cancellation outcome is currently uncertain.
    Uncertain,
}

impl StoredCancellationStatus {
    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::NotRequested, Self::Requested | Self::Confirmed)
                    | (
                        Self::Requested | Self::Dispatched | Self::Uncertain,
                        Self::Dispatched | Self::Confirmed | Self::Failed | Self::Uncertain
                    )
                    | (
                        Self::Failed,
                        Self::Requested | Self::Dispatched | Self::Confirmed | Self::Uncertain
                    )
            )
    }
}

/// Stable project identity persisted outside the source tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProjectIdentityV1 {
    /// Canonical machine-local project root.
    pub canonical_root: String,
    /// Opaque filesystem identity captured by the controller and recaptured before mutations.
    pub filesystem_identity: String,
    /// Application bundle identifier from the validated request.
    pub application_identifier: String,
}

/// Stable GitHub principal, execution repository, and config identity captured before submission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProviderIdentityV1 {
    /// Stable provider name; currently exactly `github-actions`.
    pub provider: String,
    /// Lowercase SHA-256 of the validated provider configuration.
    pub provider_config_sha256: String,
    /// Stable authenticated GitHub user ID and login.
    pub principal: GithubPrincipalIdentityV1,
    /// Canonical credential-free GitHub execution-repository URL.
    pub execution_repository: String,
    /// Stable GitHub database ID for the execution repository.
    pub execution_repository_id: u64,
}

impl From<GithubDurableIdentityV1> for StoredProviderIdentityV1 {
    fn from(identity: GithubDurableIdentityV1) -> Self {
        Self {
            provider: identity.provider,
            provider_config_sha256: identity.provider_config_sha256,
            principal: identity.principal,
            execution_repository: identity.execution_repository,
            execution_repository_id: identity.execution_repository_id,
        }
    }
}

/// Exact source identity bound to the request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSourceIdentityV1 {
    /// Exact Git commit for Git mode, otherwise a safe snapshot identifier.
    pub revision: Option<String>,
    /// Lowercase SHA-256 of the source manifest.
    pub manifest_sha256: String,
}

/// One artifact record plus machine-local publication state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredArtifactV1 {
    /// Secret-free provider artifact record.
    pub record: ArtifactRecord,
    /// Absolute create-only destination persisted before the provider download begins.
    pub download_destination: Option<String>,
    /// Canonical identity of the verified destination parent directory.
    pub download_parent_identity: Option<String>,
    /// Local published path, never a provider URL.
    pub local_path: Option<String>,
    /// Canonical machine-local single-link regular-file identity captured after publication.
    pub local_file_identity: Option<String>,
    /// Whether independent local validation completed.
    pub locally_validated: bool,
}

/// Safe typed failure persisted without raw provider text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFailureV1 {
    /// Stable sanitized error code.
    pub code: String,
    /// Whether a later controller may retry the operation.
    pub retryable: bool,
}

/// Retry ancestry and immutable child identifiers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRetryLineageV1 {
    /// Zero for an original job and positive for a retry.
    pub attempt: u32,
    /// Required immutable parent for every retry.
    pub parent_job_id: Option<LocalJobId>,
    /// Retry jobs created from this job, in creation order.
    pub child_job_ids: Vec<LocalJobId>,
}

/// Complete secret-free v1 job revision.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredJobV1 {
    /// Store schema version; currently exactly one.
    pub schema_version: u32,
    /// Stable local job identifier and directory name.
    pub local_job_id: LocalJobId,
    /// Strictly increasing immutable revision, starting at one.
    pub revision: u64,
    /// Project identity checked before project-scoped mutations.
    pub project: StoredProjectIdentityV1,
    /// Provider, principal, repository, and config identity.
    pub provider: StoredProviderIdentityV1,
    /// Provider job identifier once submission is confirmed.
    pub provider_job_id: Option<String>,
    /// Provider run identifier once exact run mapping is confirmed.
    pub provider_run_id: Option<String>,
    /// Caller-owned operation identifier from the wire request.
    pub operation_id: String,
    /// Complete validated, declarative, secret-reference-only request.
    pub request: IosDeviceBuildRequest,
    /// Canonical wire request SHA-256, including operation ID.
    pub request_sha256: String,
    /// Versioned semantic retry hash, canonically derived from the request without operation ID.
    pub semantic_retry_sha256: String,
    /// Exact source revision and manifest hash.
    pub source: StoredSourceIdentityV1,
    /// Fixed physical-iPhone target label.
    pub target: String,
    /// Rust/Xcode build profile.
    pub profile: BuildProfile,
    /// Requested signing mode; no signing bytes are stored.
    pub signing_mode: SigningMode,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Submission timestamp once a provider accepted or reconciled the job.
    pub submitted_at_ms: Option<u64>,
    /// Timestamp of this immutable revision in Unix milliseconds.
    pub updated_at_ms: u64,
    /// Detailed local lifecycle state.
    pub state: StoredJobState,
    /// Last provider-confirmed state retained while `state` is `unknown`.
    pub last_confirmed_state: Option<StoredJobState>,
    /// Immutable build outcome once known.
    pub terminal_outcome: Option<StoredBuildOutcome>,
    /// Exact credential-free compile evidence after independent provider verification.
    pub compile_evidence: Option<CompilePhaseEvidence>,
    /// Attempt-scoped proof of protected signing-material cleanup, for signed builds only.
    pub signed_cleanup_evidence: Option<GithubSignedCleanupEvidenceV1>,
    /// Validated artifact records and local paths.
    pub artifacts: Vec<StoredArtifactV1>,
    /// Managed relative log path, if log ingestion has started.
    pub log_location: Option<String>,
    /// Cleanup-policy status.
    pub cleanup_status: StoredCleanupStatus,
    /// Retry parent and children.
    pub retry_lineage: StoredRetryLineageV1,
    /// Durable cancellation status.
    pub cancellation_status: StoredCancellationStatus,
    /// Sanitized typed failure, never raw provider output.
    pub failure: Option<StoredFailureV1>,
    /// Complete secret-free GitHub provider resume checkpoint.
    pub provider_resume: Option<GithubJobResumeV1>,
}

/// Current disk envelope around the stable public logical job payload.
///
/// The predecessor digest starts an integrity-linked append-only chain at the first v2 revision.
/// Privacy and writer authenticity come from the owner-bound private-store boundary, not from a
/// MAC. A legacy v1 prefix remains byte-for-byte immutable and the first v2 successor binds its
/// exact final filename digest.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredJobRevisionV2 {
    schema_version: u32,
    previous_revision_sha256: Option<String>,
    job: StoredJobV1,
}

impl StoredJobV1 {
    /// Validate schema, bounds, identities, request binding, lifecycle invariants, and safe paths.
    ///
    /// # Errors
    ///
    /// Returns a typed store error for any malformed or inconsistent field.
    #[allow(
        clippy::too_many_lines,
        reason = "record validation keeps all durable schema invariants in one audit boundary"
    )]
    pub fn validate(&self) -> Result<(), JobStoreError> {
        if self.schema_version != JOB_STORE_SCHEMA_VERSION {
            return Err(JobStoreError::UnsupportedSchema {
                found: self.schema_version,
                supported: JOB_STORE_SCHEMA_VERSION,
            });
        }
        if !revision_is_supported(self.revision) {
            return Err(invalid_record("revision is outside the supported range"));
        }
        validate_project_root_path(&self.project.canonical_root)?;
        validate_safe_text(
            "project.filesystem_identity",
            &self.project.filesystem_identity,
        )?;
        let project_filesystem_identity = self
            .project
            .filesystem_identity
            .parse::<DirectoryFilesystemIdentity>()
            .map_err(|_| invalid_record("project filesystem identity is invalid"))?;
        if project_filesystem_identity.to_string() != self.project.filesystem_identity {
            return Err(invalid_record(
                "project filesystem identity is not canonical",
            ));
        }
        validate_safe_text(
            "project.application_identifier",
            &self.project.application_identifier,
        )?;
        if self.provider.provider != GITHUB_PROVIDER_ID {
            return Err(invalid_record(
                "stored provider identity is not the supported GitHub provider",
            ));
        }
        validate_sha256(
            "provider.provider_config_sha256",
            &self.provider.provider_config_sha256,
        )?;
        validate_github_principal(
            &self.provider.principal,
            self.provider.execution_repository_id,
        )?;
        validate_github_execution_repository(&self.provider.execution_repository)?;
        if self.provider.execution_repository_id == 0 {
            return Err(invalid_record(
                "GitHub execution repository requires a stable numeric identity",
            ));
        }
        validate_optional_identifier("provider_job_id", self.provider_job_id.as_deref())?;
        validate_optional_identifier("provider_run_id", self.provider_run_id.as_deref())?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("target", &self.target)?;
        if self.target != "iphone" {
            return Err(invalid_record("target must be the physical-iPhone target"));
        }
        self.request
            .validate()
            .map_err(|_| invalid_record("stored request is invalid"))?;
        if self.operation_id != self.request.operation_id {
            return Err(invalid_record("operation ID differs from the request"));
        }
        if self.project.application_identifier != self.request.bundle_identifier {
            return Err(invalid_record(
                "project application identifier differs from the request",
            ));
        }
        if self.profile != self.request.profile || self.signing_mode != self.request.signing.mode {
            return Err(invalid_record(
                "profile or signing mode differs from the request",
            ));
        }
        let actual_request_sha256 = canonical_request_sha256(&self.request)
            .map_err(|_| invalid_record("stored request cannot be hashed canonically"))?;
        if self.request_sha256 != actual_request_sha256 {
            return Err(invalid_record(
                "request SHA-256 differs from canonical bytes",
            ));
        }
        let actual_semantic_retry_sha256 = canonical_retry_template_sha256_v1(&self.request)
            .map_err(|_| invalid_record("stored request cannot be retry-hashed canonically"))?;
        if self.semantic_retry_sha256 != actual_semantic_retry_sha256 {
            return Err(invalid_record(
                "semantic retry SHA-256 differs from the canonical request template",
            ));
        }
        validate_sha256("request_sha256", &self.request_sha256)?;
        validate_sha256("semantic_retry_sha256", &self.semantic_retry_sha256)?;
        validate_sha256("source.manifest_sha256", &self.source.manifest_sha256)?;
        if self.source.manifest_sha256 != self.request.source.sha256
            || self.source.revision != self.request.source_revision
        {
            return Err(invalid_record("source identity differs from the request"));
        }
        if self.updated_at_ms < self.created_at_ms
            || self.submitted_at_ms.is_some_and(|submitted| {
                submitted < self.created_at_ms || submitted > self.updated_at_ms
            })
        {
            return Err(invalid_record("job timestamps are not monotonic"));
        }
        validate_job_state(self)?;
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(JobStoreError::BoundExceeded {
                kind: "artifact records",
                maximum: MAX_ARTIFACTS as u64,
            });
        }
        let mut artifact_ids = BTreeSet::new();
        let mut download_destinations = BTreeSet::new();
        let mut local_file_identities = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_artifact(artifact)?;
            validate_artifact_destination(&self.project.canonical_root, artifact)?;
            if !artifact_ids.insert(artifact.record.artifact_id.as_str()) {
                return Err(invalid_record("artifact identifiers must be unique"));
            }
            if let Some(destination) = &artifact.download_destination
                && !download_destinations.insert(local_path_uniqueness_key(destination))
            {
                return Err(invalid_record(
                    "artifact download destinations must be unique",
                ));
            }
            if let Some(identity) = &artifact.local_file_identity
                && !local_file_identities.insert(identity.as_str())
            {
                return Err(invalid_record(
                    "local artifact file identities must be unique",
                ));
            }
        }
        if self.state.requires_artifacts() && self.artifacts.is_empty() {
            return Err(invalid_record("current state requires artifact records"));
        }
        if matches!(
            self.state,
            StoredJobState::Downloading
                | StoredJobState::Downloaded
                | StoredJobState::Validating
                | StoredJobState::Succeeded
        ) && self
            .artifacts
            .iter()
            .any(|artifact| artifact.download_destination.is_none())
        {
            return Err(invalid_record(
                "artifact download state requires immutable destinations",
            ));
        }
        if matches!(
            self.state,
            StoredJobState::Downloaded | StoredJobState::Validating | StoredJobState::Succeeded
        ) && self
            .artifacts
            .iter()
            .any(|artifact| artifact.local_path.is_none())
        {
            return Err(invalid_record(
                "downloaded state requires local artifact paths",
            ));
        }
        if self.state == StoredJobState::Succeeded
            && self
                .artifacts
                .iter()
                .any(|artifact| !artifact.locally_validated)
        {
            return Err(invalid_record(
                "succeeded state requires local artifact validation",
            ));
        }
        if let Some(location) = &self.log_location {
            validate_managed_relative_path("log_location", location)?;
        }
        validate_retry_lineage(&self.local_job_id, &self.retry_lineage)?;
        if let Some(failure) = &self.failure {
            validate_identifier("failure.code", &failure.code)?;
        }
        if matches!(
            self.state,
            StoredJobState::Failed | StoredJobState::CleanupFailed
        ) && self.failure.is_none()
        {
            return Err(invalid_record(
                "failed state requires a sanitized error code",
            ));
        }
        if self.provider.provider == GITHUB_PROVIDER_ID
            && (self.provider_job_id.is_some() || self.provider_run_id.is_some())
            && self.provider_resume.is_none()
        {
            return Err(invalid_record(
                "allocated GitHub provider identity requires a durable resume checkpoint",
            ));
        }
        if let Some(compile_evidence) = &self.compile_evidence {
            let provider_job_id = self.provider_job_id.as_deref().ok_or_else(|| {
                invalid_record("compile evidence requires an allocated provider job")
            })?;
            validate_github_compile_phase_evidence(
                compile_evidence,
                &self.request,
                provider_job_id,
            )
            .map_err(|_| {
                invalid_record("compile evidence differs from the stored job or source")
            })?;
        }
        if self.signed_cleanup_evidence.is_some() && self.compile_evidence.is_none() {
            return Err(invalid_record(
                "signed cleanup evidence requires verified compile evidence",
            ));
        }
        if let Some(resume) = &self.provider_resume {
            let provider_run_id = github_resume_provider_run_id(resume)?;
            resume
                .encode()
                .map_err(|_| invalid_record("GitHub provider resume checkpoint is invalid"))?;
            validate_github_publication_boundary(resume)?;
            let verified_artifact_state = matches!(
                resume.state,
                JobState::Succeeded
                    | JobState::Cleaning
                    | JobState::Cleaned
                    | JobState::CleanupFailed
            );
            if resume.manifests.is_empty() != resume.compile_evidence.is_none() {
                return Err(invalid_record(
                    "GitHub manifests and compile evidence must bind atomically",
                ));
            }
            if !resume.manifests.is_empty() && !verified_artifact_state {
                return Err(invalid_record(
                    "GitHub verified artifact evidence is attached to a non-artifact state",
                ));
            }
            if self.request.signing.mode == SigningMode::ManualDevelopment
                && verified_artifact_state
                && resume.signed_cleanup_evidence.is_none()
            {
                return Err(invalid_record(
                    "signed GitHub completion requires protected-cleanup evidence",
                ));
            }
            if resume.signed_cleanup_evidence.is_some() && !verified_artifact_state {
                return Err(invalid_record(
                    "signed cleanup evidence is attached to a non-artifact state",
                ));
            }
            if let Some(evidence) = &resume.signed_cleanup_evidence {
                evidence.validate_for_resume(resume).map_err(|_| {
                    invalid_record("signed cleanup evidence differs from the GitHub resume")
                })?;
            }
            validate_github_resume_record_identity(self, resume)?;
            validate_github_artifact_projection(self, resume)?;
            if resume.provider != GITHUB_PROVIDER_ID || self.provider.provider != GITHUB_PROVIDER_ID
            {
                return Err(invalid_record(
                    "provider resume owner differs from the job provider",
                ));
            }
            if resume.provider_config_sha256 != self.provider.provider_config_sha256
                || resume.execution_repository != self.provider.execution_repository
                || resume.execution_repository_id != self.provider.execution_repository_id
                || resume.principal != self.provider.principal
                || resume.operation_id != self.operation_id
                || resume.request != self.request
                || resume.request_sha256 != self.request_sha256
                || Some(resume.source_repository.as_str())
                    != self.request.source_repository.as_deref()
                || Some(resume.source_revision.as_str()) != self.source.revision.as_deref()
                || self.provider_job_id.as_deref() != Some(resume.job_id.as_str())
                || self.provider_run_id.as_deref() != provider_run_id.as_deref()
                || self.compile_evidence.as_ref() != resume.compile_evidence.as_ref()
                || self.signed_cleanup_evidence.as_ref() != resume.signed_cleanup_evidence.as_ref()
            {
                return Err(invalid_record(
                    "GitHub provider resume identity differs from the local job",
                ));
            }
        } else if self.compile_evidence.is_some() || self.signed_cleanup_evidence.is_some() {
            return Err(invalid_record(
                "verified provider evidence requires a durable GitHub resume checkpoint",
            ));
        }
        Ok(())
    }
}

/// Bounded metadata returned by global job listing without retaining full provider checkpoints.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoredJobSummaryV1 {
    /// Stable local job identifier.
    pub local_job_id: LocalJobId,
    /// Latest immutable revision.
    pub revision: u64,
    /// Provider implementation identifier.
    pub provider: String,
    /// Provider job identifier once allocated.
    pub provider_job_id: Option<String>,
    /// Job creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Latest revision timestamp in Unix milliseconds.
    pub updated_at_ms: u64,
    /// Detailed local lifecycle state.
    pub state: StoredJobState,
    /// Last provider-confirmed state while observation is unknown.
    pub last_confirmed_state: Option<StoredJobState>,
    /// Immutable build outcome once known.
    pub terminal_outcome: Option<StoredBuildOutcome>,
    /// Durable cleanup-policy status.
    pub cleanup_status: StoredCleanupStatus,
    /// Durable cancellation status.
    pub cancellation_status: StoredCancellationStatus,
}

impl From<&StoredJobV1> for StoredJobSummaryV1 {
    fn from(record: &StoredJobV1) -> Self {
        Self {
            local_job_id: record.local_job_id.clone(),
            revision: record.revision,
            provider: record.provider.provider.clone(),
            provider_job_id: record.provider_job_id.clone(),
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
            state: record.state,
            last_confirmed_state: record.last_confirmed_state,
            terminal_outcome: record.terminal_outcome,
            cleanup_status: record.cleanup_status,
            cancellation_status: record.cancellation_status,
        }
    }
}

/// Result of one immutable create-only revision publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionReceipt {
    /// Job whose revision was published or already present.
    pub local_job_id: LocalJobId,
    /// Immutable revision number.
    pub revision: u64,
    /// SHA-256 bound into the final filename.
    pub sha256: String,
    /// Whether an identical revision already existed after crash/race reconciliation.
    pub already_present: bool,
}

/// Result of upgrading one legacy latest record through a create-only v2 successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReceipt {
    /// Job whose latest revision was inspected or migrated.
    pub local_job_id: LocalJobId,
    /// Latest immutable revision after migration.
    pub revision: u64,
    /// SHA-256 of the exact persisted envelope bytes.
    pub sha256: String,
    /// Disk schema observed before the operation.
    pub from_schema_version: u32,
    /// Disk schema durably present after the operation.
    pub to_schema_version: u32,
    /// Whether this invocation published the logical no-op v2 successor.
    pub migrated: bool,
    /// Whether the exact v2 revision was already present after reconciliation.
    pub already_present: bool,
}

/// Persistent machine job store rooted outside project source by default.
#[derive(Clone, Debug)]
pub struct JobStore {
    root: PathBuf,
    access: JobStoreAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobStoreAccess {
    ReadWrite,
    ReadOnly,
}

/// Provider checkpoint adapter bound to one generated local job identifier.
#[derive(Clone, Debug)]
pub struct GithubJobStoreCheckpointSink {
    store: JobStore,
    local_job_id: LocalJobId,
}

impl GithubJobStoreCheckpointSink {
    /// Bind GitHub full-checkpoint callbacks to one existing local job.
    #[must_use]
    pub fn new(store: JobStore, local_job_id: LocalJobId) -> Self {
        Self {
            store,
            local_job_id,
        }
    }
}

impl GithubJobCheckpointSink for GithubJobStoreCheckpointSink {
    fn checkpoint(&mut self, resume: &GithubJobResumeV1) -> RemoteBuildResult<()> {
        self.store
            .checkpoint_github_resume(&self.local_job_id, resume)
            .map(|_| ())
            .map_err(|error| job_checkpoint_error(&error))
    }
}

impl JobStore {
    /// Discover `RUSTFERRY_CONFIG_HOME`, otherwise use machine-local platform storage, and create
    /// the private v1 store layout.
    ///
    /// # Errors
    ///
    /// Returns a typed error when no platform config directory exists, the override is invalid,
    /// or the private directory policy cannot be established.
    pub fn open_default() -> Result<Self, JobStoreError> {
        Self::open_at(default_store_root(true)?)
    }

    /// Discover the default store without creating layout, lock, or recovery files.
    ///
    /// An absent store remains absent. Read operations then return an empty list or
    /// [`JobStoreError::JobNotFound`].
    ///
    /// # Errors
    ///
    /// Returns a typed path or private-storage error for an invalid existing layout.
    pub fn open_default_read_only() -> Result<Self, JobStoreError> {
        Self::open_at_read_only(default_store_root(false)?)
    }

    /// Open or create one explicit absolute config root, primarily for isolated tooling/tests.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the path is relative, its parent is absent, or any existing
    /// store component violates the private-directory policy.
    pub fn open_at(root: impl Into<PathBuf>) -> Result<Self, JobStoreError> {
        let root = root.into();
        if !root.is_absolute()
            || root
                .to_str()
                .is_none_or(|value| value.chars().any(char::is_control))
        {
            return Err(JobStoreError::InvalidConfigHome);
        }
        let parent = root.parent().ok_or(JobStoreError::InvalidConfigHome)?;
        if !parent.is_dir() {
            return Err(JobStoreError::InvalidConfigHome);
        }
        let store = Self {
            root,
            access: JobStoreAccess::ReadWrite,
        };
        drop(store.ensure_store_layout()?);
        recover_pending_admin_transactions(&store)?;
        Ok(store)
    }

    /// Open one absolute store path without creating or repairing any filesystem object.
    ///
    /// # Errors
    ///
    /// Returns a typed path or private-storage error when an existing component is linked,
    /// malformed, or violates the platform privacy policy.
    pub fn open_at_read_only(root: impl Into<PathBuf>) -> Result<Self, JobStoreError> {
        let root = root.into();
        if !root.is_absolute()
            || root
                .to_str()
                .is_none_or(|value| value.chars().any(char::is_control))
        {
            return Err(JobStoreError::InvalidConfigHome);
        }
        let store = Self {
            root,
            access: JobStoreAccess::ReadOnly,
        };
        drop(store.open_existing_store_layout()?);
        reject_pending_admin_transactions(&store)?;
        Ok(store)
    }

    /// Return the machine config root containing `jobs/v1`.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the first immutable revision for one local job.
    ///
    /// Identical concurrent/crash-recovery publication is idempotent; different bytes at the same
    /// revision never overwrite the existing record.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, lock, revision-conflict, private-storage, or I/O error.
    pub fn create(&self, record: &StoredJobV1) -> Result<RevisionReceipt, JobStoreError> {
        if record.revision != 1 {
            return Err(JobStoreError::RevisionConflict {
                expected: 1,
                found: record.revision,
            });
        }
        if record.provider_resume.is_some() {
            return Err(invalid_record(
                "the initial job revision cannot contain a provider checkpoint",
            ));
        }
        admin::create_initial_job_serialized(self, record)
    }

    /// Append one validated immutable revision while holding the per-job exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, lock, revision-conflict, private-storage, or I/O error.
    pub fn append(&self, record: &StoredJobV1) -> Result<RevisionReceipt, JobStoreError> {
        self.append_inner(record, false)
    }

    /// Append one logical no-op v2 envelope after a legacy v1 latest revision.
    ///
    /// Existing v1 bytes are never rewritten or removed. Repeated calls durably verify the same
    /// v2 latest revision and return without consuming another revision.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, bound, lock, validation, publication, or storage error.
    pub fn migrate_job(
        &self,
        local_job_id: &LocalJobId,
    ) -> Result<MigrationReceipt, JobStoreError> {
        self.ensure_writable()?;
        let locked = self.lock_job(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: local_job_id.clone(),
        })?;
        let latest_decoded = read_decoded_revision(&latest.path, latest.revision, &latest.sha256)?;
        if latest_decoded.record.local_job_id != *local_job_id {
            return Err(JobStoreError::MalformedRevision {
                reason: "revision local job ID differs from its job directory",
            });
        }
        let previous = latest_decoded.record;
        if latest_decoded.schema_version == JOB_REVISION_SCHEMA_VERSION {
            ensure_revision_durable(&locked, latest, &previous)?;
            return Ok(MigrationReceipt {
                local_job_id: local_job_id.clone(),
                revision: latest.revision,
                sha256: latest.sha256.clone(),
                from_schema_version: JOB_REVISION_SCHEMA_VERSION,
                to_schema_version: JOB_REVISION_SCHEMA_VERSION,
                migrated: false,
                already_present: true,
            });
        }
        let revision = previous
            .revision
            .checked_add(1)
            .filter(|revision| revision_is_supported(*revision))
            .ok_or(JobStoreError::BoundExceeded {
                kind: "job revisions required for migration",
                maximum: MAX_REVISIONS_PER_JOB as u64,
            })?;
        let mut migrated = previous.clone();
        migrated.revision = revision;
        migrated.validate()?;
        validate_regular_successor(&previous, &migrated)?;
        let bytes = encode_revision_v2(&migrated, Some(&latest.sha256))?;
        let sha256 = sha256_hex(&bytes);
        let final_path = locked
            .revisions
            .join(revision_filename(migrated.revision, &sha256));
        let already_present =
            publish_revision_with_reconciliation(&locked, &final_path, &migrated, &bytes, &sha256)?;
        Ok(MigrationReceipt {
            local_job_id: local_job_id.clone(),
            revision: migrated.revision,
            sha256,
            from_schema_version: LEGACY_JOB_REVISION_SCHEMA_VERSION,
            to_schema_version: JOB_REVISION_SCHEMA_VERSION,
            migrated: true,
            already_present,
        })
    }

    /// Build and publish the next full revision under one exclusive per-job lock.
    ///
    /// The callback must only derive local state. It must not call a provider because provider
    /// checkpoint callbacks may already execute while provider state is locked.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, callback, validation, transition, publication, or storage error.
    pub fn update(
        &self,
        local_job_id: &LocalJobId,
        update: impl FnOnce(&StoredJobV1) -> Result<StoredJobV1, JobStoreError>,
    ) -> Result<RevisionReceipt, JobStoreError> {
        self.update_optional(local_job_id, |previous| update(previous).map(Some))?
            .ok_or_else(|| invalid_record("job update unexpectedly produced no revision"))
    }

    /// Atomically persist one complete typed GitHub resume checkpoint.
    ///
    /// An identical callback is a durable no-op and does not consume another full revision.
    ///
    /// # Errors
    ///
    /// Returns a typed identity, regression, lock, publication, or storage error.
    pub fn checkpoint_github_resume(
        &self,
        local_job_id: &LocalJobId,
        resume: &GithubJobResumeV1,
    ) -> Result<Option<RevisionReceipt>, JobStoreError> {
        self.ensure_writable()?;
        resume
            .encode()
            .map_err(|_| invalid_record("GitHub provider resume checkpoint is invalid"))?;
        self.update_optional(local_job_id, |previous| {
            validate_github_resume_projection_identity(previous, resume)?;
            if previous.provider_resume.as_ref() == Some(resume) {
                return Ok(None);
            }
            project_github_resume(previous, resume).map(Some)
        })
    }

    fn update_optional(
        &self,
        local_job_id: &LocalJobId,
        update: impl FnOnce(&StoredJobV1) -> Result<Option<StoredJobV1>, JobStoreError>,
    ) -> Result<Option<RevisionReceipt>, JobStoreError> {
        self.ensure_writable()?;
        let locked = self.lock_job_for_short_write(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: local_job_id.clone(),
        })?;
        let previous =
            read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id)?;
        let Some(next) = update(&previous)? else {
            ensure_revision_durable(&locked, latest, &previous)?;
            return Ok(None);
        };
        next.validate()?;
        if next.local_job_id != *local_job_id
            || next.revision != previous.revision.saturating_add(1)
        {
            return Err(JobStoreError::RevisionConflict {
                expected: previous.revision.saturating_add(1),
                found: next.revision,
            });
        }
        validate_regular_successor(&previous, &next)?;
        let bytes = encode_revision_v2(&next, Some(&latest.sha256))?;
        let sha256 = sha256_hex(&bytes);
        let final_path = locked
            .revisions
            .join(revision_filename(next.revision, &sha256));
        let already_present =
            publish_revision_with_reconciliation(&locked, &final_path, &next, &bytes, &sha256)?;
        Ok(Some(RevisionReceipt {
            local_job_id: local_job_id.clone(),
            revision: next.revision,
            sha256,
            already_present,
        }))
    }

    /// Read and validate the deterministic latest immutable revision.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, lock, malformed-record, bound, private-storage, or I/O error.
    pub fn latest(&self, local_job_id: &LocalJobId) -> Result<StoredJobV1, JobStoreError> {
        if self.access == JobStoreAccess::ReadOnly {
            let opened = self.open_read_only_job(local_job_id)?;
            let revisions = scan_revision_files(&opened.revisions)?;
            let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
                local_job_id: local_job_id.clone(),
            })?;
            return read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id);
        }
        let locked = self.lock_job(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: local_job_id.clone(),
        })?;
        read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id)
    }

    /// Read one exact immutable revision.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, lock, malformed-record, bound, private-storage, or I/O error.
    pub fn revision(
        &self,
        local_job_id: &LocalJobId,
        revision: u64,
    ) -> Result<StoredJobV1, JobStoreError> {
        if self.access == JobStoreAccess::ReadOnly {
            let opened = self.open_read_only_job(local_job_id)?;
            let revisions = scan_revision_files(&opened.revisions)?;
            let entry = revisions
                .iter()
                .find(|entry| entry.revision == revision)
                .ok_or_else(|| JobStoreError::RevisionNotFound {
                    local_job_id: local_job_id.clone(),
                    revision,
                })?;
            return read_job_revision(&entry.path, entry.revision, &entry.sha256, local_job_id);
        }
        let locked = self.lock_job(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        let entry = revisions
            .iter()
            .find(|entry| entry.revision == revision)
            .ok_or_else(|| JobStoreError::RevisionNotFound {
                local_job_id: local_job_id.clone(),
                revision,
            })?;
        read_job_revision(&entry.path, entry.revision, &entry.sha256, local_job_id)
    }

    /// List deterministic latest summaries, ordered newest first then by local job ID.
    ///
    /// Full provider checkpoints are validated one at a time and discarded, so a global list does
    /// not retain up to 10,000 large resume snapshots in memory.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, malformed-directory, lock, private-storage, or record error.
    pub fn list_latest(&self, limit: usize) -> Result<Vec<StoredJobSummaryV1>, JobStoreError> {
        if limit == 0 || limit > MAX_LISTED_JOBS {
            return Err(JobStoreError::BoundExceeded {
                kind: "jobs list limit",
                maximum: MAX_LISTED_JOBS as u64,
            });
        }
        if self.access == JobStoreAccess::ReadWrite {
            drop(self.ensure_store_layout()?);
        }
        let Some(layout) = self.open_existing_store_layout()? else {
            return Ok(Vec::new());
        };
        let root = self.version_root();
        let mut identifiers = Vec::new();
        for entry in
            fs::read_dir(&root).map_err(|source| io_error("read jobs directory", source))?
        {
            if identifiers.len() >= MAX_STORED_JOBS {
                return Err(JobStoreError::BoundExceeded {
                    kind: "stored jobs",
                    maximum: MAX_STORED_JOBS as u64,
                });
            }
            let entry = entry.map_err(|source| io_error("read job directory entry", source))?;
            let name =
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| JobStoreError::MalformedLayout {
                        reason: "job directory name is not UTF-8",
                    })?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect job directory entry", source))?;
            if admin_store_entry_is_reserved(&name) {
                validate_admin_store_entry(&name, &metadata)?;
                continue;
            }
            let local_job_id = LocalJobId::new(name)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(JobStoreError::MalformedLayout {
                    reason: "job entry is linked or not a directory",
                });
            }
            identifiers.push(local_job_id);
        }
        identifiers.sort();
        drop(layout);
        let mut summaries = BTreeMap::new();
        for identifier in &identifiers {
            match self.latest(identifier) {
                Ok(record) => {
                    let summary = StoredJobSummaryV1::from(&record);
                    summaries.insert(
                        (Reverse(summary.updated_at_ms), summary.local_job_id.clone()),
                        summary,
                    );
                    if summaries.len() > limit {
                        let _ = summaries.pop_last();
                    }
                }
                Err(JobStoreError::JobNotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(summaries.into_values().collect())
    }

    /// List latest jobs owned by one exact canonical project-root and filesystem-identity pair.
    ///
    /// This read-only view never creates or repairs store state. Every selected record is read
    /// under a shared per-job lock, even when this handle was opened for read-write operations.
    ///
    /// # Errors
    ///
    /// Returns a typed selector, bound, lock, malformed-directory, private-storage, or record
    /// error.
    pub fn list_latest_for_project(
        &self,
        canonical_root: &str,
        filesystem_identity: &str,
        limit: usize,
    ) -> Result<Vec<StoredJobSummaryV1>, JobStoreError> {
        validate_project_selector(canonical_root, filesystem_identity)?;
        if limit == 0 || limit > MAX_LISTED_JOBS {
            return Err(JobStoreError::BoundExceeded {
                kind: "jobs list limit",
                maximum: MAX_LISTED_JOBS as u64,
            });
        }
        reject_pending_admin_transactions(self)?;
        let identifiers = self.scan_job_identifiers_read_only()?;
        let mut summaries = BTreeMap::new();
        for identifier in &identifiers {
            match self.read_latest_shared(identifier) {
                Ok(record)
                    if project_selector_matches(
                        &record.project,
                        canonical_root,
                        filesystem_identity,
                    ) =>
                {
                    let summary = StoredJobSummaryV1::from(&record);
                    summaries.insert(
                        (Reverse(summary.updated_at_ms), summary.local_job_id.clone()),
                        summary,
                    );
                    if summaries.len() > limit {
                        let _ = summaries.pop_last();
                    }
                }
                Ok(_) | Err(JobStoreError::JobNotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(summaries.into_values().collect())
    }

    /// Read one latest job only when it belongs to the exact canonical project selector.
    ///
    /// A project mismatch is reported as not found so callers cannot accidentally cross a
    /// workspace boundary. The record is read under a shared per-job lock.
    ///
    /// # Errors
    ///
    /// Returns a typed selector, not-found, lock, malformed-record, bound, or storage error.
    pub fn latest_for_project(
        &self,
        local_job_id: &LocalJobId,
        canonical_root: &str,
        filesystem_identity: &str,
    ) -> Result<StoredJobV1, JobStoreError> {
        validate_project_selector(canonical_root, filesystem_identity)?;
        let record = self.read_latest_shared(local_job_id)?;
        if !project_selector_matches(&record.project, canonical_root, filesystem_identity) {
            return Err(JobStoreError::JobNotFound {
                local_job_id: local_job_id.clone(),
            });
        }
        Ok(record)
    }

    fn read_latest_shared(&self, local_job_id: &LocalJobId) -> Result<StoredJobV1, JobStoreError> {
        let opened = self.open_read_only_job(local_job_id)?;
        let revisions = scan_revision_files(&opened.revisions)?;
        let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: local_job_id.clone(),
        })?;
        read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id)
    }

    fn scan_job_identifiers_read_only(&self) -> Result<Vec<LocalJobId>, JobStoreError> {
        let Some(layout) = self.open_existing_store_layout()? else {
            return Ok(Vec::new());
        };
        let mut identifiers = Vec::new();
        for entry in fs::read_dir(self.version_root())
            .map_err(|source| io_error("read project-filtered jobs directory", source))?
        {
            if identifiers.len() >= MAX_STORED_JOBS {
                return Err(JobStoreError::BoundExceeded {
                    kind: "stored jobs",
                    maximum: MAX_STORED_JOBS as u64,
                });
            }
            let entry = entry.map_err(|source| io_error("read job directory entry", source))?;
            let name =
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| JobStoreError::MalformedLayout {
                        reason: "job directory name is not UTF-8",
                    })?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect job directory entry", source))?;
            if admin_store_entry_is_reserved(&name) {
                validate_admin_store_entry(&name, &metadata)?;
                continue;
            }
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(JobStoreError::MalformedLayout {
                    reason: "job entry is linked or not a directory",
                });
            }
            identifiers.push(LocalJobId::new(name)?);
        }
        drop(layout);
        identifiers.sort();
        Ok(identifiers)
    }

    fn append_inner(
        &self,
        record: &StoredJobV1,
        creating: bool,
    ) -> Result<RevisionReceipt, JobStoreError> {
        self.ensure_writable()?;
        record.validate()?;
        if record.revision == 1 {
            validate_initial_job_revision(record)?;
        }
        let locked = self.lock_job_for_short_write(&record.local_job_id, creating)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        if let Some(latest) = revisions.last() {
            if record.revision == latest.revision {
                let existing = read_job_revision(
                    &latest.path,
                    latest.revision,
                    &latest.sha256,
                    &record.local_job_id,
                )?;
                if existing == *record {
                    ensure_revision_durable(&locked, latest, &existing)?;
                    return Ok(RevisionReceipt {
                        local_job_id: record.local_job_id.clone(),
                        revision: record.revision,
                        sha256: latest.sha256.clone(),
                        already_present: true,
                    });
                }
                return Err(JobStoreError::RevisionConflict {
                    expected: latest.revision.saturating_add(1),
                    found: record.revision,
                });
            }
            let expected = latest.revision.saturating_add(1);
            if record.revision != expected || creating {
                return Err(JobStoreError::RevisionConflict {
                    expected,
                    found: record.revision,
                });
            }
            let previous = read_job_revision(
                &latest.path,
                latest.revision,
                &latest.sha256,
                &record.local_job_id,
            )?;
            validate_regular_successor(&previous, record)?;
        } else {
            if !creating {
                return Err(invalid_record(
                    "append cannot publish the first revision of an empty job chain",
                ));
            }
            if record.revision != 1 {
                return Err(JobStoreError::RevisionConflict {
                    expected: 1,
                    found: record.revision,
                });
            }
        }
        let previous_sha256 = revisions.last().map(|entry| entry.sha256.as_str());
        let bytes = encode_revision_v2(record, previous_sha256)?;
        let sha256 = sha256_hex(&bytes);
        let filename = revision_filename(record.revision, &sha256);
        let final_path = locked.revisions.join(filename);
        let already_present =
            publish_revision_with_reconciliation(&locked, &final_path, record, &bytes, &sha256)?;
        Ok(RevisionReceipt {
            local_job_id: record.local_job_id.clone(),
            revision: record.revision,
            sha256,
            already_present,
        })
    }

    fn ensure_store_layout(&self) -> Result<ExistingStoreLayout, JobStoreError> {
        self.ensure_writable()?;
        let parent_path = self.root.parent().ok_or(JobStoreError::InvalidConfigHome)?;
        let parent = RetainedDirectoryIdentity::open(parent_path)
            .map_err(|error| retained_directory_error("retain job-store root parent", &error))?;
        let root = ensure_private_directory(&self.root)?;
        let jobs = self.root.join(JOBS_DIRECTORY);
        let jobs_guard = ensure_private_directory(&jobs)?;
        let version_path = jobs.join(VERSION_DIRECTORY);
        let version = ensure_private_directory(&version_path)?;
        sync_directory(&version_path, &version)?;
        sync_directory(&jobs, &jobs_guard)?;
        sync_directory(&self.root, &root)?;
        sync_retained_directory(&parent, parent_path, "sync job-store root parent metadata")?;
        Ok(ExistingStoreLayout {
            guards: vec![root, jobs_guard, version],
        })
    }

    fn ensure_writable(&self) -> Result<(), JobStoreError> {
        if self.access == JobStoreAccess::ReadOnly {
            Err(JobStoreError::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn open_existing_store_layout(&self) -> Result<Option<ExistingStoreLayout>, JobStoreError> {
        let Some(root) = open_private_directory_if_present(
            &self.root,
            "store root is linked or not a directory",
        )?
        else {
            return Ok(None);
        };
        let jobs_path = self.root.join(JOBS_DIRECTORY);
        let Some(jobs) = open_private_directory_if_present(
            &jobs_path,
            "jobs entry is linked or not a directory",
        )?
        else {
            return Ok(None);
        };
        let version_path = jobs_path.join(VERSION_DIRECTORY);
        let Some(version) = open_private_directory_if_present(
            &version_path,
            "store version entry is linked or not a directory",
        )?
        else {
            return Ok(None);
        };
        Ok(Some(ExistingStoreLayout {
            guards: vec![root, jobs, version],
        }))
    }

    fn open_read_only_job(&self, local_job_id: &LocalJobId) -> Result<ReadOnlyJob, JobStoreError> {
        reject_pending_transaction_for_job(self, local_job_id)?;
        await_pending_transaction_lock_test_control(
            local_job_id,
            PendingTransactionLockTestMode::Shared,
        );
        let opened = self.open_read_only_job_unchecked(local_job_id)?;
        reject_pending_transaction_for_job(self, local_job_id)?;
        Ok(opened)
    }

    fn open_read_only_job_unchecked(
        &self,
        local_job_id: &LocalJobId,
    ) -> Result<ReadOnlyJob, JobStoreError> {
        let job = self.version_root().join(local_job_id.as_str());
        let lock_path = job.join(LOCK_FILE);
        let Some(lock) = open_existing_private_lock(&lock_path)? else {
            return Err(self.missing_lock_error(local_job_id)?);
        };
        fs2::FileExt::try_lock_shared(&lock).map_err(|_| JobStoreError::JobBusy {
            local_job_id: local_job_id.clone(),
        })?;
        let layout = self.open_existing_job_layout(local_job_id)?;
        verify_private_lock_identity(&lock, &lock_path)?;
        Ok(ReadOnlyJob {
            lock,
            _guards: layout.guards,
            _revisions_guard: layout.revisions_guard,
            revisions: layout.revisions,
        })
    }

    fn version_root(&self) -> PathBuf {
        self.root.join(JOBS_DIRECTORY).join(VERSION_DIRECTORY)
    }

    fn lock_job(
        &self,
        local_job_id: &LocalJobId,
        create_layout: bool,
    ) -> Result<LockedJob, JobStoreError> {
        reject_pending_transaction_for_job(self, local_job_id)?;
        await_pending_transaction_lock_test_control(
            local_job_id,
            if create_layout {
                PendingTransactionLockTestMode::ExclusiveCreating
            } else {
                PendingTransactionLockTestMode::ExclusiveExisting
            },
        );
        let locked = self.lock_job_unchecked(local_job_id, create_layout)?;
        reject_pending_transaction_for_job(self, local_job_id)?;
        if create_layout {
            admin::reject_tombstoned_local_job_id(self, local_job_id)?;
        }
        Ok(locked)
    }

    fn lock_job_for_short_write(
        &self,
        local_job_id: &LocalJobId,
        create_layout: bool,
    ) -> Result<LockedJob, JobStoreError> {
        for attempt in 0..4_096 {
            match self.lock_job(local_job_id, create_layout) {
                Ok(locked) => return Ok(locked),
                Err(JobStoreError::JobBusy { .. }) if attempt < 4_095 => {
                    std::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        Err(JobStoreError::JobBusy {
            local_job_id: local_job_id.clone(),
        })
    }

    fn lock_job_unchecked(
        &self,
        local_job_id: &LocalJobId,
        create_layout: bool,
    ) -> Result<LockedJob, JobStoreError> {
        let job = self.version_root().join(local_job_id.as_str());
        let revisions = job.join(REVISIONS_DIRECTORY);
        let lock_path = job.join(LOCK_FILE);
        if create_layout {
            drop(self.ensure_store_layout()?);
        }
        let lock = match open_existing_private_lock(&lock_path)? {
            Some(lock) => lock,
            None if create_layout => {
                admin::reject_tombstoned_local_job_id(self, local_job_id)?;
                let job_guard = ensure_private_directory(&job)?;
                let revisions_guard = ensure_private_directory(&revisions)?;
                let lock = open_or_create_private_lock(&lock_path)?;
                drop(revisions_guard);
                drop(job_guard);
                lock
            }
            None => return Err(self.missing_lock_error(local_job_id)?),
        };
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| JobStoreError::JobBusy {
            local_job_id: local_job_id.clone(),
        })?;
        let layout = self.open_existing_job_layout(local_job_id)?;
        verify_private_lock_identity(&lock, &lock_path)?;
        if create_layout {
            sync_created_job_layout(self, &job, &lock, &layout)?;
        }
        Ok(LockedJob {
            lock,
            guards: layout.guards,
            revisions_guard: layout.revisions_guard,
            revisions: layout.revisions,
        })
    }

    fn open_existing_job_layout(
        &self,
        local_job_id: &LocalJobId,
    ) -> Result<ExistingJobLayout, JobStoreError> {
        let Some(layout) = self.open_existing_store_layout()? else {
            return Err(JobStoreError::JobNotFound {
                local_job_id: local_job_id.clone(),
            });
        };
        let job = self.version_root().join(local_job_id.as_str());
        let Some(job_guard) =
            open_private_directory_if_present(&job, "job entry is linked or not a directory")?
        else {
            return Err(JobStoreError::JobNotFound {
                local_job_id: local_job_id.clone(),
            });
        };
        let revisions = job.join(REVISIONS_DIRECTORY);
        let Some(revisions_guard) = open_private_directory_if_present(
            &revisions,
            "job revisions entry is linked or not a directory",
        )?
        else {
            let empty = fs::read_dir(&job)
                .map_err(|source| io_error("read incomplete job directory", source))?
                .next()
                .transpose()
                .map_err(|source| io_error("read incomplete job entry", source))?
                .is_none();
            if empty {
                return Err(JobStoreError::JobNotFound {
                    local_job_id: local_job_id.clone(),
                });
            }
            return Err(JobStoreError::MalformedLayout {
                reason: "job revisions directory is missing",
            });
        };
        validate_job_directory_entries(&job)?;
        let mut guards = layout.guards;
        guards.push(job_guard);
        Ok(ExistingJobLayout {
            guards,
            revisions_guard,
            revisions,
        })
    }

    fn missing_lock_error(
        &self,
        local_job_id: &LocalJobId,
    ) -> Result<JobStoreError, JobStoreError> {
        let layout = self.open_existing_job_layout(local_job_id)?;
        let lock_path = self
            .version_root()
            .join(local_job_id.as_str())
            .join(LOCK_FILE);
        if open_existing_private_lock(&lock_path)?.is_some() {
            return Ok(JobStoreError::JobBusy {
                local_job_id: local_job_id.clone(),
            });
        }
        let revisions_empty = fs::read_dir(&layout.revisions)
            .map_err(|source| io_error("read unlocked revisions directory", source))?
            .next()
            .transpose()
            .map_err(|source| io_error("read unlocked revision entry", source))?
            .is_none();
        if open_existing_private_lock(&lock_path)?.is_some() {
            return Ok(JobStoreError::JobBusy {
                local_job_id: local_job_id.clone(),
            });
        }
        if revisions_empty {
            Ok(JobStoreError::JobNotFound {
                local_job_id: local_job_id.clone(),
            })
        } else {
            Ok(JobStoreError::MalformedLayout {
                reason: "committed job revisions are missing their lock file",
            })
        }
    }
}

fn sync_created_job_layout(
    store: &JobStore,
    job: &Path,
    lock: &File,
    layout: &ExistingJobLayout,
) -> Result<(), JobStoreError> {
    lock.sync_all()
        .map_err(|source| io_error("sync private job lock", source))?;
    sync_directory(&layout.revisions, &layout.revisions_guard)?;
    let jobs = store.root.join(JOBS_DIRECTORY);
    let version = jobs.join(VERSION_DIRECTORY);
    let paths = [store.root.as_path(), jobs.as_path(), version.as_path(), job];
    if layout.guards.len() != paths.len() {
        return Err(JobStoreError::MalformedLayout {
            reason: "job layout omitted a retained ancestor directory guard",
        });
    }
    for (path, guard) in paths.iter().zip(&layout.guards).rev() {
        sync_directory(path, guard)?;
    }
    Ok(())
}

fn validate_job_directory_entries(job: &Path) -> Result<(), JobStoreError> {
    let mut saw_revisions = false;
    let mut saw_lock = false;
    let mut saw_operation_lock = false;
    let mut saw_events = false;
    let mut saw_artifact_removals = false;
    for entry in fs::read_dir(job).map_err(|source| io_error("read job layout", source))? {
        let entry = entry.map_err(|source| io_error("read job layout entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "job layout entry name is not UTF-8",
            })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect job layout entry", source))?;
        match name.as_str() {
            REVISIONS_DIRECTORY if !saw_revisions && metadata.is_dir() => saw_revisions = true,
            LOCK_FILE if !saw_lock && metadata.is_file() => saw_lock = true,
            "operation.lock" if !saw_operation_lock && metadata.is_file() => {
                saw_operation_lock = true;
            }
            "events" if !saw_events && metadata.is_dir() => saw_events = true,
            "artifact-removals" if !saw_artifact_removals && metadata.is_dir() => {
                saw_artifact_removals = true;
            }
            _ => {
                return Err(JobStoreError::MalformedLayout {
                    reason: "job directory contains an unexpected or linked entry",
                });
            }
        }
        if metadata.file_type().is_symlink() {
            return Err(JobStoreError::MalformedLayout {
                reason: "job directory contains an unexpected or linked entry",
            });
        }
    }
    if !saw_revisions {
        return Err(JobStoreError::MalformedLayout {
            reason: "job revisions directory is missing",
        });
    }
    Ok(())
}

fn publish_revision_with_reconciliation(
    locked: &LockedJob,
    final_path: &Path,
    record: &StoredJobV1,
    bytes: &[u8],
    sha256: &str,
) -> Result<bool, JobStoreError> {
    match publish_create_only(locked, final_path, bytes) {
        Ok(()) => Ok(false),
        Err(PublicationFailure {
            error: error @ JobStoreError::CommitUncertain { .. },
            retained_file,
        }) => {
            if let Some(retained_file) = retained_file {
                return reconcile_retained_publication(
                    locked,
                    final_path,
                    record,
                    bytes,
                    sha256,
                    retained_file,
                    error,
                );
            }
            recover_revision_staging(locked)?;
            let revisions = scan_revision_files(&locked.revisions)?;
            let Some(latest) = revisions.last() else {
                return Err(error);
            };
            if latest.revision != record.revision
                || latest.sha256 != sha256
                || latest.path != final_path
            {
                return Err(error);
            }
            let existing = read_decoded_revision(&latest.path, latest.revision, &latest.sha256)?;
            if existing.record != *record
                || existing.schema_version != JOB_REVISION_SCHEMA_VERSION
                || existing.bytes != bytes
            {
                return Err(error);
            }
            if sync_directory(&locked.revisions, &locked.revisions_guard).is_err() {
                return Err(error);
            }
            Ok(true)
        }
        Err(failure) => Err(failure.error),
    }
}

fn ensure_revision_durable(
    locked: &LockedJob,
    entry: &RevisionEntry,
    record: &StoredJobV1,
) -> Result<(), JobStoreError> {
    let decoded = read_decoded_revision(&entry.path, entry.revision, &entry.sha256)?;
    let expected = decoded.bytes;
    if entry.revision != record.revision
        || decoded.record != *record
        || entry.sha256 != sha256_hex(&expected)
        || entry.path.parent() != Some(locked.revisions.as_path())
    {
        return Err(JobStoreError::MalformedRevision {
            reason: "existing revision identity differs from the idempotent record",
        });
    }
    let mut file = open_private_revision_file_for_sync(&entry.path)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect revision durability handle", source))?;
    if metadata.len() != expected.len() as u64 || metadata.len() > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::MalformedRevision {
            reason: "existing revision size differs from the idempotent record",
        });
    }
    let mut actual = Vec::with_capacity(expected.len());
    (&mut file)
        .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|source| io_error("read revision durability handle", source))?;
    verify_open_private_revision_file(&file, &entry.path)?;
    if actual != expected || sha256_hex(&actual) != entry.sha256 {
        return Err(JobStoreError::MalformedRevision {
            reason: "existing revision bytes differ from the idempotent record",
        });
    }
    publication_checkpoint(&entry.path, PublicationCheckpoint::IdempotentFinalSync)?;
    if file.sync_all().is_err()
        || verify_open_private_revision_file(&file, &entry.path).is_err()
        || sync_directory(&locked.revisions, &locked.revisions_guard).is_err()
    {
        return Err(JobStoreError::CommitUncertain {
            reason: "an existing immutable revision could not be durably synchronized",
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact reconciliation names every immutable publication binding"
)]
fn reconcile_retained_publication(
    locked: &LockedJob,
    final_path: &Path,
    record: &StoredJobV1,
    bytes: &[u8],
    sha256: &str,
    mut retained_file: File,
    uncertain: JobStoreError,
) -> Result<bool, JobStoreError> {
    let metadata = retained_file
        .metadata()
        .map_err(|source| io_error("inspect retained uncertain revision", source))?;
    if metadata.len() != bytes.len() as u64
        || retained_file.rewind().is_err()
        || verify_open_private_revision_file(&retained_file, final_path).is_err()
    {
        return Err(uncertain);
    }
    let mut actual = Vec::with_capacity(bytes.len());
    if (&mut retained_file)
        .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .is_err()
        || actual != bytes
        || sha256_hex(&actual) != sha256
    {
        return Err(uncertain);
    }
    let revisions =
        scan_revision_files_with_retained(&locked.revisions, Some(final_path), Some(record))?;
    let Some(latest) = revisions.last() else {
        return Err(uncertain);
    };
    let Ok(previous) = previous_revision_sha256(&locked.revisions, record.revision) else {
        return Err(uncertain);
    };
    let Ok(decoded) = decode_revision_bytes(&actual, record.revision, previous.as_deref()) else {
        return Err(uncertain);
    };
    if latest.revision != record.revision
        || latest.sha256 != sha256
        || latest.path != final_path
        || decoded.schema_version != JOB_REVISION_SCHEMA_VERSION
        || decoded.record != *record
        || decoded.bytes != actual
    {
        return Err(uncertain);
    }
    if retained_file.sync_all().is_err()
        || sync_directory(&locked.revisions, &locked.revisions_guard).is_err()
    {
        return Err(uncertain);
    }
    Ok(true)
}

/// Typed failure from local job persistence or validation.
#[derive(Debug, Error)]
pub enum JobStoreError {
    /// Neither an override nor a platform config directory is available.
    #[error("a machine configuration directory is unavailable")]
    ConfigHomeUnavailable,
    /// An explicit config home is empty, relative, or has no existing parent.
    #[error("the RustFerry config home must be a non-empty absolute path with an existing parent")]
    InvalidConfigHome,
    /// A mutating API was called on a store opened for dry-run inspection.
    #[error("job store was opened read-only")]
    ReadOnly,
    /// A path-safe identifier is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidIdentifier {
        /// Field name.
        field: &'static str,
        /// Stable validation reason without echoing the value.
        reason: &'static str,
    },
    /// A decoded record violates a schema invariant.
    #[error("invalid job record: {reason}")]
    InvalidRecord {
        /// Stable validation reason without raw provider content.
        reason: &'static str,
    },
    /// A future or otherwise unsupported store schema was encountered.
    #[error("unsupported job schema {found}; this build supports {supported}")]
    UnsupportedSchema {
        /// Encountered schema version.
        found: u32,
        /// Highest supported schema version.
        supported: u32,
    },
    /// A bounded collection or file exceeds its hard limit.
    #[error("{kind} exceeds the supported maximum of {maximum}")]
    BoundExceeded {
        /// Bounded data kind.
        kind: &'static str,
        /// Maximum count or bytes.
        maximum: u64,
    },
    /// No persistent record exists for the local job ID.
    #[error("local job `{}` was not found", local_job_id.as_str())]
    JobNotFound {
        /// Missing local job identifier.
        local_job_id: LocalJobId,
    },
    /// One exact immutable revision does not exist.
    #[error("revision {revision} for local job `{}` was not found", local_job_id.as_str())]
    RevisionNotFound {
        /// Local job identifier.
        local_job_id: LocalJobId,
        /// Missing revision.
        revision: u64,
    },
    /// Another process holds the per-job lock.
    #[error("local job `{}` is busy", local_job_id.as_str())]
    JobBusy {
        /// Locked local job identifier.
        local_job_id: LocalJobId,
    },
    /// A bare provider artifact ID exists under more than one local job.
    #[error("provider artifact `{provider_artifact_id}` is ambiguous; use a local job ID")]
    ArtifactReferenceAmbiguous {
        /// Safe validated provider artifact identifier.
        provider_artifact_id: String,
    },
    /// No active job owns the requested provider artifact identifier.
    #[error("provider artifact `{provider_artifact_id}` was not found")]
    ArtifactNotFound {
        /// Safe validated provider artifact identifier.
        provider_artifact_id: String,
    },
    /// This platform cannot prove that deletion targets the retained artifact inode.
    #[error("exact managed artifact removal is unsupported on this platform")]
    ArtifactRemovalUnsupported,
    /// The caller supplied a stale or skipped revision.
    #[error("job revision conflict: expected {expected}, found {found}")]
    RevisionConflict {
        /// Required next revision.
        expected: u64,
        /// Caller-supplied revision.
        found: u64,
    },
    /// The append-only layout or revision filename is malformed.
    #[error("malformed job store layout: {reason}")]
    MalformedLayout {
        /// Stable reason without untrusted path text.
        reason: &'static str,
    },
    /// Immutable revision bytes or their filename digest are malformed.
    #[error("malformed job revision: {reason}")]
    MalformedRevision {
        /// Stable reason without raw record bytes.
        reason: &'static str,
    },
    /// A crash residue cannot be safely reconciled without inspection.
    #[error("job store recovery is required: {reason}")]
    RecoveryRequired {
        /// Stable reason without an untrusted machine path.
        reason: &'static str,
    },
    /// Windows or Unix private-storage policy rejected an object.
    #[error("private job storage policy failed during {operation}: {message}")]
    Security {
        /// Stable operation label.
        operation: &'static str,
        /// Sanitized platform policy error.
        message: String,
    },
    /// JSON encoding failed before publication.
    #[error("failed to {operation}: {source}")]
    Serialization {
        /// Stable operation label.
        operation: &'static str,
        /// Serialization failure.
        #[source]
        source: serde_json::Error,
    },
    /// Filesystem operation failed without exposing record contents.
    #[error("failed to {operation}: {source}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// A final hard link may exist but could not be fully verified.
    #[error("immutable job revision publication is uncertain: {reason}")]
    CommitUncertain {
        /// Stable reason without a machine path.
        reason: &'static str,
    },
}

struct LockedJob {
    lock: File,
    guards: Vec<File>,
    revisions_guard: File,
    revisions: PathBuf,
}

struct ExistingStoreLayout {
    guards: Vec<File>,
}

struct ExistingJobLayout {
    guards: Vec<File>,
    revisions_guard: File,
    revisions: PathBuf,
}

struct ReadOnlyJob {
    lock: File,
    _guards: Vec<File>,
    _revisions_guard: File,
    revisions: PathBuf,
}

struct RevisionEntry {
    revision: u64,
    sha256: String,
    path: PathBuf,
}

struct DecodedRevision {
    record: StoredJobV1,
    schema_version: u32,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct PublicationFailure {
    error: JobStoreError,
    retained_file: Option<File>,
}

impl From<JobStoreError> for PublicationFailure {
    fn from(error: JobStoreError) -> Self {
        Self {
            error,
            retained_file: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationCheckpoint {
    BeforeFinalSync,
    IdempotentFinalSync,
    FinalLinked,
    StagingRemoved,
    FinalReadBack,
}

#[cfg(test)]
#[derive(Clone)]
enum PublicationTestAction {
    Fail,
    Pause {
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    },
}

#[cfg(test)]
#[derive(Clone)]
struct PublicationTestControl {
    final_path: PathBuf,
    checkpoint: PublicationCheckpoint,
    action: PublicationTestAction,
}

#[cfg(test)]
static PUBLICATION_TEST_CONTROL: std::sync::Mutex<Option<PublicationTestControl>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PUBLICATION_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingTransactionLockTestMode {
    ExclusiveExisting,
    ExclusiveCreating,
    Shared,
}

#[cfg(test)]
#[derive(Clone)]
struct PendingTransactionLockTestControl {
    local_job_id: LocalJobId,
    mode: PendingTransactionLockTestMode,
    arrived: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
static PENDING_TRANSACTION_LOCK_TEST_CONTROL: std::sync::Mutex<
    Option<PendingTransactionLockTestControl>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn await_pending_transaction_lock_test_control(
    local_job_id: &LocalJobId,
    mode: PendingTransactionLockTestMode,
) {
    let control = PENDING_TRANSACTION_LOCK_TEST_CONTROL
        .lock()
        .expect("pending-transaction test-control lock is not poisoned")
        .as_ref()
        .filter(|control| control.local_job_id == *local_job_id && control.mode == mode)
        .cloned();
    if let Some(control) = control {
        control.arrived.wait();
        control.release.wait();
    }
}

#[cfg(not(test))]
fn await_pending_transaction_lock_test_control(
    _local_job_id: &LocalJobId,
    _mode: PendingTransactionLockTestMode,
) {
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlatformConfigBarrierCheckpoint {
    Base,
    Parent,
}

#[cfg(test)]
struct PlatformConfigBarrierTestControl {
    path: PathBuf,
    fail_once: Option<PlatformConfigBarrierCheckpoint>,
    attempts: Vec<PlatformConfigBarrierCheckpoint>,
}

#[cfg(test)]
static PLATFORM_CONFIG_BARRIER_TEST_CONTROL: std::sync::Mutex<
    Option<PlatformConfigBarrierTestControl>,
> = std::sync::Mutex::new(None);

#[cfg(all(test, windows))]
struct PrivateDirectoryRaceTestControl {
    path: PathBuf,
    entered: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(all(test, windows))]
static PRIVATE_DIRECTORY_RACE_TEST_CONTROL: std::sync::Mutex<
    Option<PrivateDirectoryRaceTestControl>,
> = std::sync::Mutex::new(None);

#[derive(Deserialize)]
struct RevisionSchemaProbe {
    schema_version: u32,
}

struct ScannedRevisionEntry {
    entry: RevisionEntry,
    retained_record: Option<StoredJobV1>,
}

fn default_store_root(create_platform_base: bool) -> Result<PathBuf, JobStoreError> {
    if let Some(value) = env::var_os("RUSTFERRY_CONFIG_HOME") {
        return config_override_path(&value);
    }
    let base = BaseDirs::new().ok_or(JobStoreError::ConfigHomeUnavailable)?;
    let platform_base = platform_store_base(&base);
    if create_platform_base {
        ensure_platform_config_base(platform_base)?;
    }
    Ok(platform_base.join("rustferry"))
}

fn platform_store_base(base: &BaseDirs) -> &Path {
    #[cfg(windows)]
    {
        base.data_local_dir()
    }
    #[cfg(not(windows))]
    {
        base.config_dir()
    }
}

fn config_override_path(value: &OsStr) -> Result<PathBuf, JobStoreError> {
    if value.is_empty()
        || value
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
    {
        return Err(JobStoreError::InvalidConfigHome);
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(JobStoreError::InvalidConfigHome);
    }
    Ok(path)
}

fn ensure_platform_config_base(path: &Path) -> Result<(), JobStoreError> {
    let parent_path = path.parent().ok_or(JobStoreError::InvalidConfigHome)?;
    let parent = RetainedDirectoryIdentity::open(parent_path)
        .map_err(|error| retained_directory_error("retain platform config parent", &error))?;
    let base = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            RetainedDirectoryIdentity::open(path).map_err(|error| {
                retained_directory_error("retain existing platform config directory", &error)
            })?
        }
        Ok(_) => return Err(JobStoreError::InvalidConfigHome),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            if let Err(source) = builder.create(path)
                && source.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(io_error("create platform config directory", source));
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("inspect platform config directory", source))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(JobStoreError::InvalidConfigHome);
            }
            RetainedDirectoryIdentity::open(path).map_err(|error| {
                retained_directory_error("retain created platform config directory", &error)
            })?
        }
        Err(source) => return Err(io_error("inspect platform config directory", source)),
    };
    sync_platform_config_barrier(path, &base, parent_path, &parent)
}

fn sync_platform_config_barrier(
    path: &Path,
    base: &RetainedDirectoryIdentity,
    parent_path: &Path,
    parent: &RetainedDirectoryIdentity,
) -> Result<(), JobStoreError> {
    platform_config_barrier_checkpoint(path, PlatformConfigBarrierCheckpoint::Base)?;
    sync_retained_directory(base, path, "sync platform config directory metadata")?;
    platform_config_barrier_checkpoint(path, PlatformConfigBarrierCheckpoint::Parent)?;
    sync_retained_directory(parent, parent_path, "sync platform config parent metadata")
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the production no-op and test failpoint share the fallible durability-barrier signature"
)]
fn platform_config_barrier_checkpoint(
    path: &Path,
    checkpoint: PlatformConfigBarrierCheckpoint,
) -> Result<(), JobStoreError> {
    #[cfg(not(test))]
    let _ = (path, checkpoint);
    #[cfg(test)]
    {
        let mut installed = PLATFORM_CONFIG_BARRIER_TEST_CONTROL
            .lock()
            .expect("platform-config test-control lock is not poisoned");
        if let Some(control) = installed.as_mut()
            && control.path == path
        {
            control.attempts.push(checkpoint);
            if control.fail_once == Some(checkpoint) {
                control.fail_once = None;
                return Err(io_error(
                    "complete platform config durability barrier",
                    std::io::Error::other("injected durability-barrier failure"),
                ));
            }
        }
    }
    Ok(())
}

fn retained_directory_error(
    operation: &'static str,
    error: &rustferry_core::DirectoryIdentityError,
) -> JobStoreError {
    JobStoreError::Security {
        operation,
        message: error.to_string(),
    }
}

#[cfg(windows)]
fn sync_retained_directory(
    retained: &RetainedDirectoryIdentity,
    path: &Path,
    operation: &'static str,
) -> Result<(), JobStoreError> {
    retained
        .sync_metadata(path)
        .map_err(|error| retained_directory_error(operation, &error))
}

#[cfg(not(windows))]
fn sync_retained_directory(
    retained: &RetainedDirectoryIdentity,
    path: &Path,
    operation: &'static str,
) -> Result<(), JobStoreError> {
    retained
        .verify_path(path)
        .map_err(|error| retained_directory_error(operation, &error))?;
    retained
        .as_file()
        .sync_all()
        .map_err(|source| io_error(operation, source))?;
    retained
        .verify_path(path)
        .map_err(|error| retained_directory_error(operation, &error))
}

#[allow(
    clippy::too_many_lines,
    reason = "state, outcome, cleanup, cancellation, and failure evidence form one boundary"
)]
fn validate_job_state(record: &StoredJobV1) -> Result<(), JobStoreError> {
    if record.state == StoredJobState::Unknown {
        if record
            .last_confirmed_state
            .is_none_or(|state| state == StoredJobState::Unknown)
        {
            return Err(invalid_record(
                "unknown state requires a distinct last confirmed state",
            ));
        }
    } else if record.last_confirmed_state == Some(StoredJobState::Unknown) {
        return Err(invalid_record("last confirmed state cannot be unknown"));
    }
    if matches!(
        record.state,
        StoredJobState::CleanupPending | StoredJobState::CleanupFailed
    ) && record.last_confirmed_state.is_none_or(|state| {
        matches!(
            state,
            StoredJobState::Unknown
                | StoredJobState::CleanupPending
                | StoredJobState::CleanupFailed
        )
    }) {
        return Err(invalid_record(
            "cleanup overlay requires the exact underlying confirmed local phase",
        ));
    }
    match record.state {
        StoredJobState::Succeeded
            if record.terminal_outcome != Some(StoredBuildOutcome::Succeeded) =>
        {
            return Err(invalid_record(
                "succeeded state requires a successful build outcome",
            ));
        }
        StoredJobState::Failed
            if matches!(
                record.terminal_outcome,
                Some(StoredBuildOutcome::Cancelled | StoredBuildOutcome::Expired)
            ) =>
        {
            return Err(invalid_record(
                "failed local state conflicts with the confirmed build outcome",
            ));
        }
        StoredJobState::Cancelled
            if record.terminal_outcome != Some(StoredBuildOutcome::Cancelled) =>
        {
            return Err(invalid_record(
                "cancelled state requires a cancelled build outcome",
            ));
        }
        StoredJobState::Expired if record.terminal_outcome != Some(StoredBuildOutcome::Expired) => {
            return Err(invalid_record(
                "expired state requires an expired build outcome",
            ));
        }
        StoredJobState::ArtifactReady
        | StoredJobState::Downloading
        | StoredJobState::Downloaded
        | StoredJobState::Validating
            if record
                .terminal_outcome
                .is_some_and(|outcome| outcome != StoredBuildOutcome::Succeeded) =>
        {
            return Err(invalid_record(
                "local artifact processing permits only a successful build outcome",
            ));
        }
        StoredJobState::Succeeded
        | StoredJobState::Failed
        | StoredJobState::Cancelled
        | StoredJobState::Expired
        | StoredJobState::ArtifactReady
        | StoredJobState::Downloading
        | StoredJobState::Downloaded
        | StoredJobState::Validating
        | StoredJobState::CleanupPending
        | StoredJobState::CleanupFailed
        | StoredJobState::Unknown => {}
        _ if record.terminal_outcome.is_some() => {
            return Err(invalid_record(
                "build outcome was recorded before a build-terminal state",
            ));
        }
        _ => {}
    }
    if record.state == StoredJobState::Succeeded
        && record.cleanup_status != StoredCleanupStatus::Confirmed
    {
        return Err(invalid_record(
            "succeeded state requires confirmed cleanup policy",
        ));
    }
    if record.state == StoredJobState::CleanupPending
        && matches!(
            record.cleanup_status,
            StoredCleanupStatus::NotStarted | StoredCleanupStatus::Failed
        )
    {
        return Err(invalid_record(
            "cleanup-pending state requires a pending, uncertain, or confirmed cleanup status",
        ));
    }
    if record.state == StoredJobState::CleanupFailed
        && record.cleanup_status != StoredCleanupStatus::Failed
    {
        return Err(invalid_record(
            "cleanup-failed state requires failed cleanup status",
        ));
    }
    if record.state == StoredJobState::CancellationRequested
        && !matches!(
            record.cancellation_status,
            StoredCancellationStatus::Requested
                | StoredCancellationStatus::Dispatched
                | StoredCancellationStatus::Uncertain
        )
    {
        return Err(invalid_record(
            "cancellation-requested state requires durable cancellation intent",
        ));
    }
    if record.state == StoredJobState::Cancelled
        && record.cancellation_status != StoredCancellationStatus::Confirmed
    {
        return Err(invalid_record(
            "cancelled state requires provider terminal confirmation",
        ));
    }
    let failure_required = record.terminal_outcome == Some(StoredBuildOutcome::Failed)
        || matches!(
            record.state,
            StoredJobState::Failed | StoredJobState::CleanupFailed
        );
    let failure_allowed = failure_required
        || matches!(
            record.state,
            StoredJobState::CleanupPending | StoredJobState::Unknown
        );
    if failure_required && record.failure.is_none() || !failure_allowed && record.failure.is_some()
    {
        return Err(invalid_record(
            "sanitized failure evidence is inconsistent with state and outcome",
        ));
    }
    Ok(())
}

fn validate_initial_job_revision(record: &StoredJobV1) -> Result<(), JobStoreError> {
    if record.state != StoredJobState::SourceReady
        || record.last_confirmed_state != Some(StoredJobState::SourceReady)
        || record.provider_job_id.is_some()
        || record.provider_run_id.is_some()
        || record.submitted_at_ms.is_some()
        || record.terminal_outcome.is_some()
        || record.compile_evidence.is_some()
        || record.signed_cleanup_evidence.is_some()
        || !record.artifacts.is_empty()
        || record.cleanup_status != StoredCleanupStatus::NotStarted
        || record.cancellation_status != StoredCancellationStatus::NotRequested
        || record.log_location.is_some()
        || record.failure.is_some()
        || record.provider_resume.is_some()
        || !record.retry_lineage.child_job_ids.is_empty()
    {
        return Err(invalid_record(
            "the initial revision must contain only pre-provider source-ready intent",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "successor validation is one auditable monotonicity boundary"
)]
fn validate_successor(previous: &StoredJobV1, next: &StoredJobV1) -> Result<(), JobStoreError> {
    if previous.local_job_id != next.local_job_id
        || previous.project != next.project
        || previous.provider != next.provider
        || previous.operation_id != next.operation_id
        || previous.request != next.request
        || previous.request_sha256 != next.request_sha256
        || previous.semantic_retry_sha256 != next.semantic_retry_sha256
        || previous.source != next.source
        || previous.target != next.target
        || previous.profile != next.profile
        || previous.signing_mode != next.signing_mode
        || previous.created_at_ms != next.created_at_ms
        || previous.retry_lineage.attempt != next.retry_lineage.attempt
        || previous.retry_lineage.parent_job_id != next.retry_lineage.parent_job_id
    {
        return Err(invalid_record(
            "immutable job identity changed between revisions",
        ));
    }
    if next.updated_at_ms < previous.updated_at_ms {
        return Err(invalid_record("revision timestamp moved backwards"));
    }
    if !option_can_be_bound_once(
        previous.provider_job_id.as_deref(),
        next.provider_job_id.as_deref(),
    ) || !option_can_be_bound_once(
        previous.provider_run_id.as_deref(),
        next.provider_run_id.as_deref(),
    ) || !option_can_be_bound_once(
        previous.submitted_at_ms.as_ref(),
        next.submitted_at_ms.as_ref(),
    ) {
        return Err(invalid_record(
            "provider identity or submission time was replaced",
        ));
    }
    if !option_can_be_bound_once(
        previous.compile_evidence.as_ref(),
        next.compile_evidence.as_ref(),
    ) || !option_can_be_bound_once(
        previous.signed_cleanup_evidence.as_ref(),
        next.signed_cleanup_evidence.as_ref(),
    ) {
        return Err(invalid_record(
            "verified provider evidence changed between revisions",
        ));
    }
    if !option_can_be_bound_once(
        previous.log_location.as_deref(),
        next.log_location.as_deref(),
    ) {
        return Err(invalid_record(
            "managed log location changed between revisions",
        ));
    }
    if previous.state != StoredJobState::Unknown
        && !previous.state.can_transition_to(next.state)
        && !cleanup_failure_has_exact_recovery(previous, next)
    {
        return Err(invalid_record("invalid local job state transition"));
    }
    if next.state == StoredJobState::Unknown {
        let expected = if previous.state == StoredJobState::Unknown {
            previous.last_confirmed_state
        } else {
            Some(effective_local_phase(previous))
        };
        if next.last_confirmed_state != expected {
            return Err(invalid_record(
                "unknown state must preserve the exact last confirmed state",
            ));
        }
        if next.terminal_outcome != previous.terminal_outcome {
            return Err(invalid_record(
                "unknown state cannot introduce a terminal build outcome",
            ));
        }
    }
    if previous.state == StoredJobState::Unknown
        && next.state != StoredJobState::Unknown
        && previous
            .last_confirmed_state
            .is_none_or(|confirmed| !confirmed.can_transition_to(next.state))
    {
        return Err(invalid_record(
            "recovery from unknown regressed the last confirmed local phase",
        ));
    }
    if matches!(
        next.state,
        StoredJobState::CleanupPending | StoredJobState::CleanupFailed
    ) && next.last_confirmed_state != Some(effective_local_phase(previous))
    {
        return Err(invalid_record(
            "cleanup overlay changed its underlying confirmed local phase",
        ));
    }
    if previous.state == StoredJobState::Unknown
        && matches!(
            next.state,
            StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
        && next.last_confirmed_state != Some(next.state)
    {
        return Err(invalid_record(
            "terminal recovery from unknown requires an exact confirmed state",
        ));
    }
    if previous
        .terminal_outcome
        .is_some_and(|outcome| next.terminal_outcome != Some(outcome))
    {
        return Err(invalid_record("terminal build outcome changed"));
    }
    let provider_checkpoint_changed = previous.provider_resume != next.provider_resume;
    if previous.terminal_outcome != next.terminal_outcome
        && matches!(
            next.terminal_outcome,
            Some(StoredBuildOutcome::Succeeded | StoredBuildOutcome::Cancelled)
        )
        && !provider_checkpoint_changed
    {
        return Err(invalid_record(
            "provider-owned terminal outcome lacks a changed provider checkpoint",
        ));
    }
    if previous.cancellation_status != StoredCancellationStatus::Confirmed
        && next.cancellation_status == StoredCancellationStatus::Confirmed
        && !provider_checkpoint_changed
    {
        return Err(invalid_record(
            "confirmed cancellation lacks a changed provider checkpoint",
        ));
    }
    if previous.cleanup_status != next.cleanup_status
        && matches!(
            next.cleanup_status,
            StoredCleanupStatus::Confirmed | StoredCleanupStatus::Failed
        )
        && !provider_checkpoint_changed
    {
        return Err(invalid_record(
            "confirmed or failed cleanup lacks a changed provider checkpoint",
        ));
    }
    if !failure_can_transition(previous, next) {
        return Err(invalid_record("sanitized failure evidence changed"));
    }
    if !previous
        .cleanup_status
        .can_transition_to(next.cleanup_status)
        || !previous
            .cancellation_status
            .can_transition_to(next.cancellation_status)
    {
        return Err(invalid_record("cleanup or cancellation status regressed"));
    }
    if !previous.retry_lineage.child_job_ids.iter().eq(next
        .retry_lineage
        .child_job_ids
        .iter()
        .take(previous.retry_lineage.child_job_ids.len()))
    {
        return Err(invalid_record("retry children were removed or reordered"));
    }
    validate_artifact_successor(&previous.artifacts, &next.artifacts)?;
    match (&previous.provider_resume, &next.provider_resume) {
        (Some(previous_resume), Some(next_resume)) => {
            previous_resume
                .validate_successor(next_resume)
                .map_err(|_| {
                    invalid_record("GitHub provider resume checkpoint regressed between revisions")
                })?;
            if previous_resume != next_resume
                && project_github_resume(previous, next_resume)? != *next
            {
                return Err(invalid_record(
                    "GitHub provider checkpoint differs from its canonical local projection",
                ));
            }
        }
        (Some(_), None) => {
            return Err(invalid_record(
                "GitHub provider resume checkpoint was removed between revisions",
            ));
        }
        (None, Some(next_resume)) => {
            if project_github_resume(previous, next_resume)? != *next {
                return Err(invalid_record(
                    "GitHub provider checkpoint differs from its canonical local projection",
                ));
            }
        }
        (None, None) => {}
    }
    Ok(())
}

fn validate_regular_successor(
    previous: &StoredJobV1,
    next: &StoredJobV1,
) -> Result<(), JobStoreError> {
    if previous.retry_lineage.child_job_ids != next.retry_lineage.child_job_ids {
        return Err(invalid_record(
            "retry children may only be changed by the atomic lineage API",
        ));
    }
    validate_successor(previous, next)
}

fn cleanup_failure_has_exact_recovery(previous: &StoredJobV1, next: &StoredJobV1) -> bool {
    previous.state == StoredJobState::CleanupFailed
        && previous.cleanup_status == StoredCleanupStatus::Failed
        && next.cleanup_status == StoredCleanupStatus::Confirmed
        && matches!(
            next.state,
            StoredJobState::ArtifactReady
                | StoredJobState::Downloading
                | StoredJobState::Downloaded
                | StoredJobState::Validating
                | StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
        && matches!(
            next.provider_resume.as_ref(),
            Some(resume) if resume.state == JobState::Cleaned
        )
}

fn failure_can_transition(previous: &StoredJobV1, next: &StoredJobV1) -> bool {
    match (&previous.failure, &next.failure) {
        (None, _) => true,
        (Some(previous_failure), Some(next_failure)) => previous_failure == next_failure,
        (Some(_), None) => {
            recoverable_cleanup_failure(previous)
                && matches!(
                    next.cleanup_status,
                    StoredCleanupStatus::Pending | StoredCleanupStatus::Confirmed
                )
                && matches!(
                    next.state,
                    StoredJobState::CleanupPending
                        | StoredJobState::ArtifactReady
                        | StoredJobState::Downloading
                        | StoredJobState::Downloaded
                        | StoredJobState::Validating
                        | StoredJobState::Succeeded
                        | StoredJobState::Cancelled
                )
        }
    }
}

fn recoverable_cleanup_failure(record: &StoredJobV1) -> bool {
    let Some(failure) = &record.failure else {
        return false;
    };
    if failure.code == "github.cleanup_failed" {
        return matches!(
            record.cleanup_status,
            StoredCleanupStatus::Failed
                | StoredCleanupStatus::Pending
                | StoredCleanupStatus::Uncertain
        ) && matches!(
            record.state,
            StoredJobState::CleanupFailed
                | StoredJobState::CleanupPending
                | StoredJobState::Failed
                | StoredJobState::Unknown
        ) && matches!(
            record.provider_resume.as_ref(),
            Some(resume) if resume.state == JobState::CleanupFailed
        );
    }
    failure.code == "controller.cleanup_unconfirmed"
        && failure.retryable
        && matches!(
            record.cleanup_status,
            StoredCleanupStatus::Pending | StoredCleanupStatus::Uncertain
        )
        && matches!(
            record.state,
            StoredJobState::Failed | StoredJobState::CleanupPending | StoredJobState::Unknown
        )
}

fn validate_artifact_successor(
    previous: &[StoredArtifactV1],
    next: &[StoredArtifactV1],
) -> Result<(), JobStoreError> {
    for previous in previous {
        let Some(next) = next
            .iter()
            .find(|candidate| candidate.record.artifact_id == previous.record.artifact_id)
        else {
            return Err(invalid_record(
                "artifact record was removed between revisions",
            ));
        };
        if previous.record != next.record
            || !option_can_be_bound_once(
                previous.download_destination.as_deref(),
                next.download_destination.as_deref(),
            )
            || !option_can_be_bound_once(
                previous.download_parent_identity.as_deref(),
                next.download_parent_identity.as_deref(),
            )
            || !option_can_be_bound_once(previous.local_path.as_deref(), next.local_path.as_deref())
            || !option_can_be_bound_once(
                previous.local_file_identity.as_deref(),
                next.local_file_identity.as_deref(),
            )
            || previous.locally_validated && !next.locally_validated
        {
            return Err(invalid_record(
                "artifact identity, path, or validation regressed",
            ));
        }
        if previous.local_path.is_none()
            && next.local_path.is_some()
            && (previous.download_destination.is_none()
                || previous.download_parent_identity.is_none()
                || previous.download_destination != next.download_destination
                || previous.download_parent_identity != next.download_parent_identity)
        {
            return Err(invalid_record(
                "artifact publication requires a previously durable destination intent",
            ));
        }
        if !previous.locally_validated
            && next.locally_validated
            && (previous.local_path.is_none() || previous.local_file_identity.is_none())
        {
            return Err(invalid_record(
                "artifact validation requires a previously durable local file identity",
            ));
        }
    }
    if next.iter().any(|next| {
        !previous
            .iter()
            .any(|previous| previous.record.artifact_id == next.record.artifact_id)
            && (next.local_path.is_some()
                || next.local_file_identity.is_some()
                || next.locally_validated)
    }) {
        return Err(invalid_record(
            "new provider artifacts cannot introduce local publication evidence",
        ));
    }
    Ok(())
}

fn option_can_be_bound_once<T: PartialEq + ?Sized>(previous: Option<&T>, next: Option<&T>) -> bool {
    match (previous, next) {
        (None, _) => true,
        (Some(previous), Some(next)) => previous == next,
        (Some(_), None) => false,
    }
}

fn validate_github_publication_boundary(resume: &GithubJobResumeV1) -> Result<(), JobStoreError> {
    let first_observed = resume.publication_absence_first_observed_at_ms;
    let armed = resume.publication_started_at_ms != 0
        && resume.publication_started_at_ms >= resume.created_at_ms
        && (first_observed == 0 || first_observed >= resume.publication_started_at_ms)
        && resume.publication_quiescence_deadline_ms
            == resume
                .publication_started_at_ms
                .max(first_observed)
                .saturating_add(GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS);
    let unarmed = resume.publication_started_at_ms == 0
        && resume.publication_quiescence_deadline_ms == u64::MAX
        && first_observed == 0;
    let observation_time_is_bound = resume.publication_absence_observations != 0;
    let latest_event_ms = resume
        .events
        .iter()
        .map(|event| event.timestamp_ms)
        .max()
        .unwrap_or(0);
    if let Some(scope) = &resume.publication_lease_scope_sha256 {
        validate_sha256("provider_resume.publication_lease_scope_sha256", scope)?;
    }
    if !(armed || unarmed)
        || resume.publication_intent != armed
        || resume.publication_process_fenced && resume.publication_lease_scope_sha256.is_none()
        || observation_time_is_bound != (first_observed != 0)
        || resume.publication_absence_observations > 2
        || observation_time_is_bound && resume.prepared_dispatch_commit.is_none()
        || resume.publication_absent
            && (resume.publication_absence_observations < 2
                || resume.prepared_dispatch_commit.is_none()
                || resume.dispatch_commit.is_some()
                || resume.publication_uncertain
                || !resume.publication_process_fenced
                || !resume.temporary_ref_deleted
                || latest_event_ms < resume.publication_quiescence_deadline_ms)
    {
        return Err(invalid_record(
            "GitHub publication boundary or absence evidence is invalid",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the checkpoint identity boundary is intentionally audited in one place"
)]
fn validate_github_resume_projection_identity(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<(), JobStoreError> {
    validate_github_resume_record_identity(previous, resume)?;
    if let Some(prior) = &previous.provider_resume {
        prior.validate_successor(resume).map_err(|_| {
            invalid_record("GitHub provider resume checkpoint regressed between revisions")
        })?;
    }
    Ok(())
}

fn github_resume_provider_run_id(
    resume: &GithubJobResumeV1,
) -> Result<Option<String>, JobStoreError> {
    let run_id = resume.run.as_ref().map(|run| run.run_id);
    let receipt_id = resume
        .workflow_dispatch
        .as_ref()
        .and_then(|dispatch| dispatch.receipt.as_ref())
        .map(|receipt| receipt.run_id);
    if matches!((run_id, receipt_id), (Some(run), Some(receipt)) if run != receipt) {
        return Err(invalid_record(
            "GitHub workflow-dispatch receipt and run identifiers differ",
        ));
    }
    Ok(run_id.or(receipt_id).map(|run_id| run_id.to_string()))
}

#[allow(
    clippy::too_many_lines,
    reason = "the durable resume identity boundary is intentionally audited in one place"
)]
fn validate_github_resume_record_identity(
    record: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<(), JobStoreError> {
    validate_github_publication_boundary(resume)?;
    resume
        .validate_trigger_binding()
        .map_err(|_| invalid_record("GitHub trigger-specific resume binding is invalid"))?;
    validate_github_snapshot_resume_identity(record, resume)?;
    validate_identifier("provider_resume.job_id", &resume.job_id)?;
    let resume_run_id = github_resume_provider_run_id(resume)?;
    if resume.schema_version != 1
        || resume.provider != GITHUB_PROVIDER_ID
        || record.provider.provider != GITHUB_PROVIDER_ID
        || resume.provider_config_sha256 != record.provider.provider_config_sha256
        || resume.principal != record.provider.principal
        || resume.execution_repository != record.provider.execution_repository
        || resume.execution_repository_id != record.provider.execution_repository_id
        || resume.operation_id != record.operation_id
        || resume.job_id != resume.operation_id
        || resume.request != record.request
        || resume.request_sha256 != record.request_sha256
        || Some(resume.source_repository.as_str()) != record.request.source_repository.as_deref()
        || Some(resume.source_revision.as_str()) != record.source.revision.as_deref()
        || record
            .provider_job_id
            .as_deref()
            .is_some_and(|job_id| job_id != resume.job_id)
        || record
            .provider_run_id
            .as_deref()
            .is_some_and(|run_id| Some(run_id) != resume_run_id.as_deref())
        || resume.created_at_ms < record.created_at_ms
    {
        return Err(invalid_record(
            "GitHub provider resume identity differs from the local job",
        ));
    }
    if resume
        .prepared_dispatch_commit
        .as_deref()
        .is_some_and(|commit| !github_commit_sha_is_valid(commit))
        || resume
            .dispatch_commit
            .as_deref()
            .is_some_and(|commit| !github_commit_sha_is_valid(commit))
        || matches!(
            (&resume.prepared_dispatch_commit, &resume.dispatch_commit),
            (Some(prepared), Some(dispatch)) if prepared != dispatch
        )
    {
        return Err(invalid_record(
            "GitHub prepared or published dispatch commit is invalid",
        ));
    }
    if let Some(run) = &resume.run {
        let expected_event = if resume.workflow_dispatch.is_some() {
            GithubRunEventV1::WorkflowDispatch
        } else {
            GithubRunEventV1::Push
        };
        let branch = resume
            .temporary_ref
            .strip_prefix("refs/heads/")
            .ok_or_else(|| invalid_record("GitHub temporary ref is not a full branch ref"))?;
        let dispatch_commit = resume
            .dispatch_commit
            .as_deref()
            .ok_or_else(|| invalid_record("GitHub run identity lacks an exact dispatch commit"))?;
        if run.run_id == 0
            || run.workflow_id == 0
            || run.run_number == 0
            || run.run_attempt == 0
            || run.workflow_path != resume.workflow_path
            || run.head_sha != dispatch_commit
            || run.branch != branch
            || run.event != expected_event
            || ((run.status == GithubRunStatusV1::Completed) != run.conclusion.is_some())
        {
            return Err(invalid_record(
                "GitHub run identity is not exactly bound to the dispatch",
            ));
        }
    }
    for (index, event) in resume.events.iter().enumerate() {
        event
            .validate()
            .map_err(|_| invalid_record("GitHub provider event is invalid"))?;
        if event.operation_id != resume.operation_id
            || event.job_id != resume.job_id
            || event.provider != GITHUB_PROVIDER_ID
            || event.sequence != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
            || event.timestamp_ms < resume.created_at_ms
            || matches!(&event.kind, RemoteBuildEventKind::Unknown)
        {
            return Err(invalid_record(
                "GitHub provider event identity or ordering is invalid",
            ));
        }
        if let RemoteBuildEventKind::ArtifactValidated { artifact } = &event.kind {
            validate_github_manifest_identity(record, resume, artifact)?;
            if !resume.manifests.contains(artifact) {
                return Err(invalid_record(
                    "validated GitHub artifact event is absent from the durable manifests",
                ));
            }
        }
    }
    for manifest in &resume.manifests {
        validate_github_manifest_identity(record, resume, manifest)?;
    }
    let run_completed_success = matches!(
        resume.run.as_ref(),
        Some(run)
            if run.status == GithubRunStatusV1::Completed
                && run.conclusion == Some(GithubRunConclusionV1::Success)
    );
    if (resume.state == JobState::Succeeded || !resume.manifests.is_empty())
        && !run_completed_success
    {
        return Err(invalid_record(
            "GitHub artifact success contradicts the bound run conclusion",
        ));
    }
    Ok(())
}

fn validate_github_snapshot_resume_identity(
    record: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<(), JobStoreError> {
    let Some(snapshot) = resume.git_snapshot.as_ref() else {
        if record.request.source_mode == SourceMode::GitSnapshot {
            return Err(invalid_record(
                "Git snapshot request lacks its durable snapshot checkpoint",
            ));
        }
        return Ok(());
    };
    if record.request.source_mode != SourceMode::GitSnapshot {
        return Err(invalid_record(
            "non-snapshot request carries a Git snapshot checkpoint",
        ));
    }
    let descriptor = GitSnapshotDescriptor::from_request(
        &record.request,
        SourceBundleDescriptor::new(
            snapshot.stage.archive.clone(),
            record.request.source.clone(),
        ),
    )
    .map_err(|_| invalid_record("Git snapshot descriptor cannot be reconstructed"))?;
    snapshot
        .stage_locator
        .validate_for_operation(&record.operation_id)
        .map_err(|_| invalid_record("Git snapshot locator differs from the stored operation"))?;
    snapshot
        .stage
        .validate_for_request(&descriptor, &record.request)
        .map_err(|_| invalid_record("Git snapshot stage differs from the stored request"))?;
    let release_phase = matches!(
        snapshot.phase,
        GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent
            | GithubGitSnapshotPhaseV1::KeepaliveReleased
    );
    if release_phase != snapshot.keepalive_release_authorization_sha256.is_some() {
        return Err(invalid_record(
            "Git snapshot keepalive release phase lacks exact authorization",
        ));
    }
    if let Some(authorization) = &snapshot.keepalive_release_authorization_sha256 {
        validate_sha256(
            "provider_resume.git_snapshot.keepalive_release_authorization_sha256",
            authorization,
        )?;
    }
    Ok(())
}

fn github_commit_sha_is_valid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_github_manifest_identity(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
    manifest: &ArtifactManifest,
) -> Result<(), JobStoreError> {
    if manifest.schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION
        || manifest.operation_id != resume.operation_id
        || manifest.job_id != resume.job_id
        || manifest.provider != GITHUB_PROVIDER_ID
        || manifest.source_repository.as_deref() != Some(resume.source_repository.as_str())
        || manifest.source_revision.as_deref() != Some(resume.source_revision.as_str())
        || manifest.source_sha256 != previous.source.manifest_sha256
        || manifest.artifacts.is_empty()
    {
        return Err(invalid_record(
            "GitHub artifact manifest identity differs from the local job",
        ));
    }
    Ok(())
}

fn validate_github_artifact_projection(
    record: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<(), JobStoreError> {
    let mut expected = BTreeMap::new();
    for artifact in resume
        .manifests
        .iter()
        .flat_map(|manifest| &manifest.artifacts)
    {
        if let Some(previous) = expected.insert(artifact.artifact_id.as_str(), artifact)
            && previous != artifact
        {
            return Err(invalid_record(
                "GitHub manifests contain conflicting artifact identities",
            ));
        }
    }
    if expected.len() != record.artifacts.len()
        || record.artifacts.iter().any(|artifact| {
            expected
                .get(artifact.record.artifact_id.as_str())
                .is_none_or(|expected| **expected != artifact.record)
        })
    {
        return Err(invalid_record(
            "stored artifacts differ from the exact GitHub manifest set",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct GithubProjectionEvidence {
    outcome: Option<StoredBuildOutcome>,
    failure: Option<StoredFailureV1>,
    cancellation_confirmed: bool,
    cleanup_started_at_ms: Option<u64>,
    cleanup_confirmation: Option<rustferry_remote::CleanupConfirmation>,
}

fn merge_github_outcome(
    evidence: &mut GithubProjectionEvidence,
    outcome: StoredBuildOutcome,
    failure: Option<StoredFailureV1>,
) -> Result<(), JobStoreError> {
    if evidence.outcome.is_some_and(|existing| existing != outcome)
        || evidence
            .failure
            .as_ref()
            .is_some_and(|existing| failure.as_ref() != Some(existing))
    {
        return Err(invalid_record(
            "GitHub provider terminal evidence is contradictory",
        ));
    }
    if outcome == StoredBuildOutcome::Failed && failure.is_none()
        || outcome != StoredBuildOutcome::Failed && failure.is_some()
    {
        return Err(invalid_record(
            "GitHub provider failure evidence is inconsistent",
        ));
    }
    evidence.outcome = Some(outcome);
    if failure.is_some() {
        evidence.failure = failure;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "typed provider evidence is reduced without retaining message or help text"
)]
fn collect_github_projection_evidence(
    resume: &GithubJobResumeV1,
) -> Result<GithubProjectionEvidence, JobStoreError> {
    let mut evidence = GithubProjectionEvidence::default();
    for event in &resume.events {
        match &event.kind {
            RemoteBuildEventKind::OperationFinished {
                success,
                result,
                error,
                ..
            } => {
                if let Some(result) = result {
                    result
                        .validate()
                        .map_err(|_| invalid_record("GitHub build result is invalid"))?;
                    if result.operation_id != resume.operation_id || result.job_id != resume.job_id
                    {
                        return Err(invalid_record(
                            "GitHub build result identity differs from the checkpoint",
                        ));
                    }
                }
                if *success {
                    let Some(result) = result else {
                        return Err(invalid_record(
                            "successful GitHub operation lacks a typed build result",
                        ));
                    };
                    if result.state != JobState::Succeeded || result.artifacts != resume.manifests {
                        return Err(invalid_record(
                            "successful GitHub build result differs from durable manifests",
                        ));
                    }
                    merge_github_outcome(&mut evidence, StoredBuildOutcome::Succeeded, None)?;
                } else {
                    if result
                        .as_ref()
                        .is_some_and(|result| result.state != JobState::Failed)
                    {
                        return Err(invalid_record(
                            "failed GitHub operation has a non-failed build result",
                        ));
                    }
                    let error = error.as_ref().ok_or_else(|| {
                        invalid_record("failed GitHub operation lacks typed failure evidence")
                    })?;
                    merge_github_outcome(
                        &mut evidence,
                        StoredBuildOutcome::Failed,
                        Some(StoredFailureV1 {
                            code: error.code.clone(),
                            retryable: error.retryable,
                        }),
                    )?;
                }
            }
            RemoteBuildEventKind::OperationCancelled { .. } => {
                evidence.cancellation_confirmed = true;
                merge_github_outcome(&mut evidence, StoredBuildOutcome::Cancelled, None)?;
            }
            RemoteBuildEventKind::CleanupStarted => {
                if evidence.cleanup_started_at_ms.is_some()
                    && evidence.cleanup_confirmation.is_none()
                {
                    return Err(invalid_record(
                        "GitHub cleanup retry started before the prior attempt completed",
                    ));
                }
                if evidence
                    .cleanup_confirmation
                    .as_ref()
                    .is_some_and(|confirmation| event.timestamp_ms < confirmation.completed_at_ms)
                {
                    return Err(invalid_record(
                        "GitHub cleanup retry evidence is out of order",
                    ));
                }
                evidence.cleanup_started_at_ms = Some(event.timestamp_ms);
                evidence.cleanup_confirmation = None;
            }
            RemoteBuildEventKind::CleanupFinished { confirmation } => {
                let Some(started_at_ms) = evidence.cleanup_started_at_ms else {
                    return Err(invalid_record(
                        "GitHub cleanup confirmation identity or ordering is invalid",
                    ));
                };
                if confirmation.completed_at_ms < started_at_ms
                    || confirmation.job_id != resume.job_id
                    || confirmation.completed_at_ms < resume.created_at_ms
                    || event.timestamp_ms < started_at_ms
                    || confirmation.completed_at_ms > event.timestamp_ms
                    || evidence.cleanup_confirmation.is_some()
                {
                    return Err(invalid_record(
                        "GitHub cleanup confirmation identity or ordering is invalid",
                    ));
                }
                evidence.cleanup_confirmation = Some(confirmation.clone());
            }
            _ => {}
        }
    }
    Ok(evidence)
}

fn github_run_failure(conclusion: GithubRunConclusionV1) -> Option<StoredFailureV1> {
    let code = match conclusion {
        GithubRunConclusionV1::Failure => "github.run_failed",
        GithubRunConclusionV1::TimedOut => "github.run_timed_out",
        GithubRunConclusionV1::Neutral => "github.run_neutral",
        GithubRunConclusionV1::Skipped => "github.run_skipped",
        GithubRunConclusionV1::Stale => "github.run_stale",
        GithubRunConclusionV1::ActionRequired => "github.run_action_required",
        GithubRunConclusionV1::StartupFailure => "github.run_startup_failure",
        GithubRunConclusionV1::Success | GithubRunConclusionV1::Cancelled => return None,
    };
    Some(StoredFailureV1 {
        code: code.to_owned(),
        retryable: matches!(
            conclusion,
            GithubRunConclusionV1::TimedOut
                | GithubRunConclusionV1::Stale
                | GithubRunConclusionV1::StartupFailure
        ),
    })
}

fn derive_github_outcome(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
    evidence: &mut GithubProjectionEvidence,
) -> Result<Option<StoredBuildOutcome>, JobStoreError> {
    match resume.state {
        JobState::Succeeded => {
            merge_github_outcome(evidence, StoredBuildOutcome::Succeeded, None)?;
        }
        JobState::Failed => {
            let failure = evidence.failure.clone().or_else(|| {
                Some(StoredFailureV1 {
                    code: "github.provider_failed".to_owned(),
                    retryable: false,
                })
            });
            merge_github_outcome(evidence, StoredBuildOutcome::Failed, failure)?;
        }
        JobState::Cancelled => {
            let run_cancelled = resume.run.as_ref().is_some_and(|run| {
                run.status == GithubRunStatusV1::Completed
                    && run.conclusion == Some(GithubRunConclusionV1::Cancelled)
            });
            if !(evidence.cancellation_confirmed
                || run_cancelled
                || resume.publication_absent && resume.cancellation_requested)
            {
                return Err(invalid_record(
                    "cancelled GitHub state lacks exact cancellation evidence",
                ));
            }
            evidence.cancellation_confirmed = true;
            merge_github_outcome(evidence, StoredBuildOutcome::Cancelled, None)?;
        }
        JobState::Cleaning | JobState::Cleaned | JobState::CleanupFailed => {
            if evidence.outcome.is_none()
                && previous.terminal_outcome.is_none()
                && let Some(conclusion) = resume.run.as_ref().and_then(|run| run.conclusion)
            {
                match conclusion {
                    GithubRunConclusionV1::Success => {
                        merge_github_outcome(evidence, StoredBuildOutcome::Succeeded, None)?;
                    }
                    GithubRunConclusionV1::Cancelled => {
                        merge_github_outcome(evidence, StoredBuildOutcome::Cancelled, None)?;
                    }
                    conclusion => merge_github_outcome(
                        evidence,
                        StoredBuildOutcome::Failed,
                        github_run_failure(conclusion),
                    )?,
                }
            }
        }
        JobState::Created | JobState::Queued | JobState::Running | JobState::Cancelling => {
            if evidence.outcome.is_some() {
                return Err(invalid_record(
                    "nonterminal GitHub state contains terminal build evidence",
                ));
            }
        }
    }
    let outcome = evidence.outcome.or(previous.terminal_outcome);
    if previous
        .terminal_outcome
        .is_some_and(|previous| Some(previous) != outcome)
    {
        return Err(invalid_record("GitHub provider build outcome changed"));
    }
    Ok(outcome)
}

fn project_github_artifacts(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<Vec<StoredArtifactV1>, JobStoreError> {
    let mut projected = previous.artifacts.clone();
    for artifact in resume
        .manifests
        .iter()
        .flat_map(|manifest| &manifest.artifacts)
    {
        if let Some(existing) = projected
            .iter()
            .find(|existing| existing.record.artifact_id == artifact.artifact_id)
        {
            if existing.record != *artifact {
                return Err(invalid_record(
                    "GitHub artifact identity changed between manifests",
                ));
            }
            continue;
        }
        let candidate = StoredArtifactV1 {
            record: artifact.clone(),
            download_destination: None,
            download_parent_identity: None,
            local_path: None,
            local_file_identity: None,
            locally_validated: false,
        };
        validate_artifact(&candidate)?;
        projected.push(candidate);
    }
    Ok(projected)
}

fn github_cleanup_is_confirmed(
    resume: &GithubJobResumeV1,
    evidence: &GithubProjectionEvidence,
) -> bool {
    evidence
        .cleanup_confirmation
        .as_ref()
        .is_some_and(|confirmation| {
            confirmation.workspace_removed
                && confirmation.signing_material_removed
                && resume.temporary_ref_deleted
                && github_snapshot_source_is_clean(resume)
                && (!resume.remove_artifacts_requested || resume.artifacts_removed)
                && confirmation.artifacts_retained != resume.remove_artifacts_requested
        })
}

fn github_absent_publication_is_clean(resume: &GithubJobResumeV1) -> bool {
    resume.publication_absent
        && resume.temporary_ref_deleted
        && github_snapshot_source_is_clean(resume)
        && (!resume.remove_artifacts_requested || resume.artifacts_removed)
}

fn github_snapshot_source_is_clean(resume: &GithubJobResumeV1) -> bool {
    resume.git_snapshot.as_ref().is_none_or(|snapshot| {
        matches!(
            snapshot.phase,
            GithubGitSnapshotPhaseV1::SourceAbsent
                | GithubGitSnapshotPhaseV1::SourceConflict
                | GithubGitSnapshotPhaseV1::SourceDeleted
                | GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent
                | GithubGitSnapshotPhaseV1::KeepaliveReleased
        )
    })
}

fn effective_local_phase(previous: &StoredJobV1) -> StoredJobState {
    let cleanup_overlay = matches!(
        previous.state,
        StoredJobState::Unknown | StoredJobState::CleanupPending | StoredJobState::CleanupFailed
    ) || recoverable_cleanup_failure(previous);
    if cleanup_overlay
        && let Some(confirmed) = previous.last_confirmed_state
        && !matches!(
            confirmed,
            StoredJobState::Unknown
                | StoredJobState::CleanupPending
                | StoredJobState::CleanupFailed
        )
    {
        return confirmed;
    }
    previous.state
}

fn project_github_state(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
    outcome: Option<StoredBuildOutcome>,
    artifacts: &[StoredArtifactV1],
) -> Result<(StoredJobState, StoredJobState), JobStoreError> {
    let effective_previous = effective_local_phase(previous);
    let preserve_artifact_phase = || {
        if previous.state == StoredJobState::CleanupPending && resume.state != JobState::Cleaned {
            return StoredJobState::CleanupPending;
        }
        matches!(
            effective_previous,
            StoredJobState::ArtifactReady
                | StoredJobState::Downloading
                | StoredJobState::Downloaded
                | StoredJobState::Validating
                | StoredJobState::Failed
                | StoredJobState::CleanupPending
                | StoredJobState::Succeeded
        )
        .then_some(effective_previous)
        .unwrap_or(StoredJobState::ArtifactReady)
    };
    let projected = match resume.state {
        JobState::Created => (StoredJobState::Submitting, StoredJobState::Submitting),
        JobState::Queued => (StoredJobState::Queued, StoredJobState::Queued),
        JobState::Running => {
            let local_state = if matches!(
                effective_previous,
                StoredJobState::CompileRunning
                    | StoredJobState::SigningWaiting
                    | StoredJobState::SigningRunning
                    | StoredJobState::ArtifactUploading
            ) {
                effective_previous
            } else {
                StoredJobState::Running
            };
            (local_state, StoredJobState::Running)
        }
        JobState::Cancelling => (
            StoredJobState::CancellationRequested,
            StoredJobState::CancellationRequested,
        ),
        JobState::Succeeded => {
            let local_state = preserve_artifact_phase();
            let confirmed_state = if local_state == StoredJobState::CleanupPending {
                effective_previous
            } else {
                StoredJobState::ArtifactReady
            };
            (local_state, confirmed_state)
        }
        JobState::Failed => (StoredJobState::Failed, StoredJobState::Failed),
        JobState::Cancelled => (StoredJobState::Cancelled, StoredJobState::Cancelled),
        JobState::Cleaning => (StoredJobState::CleanupPending, effective_previous),
        JobState::CleanupFailed => (StoredJobState::CleanupFailed, effective_previous),
        JobState::Cleaned => match outcome {
            Some(StoredBuildOutcome::Succeeded) => {
                let has_nonrecoverable_failure =
                    previous.failure.is_some() && !recoverable_cleanup_failure(previous);
                if has_nonrecoverable_failure {
                    (StoredJobState::Failed, StoredJobState::ArtifactReady)
                } else if (matches!(
                    previous.state,
                    StoredJobState::CleanupPending | StoredJobState::CleanupFailed
                ) || recoverable_cleanup_failure(previous))
                    && effective_previous == StoredJobState::Validating
                {
                    (StoredJobState::CleanupPending, StoredJobState::Validating)
                } else if !artifacts.is_empty()
                    && artifacts
                        .iter()
                        .all(|artifact| artifact.local_path.is_some() && artifact.locally_validated)
                {
                    (StoredJobState::Succeeded, StoredJobState::Succeeded)
                } else {
                    (preserve_artifact_phase(), StoredJobState::ArtifactReady)
                }
            }
            Some(StoredBuildOutcome::Failed) => (StoredJobState::Failed, StoredJobState::Failed),
            Some(StoredBuildOutcome::Cancelled) => {
                (StoredJobState::Cancelled, StoredJobState::Cancelled)
            }
            Some(StoredBuildOutcome::Expired) | None => {
                return Err(invalid_record(
                    "cleaned GitHub state lacks a supported build outcome",
                ));
            }
        },
    };
    Ok(projected)
}

#[allow(
    clippy::too_many_lines,
    reason = "one pure reducer keeps provider-owned and controller-owned state visibly separate"
)]
fn project_github_resume(
    previous: &StoredJobV1,
    resume: &GithubJobResumeV1,
) -> Result<StoredJobV1, JobStoreError> {
    let mut evidence = collect_github_projection_evidence(resume)?;
    let outcome = derive_github_outcome(previous, resume, &mut evidence)?;
    let artifacts = project_github_artifacts(previous, resume)?;
    if outcome == Some(StoredBuildOutcome::Succeeded)
        && matches!(resume.state, JobState::Succeeded | JobState::Cleaned)
        && artifacts.is_empty()
    {
        return Err(invalid_record(
            "successful GitHub checkpoint lacks artifact evidence",
        ));
    }
    let (state, last_confirmed_state) =
        project_github_state(previous, resume, outcome, &artifacts)?;

    let mut cleanup_status = previous.cleanup_status;
    if resume.cleanup_requested && cleanup_status != StoredCleanupStatus::Confirmed {
        cleanup_status = StoredCleanupStatus::Pending;
    }
    match resume.state {
        JobState::Cleaning => {
            if evidence.cleanup_started_at_ms.is_none() {
                return Err(invalid_record(
                    "cleaning GitHub state lacks cleanup-started evidence",
                ));
            }
            cleanup_status = StoredCleanupStatus::Pending;
        }
        JobState::Cleaned => {
            if !resume.cleanup_requested
                || evidence.cleanup_started_at_ms.is_none()
                || !github_cleanup_is_confirmed(resume, &evidence)
            {
                return Err(invalid_record(
                    "cleaned GitHub state lacks exact resource-removal evidence",
                ));
            }
            cleanup_status = StoredCleanupStatus::Confirmed;
        }
        JobState::CleanupFailed => {
            if !resume.cleanup_requested
                || evidence.cleanup_started_at_ms.is_none()
                || evidence.cleanup_confirmation.is_none()
                || github_cleanup_is_confirmed(resume, &evidence)
            {
                return Err(invalid_record(
                    "cleanup-failed GitHub state lacks consistent negative cleanup evidence",
                ));
            }
            cleanup_status = StoredCleanupStatus::Failed;
        }
        _ => {}
    }
    if github_absent_publication_is_clean(resume) && resume.state != JobState::CleanupFailed {
        cleanup_status = StoredCleanupStatus::Confirmed;
    } else if resume.publication_uncertain
        && !resume.publication_absent
        && !github_cleanup_is_confirmed(resume, &evidence)
        && cleanup_status != StoredCleanupStatus::Confirmed
        && resume.state != JobState::CleanupFailed
    {
        cleanup_status = StoredCleanupStatus::Uncertain;
    }

    let mut cancellation_status = previous.cancellation_status;
    if resume.cancellation_requested
        && cancellation_status == StoredCancellationStatus::NotRequested
    {
        return Err(invalid_record(
            "GitHub cancellation callback lacks a controller-owned durable intent",
        ));
    }
    if resume.cancellation_dispatched
        && !matches!(
            cancellation_status,
            StoredCancellationStatus::Confirmed | StoredCancellationStatus::Uncertain
        )
    {
        if cancellation_status == StoredCancellationStatus::NotRequested {
            return Err(invalid_record(
                "GitHub cancellation dispatch lacks a controller-owned durable intent",
            ));
        }
        cancellation_status = StoredCancellationStatus::Dispatched;
    }
    if evidence.cancellation_confirmed {
        cancellation_status = StoredCancellationStatus::Confirmed;
    } else if resume.cancellation_requested && outcome == Some(StoredBuildOutcome::Failed) {
        cancellation_status = StoredCancellationStatus::Failed;
    }

    let retained_failure = previous.failure.clone().filter(|_| {
        !(recoverable_cleanup_failure(previous)
            && matches!(
                (resume.state, cleanup_status),
                (
                    JobState::Cleaning,
                    StoredCleanupStatus::Pending | StoredCleanupStatus::Confirmed
                ) | (JobState::Cleaned, StoredCleanupStatus::Confirmed)
            ))
    });
    let failure = retained_failure.or_else(|| {
        if outcome == Some(StoredBuildOutcome::Failed) {
            evidence.failure.or_else(|| {
                Some(StoredFailureV1 {
                    code: "github.provider_failed".to_owned(),
                    retryable: false,
                })
            })
        } else if matches!(
            state,
            StoredJobState::Failed | StoredJobState::CleanupFailed
        ) {
            Some(StoredFailureV1 {
                code: "github.cleanup_failed".to_owned(),
                retryable: false,
            })
        } else {
            None
        }
    });

    let updated_at_ms = resume.events.iter().fold(
        previous
            .updated_at_ms
            .max(resume.created_at_ms)
            .max(resume.publication_started_at_ms)
            .max(resume.publication_absence_first_observed_at_ms),
        |latest, event| latest.max(event.timestamp_ms),
    );
    let mut next = previous.clone();
    next.revision = previous
        .revision
        .checked_add(1)
        .ok_or_else(|| invalid_record("job revision cannot advance beyond the supported range"))?;
    next.provider_job_id = Some(resume.job_id.clone());
    next.provider_run_id = github_resume_provider_run_id(resume)?;
    if next.submitted_at_ms.is_none() && resume.publication_intent {
        next.submitted_at_ms = Some(resume.publication_started_at_ms);
    }
    next.updated_at_ms = updated_at_ms;
    next.state = state;
    next.last_confirmed_state = Some(last_confirmed_state);
    next.terminal_outcome = outcome;
    next.compile_evidence.clone_from(&resume.compile_evidence);
    next.signed_cleanup_evidence
        .clone_from(&resume.signed_cleanup_evidence);
    next.artifacts = artifacts;
    next.cleanup_status = cleanup_status;
    next.cancellation_status = cancellation_status;
    next.failure = failure;
    next.provider_resume = Some(resume.clone());
    Ok(next)
}

fn validate_retry_lineage(
    local_job_id: &LocalJobId,
    lineage: &StoredRetryLineageV1,
) -> Result<(), JobStoreError> {
    if (lineage.attempt == 0) != lineage.parent_job_id.is_none() {
        return Err(invalid_record("every retry must have a parent job"));
    }
    if lineage.parent_job_id.as_ref() == Some(local_job_id) {
        return Err(invalid_record("job cannot be its own retry parent"));
    }
    if lineage.child_job_ids.len() > MAX_RETRY_CHILDREN {
        return Err(JobStoreError::BoundExceeded {
            kind: "retry children",
            maximum: MAX_RETRY_CHILDREN as u64,
        });
    }
    let mut children = BTreeSet::new();
    for child in &lineage.child_job_ids {
        if child == local_job_id || !children.insert(child) {
            return Err(invalid_record("retry children must be unique and not self"));
        }
    }
    Ok(())
}

fn validate_artifact(artifact: &StoredArtifactV1) -> Result<(), JobStoreError> {
    validate_identifier("artifact.artifact_id", &artifact.record.artifact_id)?;
    validate_portable_filename(&artifact.record.file_name)?;
    validate_sha256("artifact.sha256", &artifact.record.sha256)?;
    if let Some(media_type) = &artifact.record.media_type {
        validate_safe_text("artifact.media_type", media_type)?;
    }
    if let Some(destination) = &artifact.download_destination {
        validate_local_artifact_path("artifact.download_destination", destination)?;
    }
    match (
        &artifact.download_destination,
        &artifact.download_parent_identity,
    ) {
        (None, None) => {}
        (Some(_), Some(identity)) => {
            validate_safe_text("artifact.download_parent_identity", identity)?;
            let parsed = identity
                .parse::<DirectoryFilesystemIdentity>()
                .map_err(|_| invalid_record("artifact download parent identity is invalid"))?;
            if parsed.to_string() != *identity {
                return Err(invalid_record(
                    "artifact download parent identity is not canonical",
                ));
            }
        }
        _ => {
            return Err(invalid_record(
                "artifact destination and parent identity must be bound together",
            ));
        }
    }
    match (&artifact.local_path, &artifact.local_file_identity) {
        (None, None) if !artifact.locally_validated => {}
        (Some(path), Some(identity)) => {
            validate_local_artifact_path("artifact.local_path", path)?;
            if artifact.download_destination.as_deref() != Some(path.as_str()) {
                return Err(invalid_record(
                    "local artifact path differs from its immutable download destination",
                ));
            }
            validate_safe_text("artifact.local_file_identity", identity)?;
            let parsed = identity
                .parse::<RegularFileFilesystemIdentity>()
                .map_err(|_| invalid_record("local artifact file identity is invalid"))?;
            if parsed.to_string() != *identity {
                return Err(invalid_record(
                    "local artifact file identity is not canonical",
                ));
            }
        }
        _ => {
            return Err(invalid_record(
                "local artifact path, file identity, and validation evidence are inconsistent",
            ));
        }
    }
    Ok(())
}

fn validate_artifact_destination(
    project_root: &str,
    artifact: &StoredArtifactV1,
) -> Result<(), JobStoreError> {
    let Some(destination) = &artifact.download_destination else {
        return Ok(());
    };
    let managed_root = Path::new(project_root).join("target").join("ferry");
    let relative = Path::new(destination)
        .strip_prefix(&managed_root)
        .map_err(|_| {
            invalid_record(
                "artifact download destination is outside the exact project target/ferry tree",
            )
        })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_record(
            "artifact download destination is not a managed target/ferry descendant",
        ));
    }
    Ok(())
}

fn validate_project_root_path(value: &str) -> Result<(), JobStoreError> {
    validate_safe_text("project.canonical_root", value)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || value.contains("://")
        || value.contains('#')
        || path.file_name().is_none()
        || local_path_has_non_normal_component(value)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_record(
            "project canonical root must be normalized and absolute",
        ));
    }
    #[cfg(windows)]
    validate_windows_local_path(path)?;
    Ok(())
}

fn validate_project_selector(
    canonical_root: &str,
    filesystem_identity: &str,
) -> Result<(), JobStoreError> {
    validate_project_root_path(canonical_root)?;
    validate_safe_text("project.filesystem_identity", filesystem_identity)?;
    let identity = filesystem_identity
        .parse::<DirectoryFilesystemIdentity>()
        .map_err(|_| invalid_record("project filesystem identity is invalid"))?;
    if identity.to_string() != filesystem_identity {
        return Err(invalid_record(
            "project filesystem identity is not canonical",
        ));
    }
    Ok(())
}

fn project_selector_matches(
    project: &StoredProjectIdentityV1,
    canonical_root: &str,
    filesystem_identity: &str,
) -> bool {
    project.canonical_root == canonical_root && project.filesystem_identity == filesystem_identity
}

fn validate_local_artifact_path(field: &'static str, value: &str) -> Result<(), JobStoreError> {
    validate_safe_text(field, value)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || value.contains("://")
        || value.contains('#')
        || path_contains_query_marker(value)
        || path.file_name().is_none()
        || local_path_has_non_normal_component(value)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_record(
            "local artifact path must be normalized, absolute, and not a provider URL",
        ));
    }
    #[cfg(windows)]
    validate_windows_local_path(path)?;
    Ok(())
}

#[cfg(windows)]
fn validate_windows_local_path(path: &Path) -> Result<(), JobStoreError> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid_record(
            "local artifact path must use a drive or UNC prefix",
        ));
    };
    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::UNC(_, _) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)
    ) || components.any(|component| {
        let Component::Normal(component) = component else {
            return false;
        };
        let component = component.to_string_lossy();
        component.ends_with(['.', ' '])
            || component.contains([':', '*', '?', '"', '<', '>', '|'])
            || is_windows_reserved_component(&component)
    }) {
        return Err(invalid_record(
            "local artifact path contains a Windows device, stream, or non-portable component",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn path_contains_query_marker(value: &str) -> bool {
    value
        .strip_prefix("\\\\?\\")
        .map_or_else(|| value.contains('?'), |remainder| remainder.contains('?'))
}

#[cfg(not(windows))]
fn path_contains_query_marker(value: &str) -> bool {
    value.contains('?')
}

#[cfg(windows)]
fn local_path_has_non_normal_component(value: &str) -> bool {
    let normalized_separators = value.replace('/', "\\");
    let without_unc_prefix = normalized_separators
        .strip_prefix("\\\\")
        .unwrap_or(&normalized_separators);
    normalized_separators.ends_with('\\')
        || without_unc_prefix.contains("\\\\")
        || normalized_separators
            .split('\\')
            .any(|component| matches!(component, "." | ".."))
}

#[cfg(not(windows))]
fn local_path_has_non_normal_component(value: &str) -> bool {
    value.ends_with('/')
        || value.contains("//")
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

#[cfg(windows)]
fn local_path_uniqueness_key(value: &str) -> String {
    Path::new(value)
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>()
        .join("\0")
}

#[cfg(not(windows))]
fn local_path_uniqueness_key(value: &str) -> String {
    Path::new(value)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("\0")
}

fn validate_portable_filename(value: &str) -> Result<(), JobStoreError> {
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || value.ends_with(['.', ' '])
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(
                    byte,
                    b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
                )
        })
        || is_windows_reserved_component(value)
    {
        return Err(invalid_record(
            "artifact filename is not one portable component",
        ));
    }
    Ok(())
}

fn validate_managed_relative_path(_field: &'static str, value: &str) -> Result<(), JobStoreError> {
    validate_safe_text("managed relative path", value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || value.contains('\\')
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_string_lossy().contains(':')
        })
    {
        return Err(invalid_record(
            "managed path is not a normalized relative path",
        ));
    }
    Ok(())
}

fn validate_github_principal(
    principal: &GithubPrincipalIdentityV1,
    execution_repository_id: u64,
) -> Result<(), JobStoreError> {
    match principal {
        GithubPrincipalIdentityV1::User { id, login } if *id != 0 => {
            validate_safe_text("provider.principal.login", login)
        }
        GithubPrincipalIdentityV1::RepositoryCredential if execution_repository_id != 0 => Ok(()),
        GithubPrincipalIdentityV1::User { .. } => Err(invalid_record(
            "GitHub provider requires a stable authenticated user identity",
        )),
        GithubPrincipalIdentityV1::RepositoryCredential => Err(invalid_record(
            "GitHub repository credential requires a stable execution repository identity",
        )),
    }
}

fn validate_github_execution_repository(value: &str) -> Result<(), JobStoreError> {
    validate_safe_text("provider.execution_repository", value)?;
    let Some(slug) = value.strip_prefix("https://github.com/") else {
        return Err(invalid_record(
            "GitHub execution repository must be a canonical credential-free HTTPS URL",
        ));
    };
    let mut components = slug.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    if owner.is_empty()
        || repository.is_empty()
        || components.next().is_some()
        || slug.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        })
    {
        return Err(invalid_record(
            "GitHub execution repository must be a canonical credential-free HTTPS URL",
        ));
    }
    Ok(())
}

fn validate_optional_identifier(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), JobStoreError> {
    if let Some(value) = value {
        validate_identifier(field, value)?;
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), JobStoreError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(JobStoreError::InvalidIdentifier {
            field,
            reason: "must be bounded ASCII letters, digits, hyphens, underscores, dots, or colons",
        });
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), JobStoreError> {
    if value.is_empty() || value.len() > MAX_SAFE_TEXT_BYTES || value.chars().any(char::is_control)
    {
        return Err(JobStoreError::InvalidIdentifier {
            field,
            reason: "must be non-empty bounded text without control characters",
        });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), JobStoreError> {
    if !is_sha256(value) {
        return Err(JobStoreError::InvalidIdentifier {
            field,
            reason: "must be lowercase 64-character SHA-256 hex",
        });
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_windows_reserved_component(value: &str) -> bool {
    let basename = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(basename.as_str(), "con" | "prn" | "aux" | "nul")
        || basename
            .strip_prefix("com")
            .or_else(|| basename.strip_prefix("lpt"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn invalid_record(reason: &'static str) -> JobStoreError {
    JobStoreError::InvalidRecord { reason }
}

fn io_error(operation: &'static str, source: std::io::Error) -> JobStoreError {
    JobStoreError::Io { operation, source }
}

fn job_checkpoint_error(error: &JobStoreError) -> RemoteBuildError {
    let retryable = matches!(
        error,
        JobStoreError::JobBusy { .. }
            | JobStoreError::Io { .. }
            | JobStoreError::CommitUncertain { .. }
    );
    RemoteBuildError::ProviderFailure {
        provider: GITHUB_PROVIDER_ID.to_owned(),
        code: "job_checkpoint_persistence_failed".to_owned(),
        message: "the durable local GitHub job checkpoint could not be persisted".to_owned(),
        retryable,
    }
}

fn encode_legacy_revision(record: &StoredJobV1) -> Result<Vec<u8>, JobStoreError> {
    let mut bytes = serde_json::to_vec(record).map_err(|source| JobStoreError::Serialization {
        operation: "encode legacy job revision",
        source,
    })?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_LEGACY_JOB_REVISION_BYTES {
        return Err(JobStoreError::BoundExceeded {
            kind: "legacy job revision bytes",
            maximum: MAX_LEGACY_JOB_REVISION_BYTES,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
fn encode_revision(record: &StoredJobV1) -> Result<Vec<u8>, JobStoreError> {
    encode_legacy_revision(record)
}

fn encode_revision_v2(
    record: &StoredJobV1,
    previous_revision_sha256: Option<&str>,
) -> Result<Vec<u8>, JobStoreError> {
    match (record.revision, previous_revision_sha256) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err(invalid_record(
                "the first v2 revision cannot name a predecessor",
            ));
        }
        (_, Some(sha256)) if is_sha256(sha256) => {}
        _ => {
            return Err(invalid_record(
                "a later v2 revision requires the exact predecessor SHA-256",
            ));
        }
    }
    let envelope = StoredJobRevisionV2 {
        schema_version: JOB_REVISION_SCHEMA_VERSION,
        previous_revision_sha256: previous_revision_sha256.map(str::to_owned),
        job: record.clone(),
    };
    let mut bytes =
        serde_json::to_vec(&envelope).map_err(|source| JobStoreError::Serialization {
            operation: "encode v2 job revision",
            source,
        })?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::BoundExceeded {
            kind: "job revision bytes",
            maximum: MAX_JOB_REVISION_BYTES,
        });
    }
    Ok(bytes)
}

fn revision_filename(revision: u64, sha256: &str) -> String {
    format!("{revision:0REVISION_DIGITS$}-{sha256}.json")
}

fn revision_is_supported(revision: u64) -> bool {
    revision != 0
        && usize::try_from(revision).is_ok_and(|revision| revision <= MAX_REVISIONS_PER_JOB)
}

fn parse_revision_filename(name: &str) -> Result<(u64, String), JobStoreError> {
    let Some(stem) = name.strip_suffix(".json") else {
        return Err(JobStoreError::MalformedLayout {
            reason: "revision filename has an unsupported suffix",
        });
    };
    let Some((revision, sha256)) = stem.split_once('-') else {
        return Err(JobStoreError::MalformedLayout {
            reason: "revision filename is missing its digest",
        });
    };
    if revision.len() != REVISION_DIGITS
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || !is_sha256(sha256)
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "revision filename is not canonical",
        });
    }
    let revision = revision
        .parse::<u64>()
        .map_err(|_| JobStoreError::MalformedLayout {
            reason: "revision number is invalid",
        })?;
    if !revision_is_supported(revision) {
        return Err(JobStoreError::MalformedLayout {
            reason: "revision number is outside the supported range",
        });
    }
    Ok((revision, sha256.to_owned()))
}

fn is_revision_staging_name(name: &str) -> bool {
    name.strip_prefix(".revision-")
        .and_then(|name| name.strip_suffix(".tmp"))
        .is_some_and(|identifier| {
            identifier.len() == 32
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn revision_staging_paths(directory: &Path) -> Result<Vec<PathBuf>, JobStoreError> {
    let mut staging = Vec::new();
    let mut entries = 0_usize;
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("read revisions for recovery", source))?
    {
        entries = entries.saturating_add(1);
        if entries > MAX_REVISIONS_PER_JOB.saturating_mul(2) {
            return Err(JobStoreError::BoundExceeded {
                kind: "revision directory entries",
                maximum: (MAX_REVISIONS_PER_JOB * 2) as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read recovery entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "revision recovery filename is not UTF-8",
            })?;
        if name.starts_with(".revision-")
            || Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "tmp")
        {
            if !is_revision_staging_name(&name) {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "an unrecognized staging entry occupies the revisions directory",
                });
            }
            staging.push(entry.path());
        }
    }
    staging.sort();
    Ok(staging)
}

fn read_recovery_bytes(file: &mut File) -> Result<Vec<u8>, JobStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect recovery staging file", source))?;
    if metadata.len() > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::RecoveryRequired {
            reason: "a recovery staging file exceeds the revision bound",
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read recovery staging file", source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::RecoveryRequired {
            reason: "a recovery staging file changed while it was read",
        });
    }
    Ok(bytes)
}

fn recovery_final_link(
    directory: &Path,
    staging: &File,
    bytes: &[u8],
) -> Result<RevisionEntry, JobStoreError> {
    let staging_identity = same_file::Handle::from_file(
        staging
            .try_clone()
            .map_err(|source| io_error("clone recovery staging handle", source))?,
    )
    .map_err(|source| io_error("identify recovery staging handle", source))?;
    let mut matched = None;
    let mut entries = 0_usize;
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("scan recovery final links", source))?
    {
        entries = entries.saturating_add(1);
        if entries > MAX_REVISIONS_PER_JOB.saturating_mul(2) {
            return Err(JobStoreError::BoundExceeded {
                kind: "revision directory entries",
                maximum: (MAX_REVISIONS_PER_JOB * 2) as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read recovery final link", source))?;
        let name =
            entry
                .file_name()
                .into_string()
                .map_err(|_| JobStoreError::RecoveryRequired {
                    reason: "a recovery candidate filename is not UTF-8",
                })?;
        let Ok((revision, sha256)) = parse_revision_filename(&name) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect recovery final link", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let identity = same_file::Handle::from_path(entry.path())
            .map_err(|source| io_error("identify recovery final link", source))?;
        if identity == staging_identity {
            if matched.is_some() {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "a staging file has more than one candidate final link",
                });
            }
            matched = Some((revision, sha256, entry.path()));
        }
    }
    drop(staging_identity);
    let (revision, sha256, path) = matched.ok_or(JobStoreError::RecoveryRequired {
        reason: "a two-link staging file has no canonical final revision link",
    })?;
    if sha256_hex(bytes) != sha256 {
        return Err(JobStoreError::RecoveryRequired {
            reason: "a recovered final link does not bind its staged bytes",
        });
    }
    let previous = previous_revision_sha256(directory, revision).map_err(|_| {
        JobStoreError::RecoveryRequired {
            reason: "a published recovery pair has no exact predecessor",
        }
    })?;
    decode_revision_bytes(bytes, revision, previous.as_deref()).map_err(|_| {
        JobStoreError::RecoveryRequired {
            reason: "a published recovery pair is not a canonical supported revision",
        }
    })?;
    Ok(RevisionEntry {
        revision,
        sha256,
        path,
    })
}

#[cfg(windows)]
fn recover_revision_staging(locked: &LockedJob) -> Result<(), JobStoreError> {
    use rustferry_core::windows_private_directory::{
        PrivateDirectoryErrorKind, PrivateFileLinkState, complete_private_publication_pair,
        open_private_file_for_removal_in_state, remove_private_file_handle,
    };
    use std::os::windows::io::AsHandle as _;

    let directory = &locked.revisions;

    for path in revision_staging_paths(directory)? {
        match open_private_file_for_removal_in_state(&path, PrivateFileLinkState::Single) {
            Ok(file) => {
                remove_private_file_handle(file).map_err(|_| JobStoreError::RecoveryRequired {
                    reason: "an unpublished Windows staging file could not be removed by handle",
                })?;
            }
            Err(error) if error.kind() == PrivateDirectoryErrorKind::MultipleLinks => {
                let mut file = open_private_file_for_removal_in_state(
                    &path,
                    PrivateFileLinkState::PublicationPair,
                )
                .map_err(|_| JobStoreError::RecoveryRequired {
                    reason: "a linked Windows staging file does not have one exact publication pair",
                })?;
                let bytes = read_recovery_bytes(&mut file)?;
                let final_link = recovery_final_link(directory, &file, &bytes)?;
                let destination_name =
                    final_link
                        .path
                        .file_name()
                        .ok_or(JobStoreError::RecoveryRequired {
                            reason: "a recovered Windows final revision has no filename",
                        })?;
                let mut final_file = complete_private_publication_pair(
                    file,
                    locked.revisions_guard.as_handle(),
                    destination_name,
                )
                .map_err(|_| JobStoreError::RecoveryRequired {
                    reason: "a legacy Windows publication pair could not be sealed exactly",
                })?;
                final_file
                    .rewind()
                    .map_err(|_| JobStoreError::RecoveryRequired {
                        reason: "a recovered Windows final revision could not be rewound",
                    })?;
                let mut actual = Vec::with_capacity(bytes.len());
                (&mut final_file)
                    .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
                    .read_to_end(&mut actual)
                    .map_err(|_| JobStoreError::RecoveryRequired {
                        reason: "a recovered Windows final revision could not be reread",
                    })?;
                if actual != bytes {
                    return Err(JobStoreError::RecoveryRequired {
                        reason: "a recovered Windows final revision changed after pair collapse",
                    });
                }
            }
            Err(_) => {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "a Windows staging entry violates the private-file policy",
                });
            }
        }
        sync_directory(directory, &locked.revisions_guard)?;
    }
    Ok(())
}

#[cfg(unix)]
fn recover_revision_staging(locked: &LockedJob) -> Result<(), JobStoreError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let directory = &locked.revisions;

    for path in revision_staging_paths(directory)? {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(&path)
            .map_err(|source| io_error("open Unix recovery staging file", source))?;
        let links = file
            .metadata()
            .map_err(|source| io_error("inspect Unix recovery staging file", source))?
            .nlink();
        match links {
            1 => remove_owned_unix_staging(&file, &path).map_err(|_| {
                JobStoreError::RecoveryRequired {
                    reason: "an unpublished Unix staging file could not be safely removed",
                }
            })?,
            2 => {
                verify_unix_private_file(&file, &path, 2)?;
                let bytes = read_recovery_bytes(&mut file)?;
                let final_link = recovery_final_link(directory, &file, &bytes)?;
                verify_unix_private_file(&file, &path, 2)?;
                fs::remove_file(&path).map_err(|_| JobStoreError::RecoveryRequired {
                    reason: "a recovered Unix staging link could not be removed",
                })?;
                read_revision(&final_link.path, final_link.revision, &final_link.sha256)?;
            }
            _ => {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "a Unix staging entry has an unexpected hard-link count",
                });
            }
        }
        sync_directory(directory, &locked.revisions_guard)?;
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn recover_revision_staging(locked: &LockedJob) -> Result<(), JobStoreError> {
    let directory = &locked.revisions;
    if revision_staging_paths(directory)?.is_empty() {
        Ok(())
    } else {
        Err(JobStoreError::RecoveryRequired {
            reason: "staging recovery is unsupported on this platform",
        })
    }
}

fn scan_revision_files(directory: &Path) -> Result<Vec<RevisionEntry>, JobStoreError> {
    scan_revision_files_with_retained(directory, None, None)
}

fn scan_revision_files_with_retained(
    directory: &Path,
    retained_path: Option<&Path>,
    retained_record: Option<&StoredJobV1>,
) -> Result<Vec<RevisionEntry>, JobStoreError> {
    let mut revisions = Vec::new();
    let mut total_entries = 0_usize;
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("read revisions directory", source))?
    {
        total_entries = total_entries.saturating_add(1);
        if total_entries > MAX_REVISIONS_PER_JOB.saturating_mul(2) {
            return Err(JobStoreError::BoundExceeded {
                kind: "revision directory entries",
                maximum: (MAX_REVISIONS_PER_JOB * 2) as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read revision directory entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "revision filename is not UTF-8",
            })?;
        if is_revision_staging_name(&name) {
            return Err(JobStoreError::RecoveryRequired {
                reason: "a staging entry remains after exclusive recovery",
            });
        }
        let (revision, sha256) = parse_revision_filename(&name)?;
        let entry_path = entry.path();
        let retained_record = if retained_path == Some(entry_path.as_path()) {
            let metadata = fs::symlink_metadata(&entry_path)
                .map_err(|source| io_error("inspect retained revision entry", source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(JobStoreError::MalformedLayout {
                    reason: "retained revision entry is linked or not a regular file",
                });
            }
            Some(
                retained_record
                    .ok_or(JobStoreError::MalformedRevision {
                        reason: "retained revision payload is unavailable",
                    })?
                    .clone(),
            )
        } else {
            inspect_private_revision_file(&entry_path, MAX_JOB_REVISION_BYTES)?;
            None
        };
        revisions.push(ScannedRevisionEntry {
            entry: RevisionEntry {
                revision,
                sha256,
                path: entry_path,
            },
            retained_record,
        });
    }
    let owner = revision_directory_owner(directory)?;
    validate_scanned_revision_chain(revisions, &owner)
}

fn validate_scanned_revision_chain(
    mut revisions: Vec<ScannedRevisionEntry>,
    owner: &LocalJobId,
) -> Result<Vec<RevisionEntry>, JobStoreError> {
    if revisions.len() > MAX_REVISIONS_PER_JOB {
        return Err(JobStoreError::BoundExceeded {
            kind: "job revisions",
            maximum: MAX_REVISIONS_PER_JOB as u64,
        });
    }
    revisions.sort_by_key(|scanned| scanned.entry.revision);
    for (index, scanned) in revisions.iter().enumerate() {
        let expected = index as u64 + 1;
        if scanned.entry.revision != expected {
            return Err(JobStoreError::MalformedLayout {
                reason: "job revisions are duplicated or non-contiguous",
            });
        }
    }
    let mut saw_v2 = false;
    let mut previous_record = None;
    for (index, scanned) in revisions.iter().enumerate() {
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| revisions[previous].entry.sha256.as_str());
        let (schema_version, record) = if let Some(record) = &scanned.retained_record {
            record.validate()?;
            if record.revision == 1 {
                validate_initial_job_revision(record)?;
            }
            (JOB_REVISION_SCHEMA_VERSION, record.clone())
        } else {
            let decoded = read_decoded_revision_with_previous(
                &scanned.entry.path,
                scanned.entry.revision,
                &scanned.entry.sha256,
                expected_previous,
            )?;
            (decoded.schema_version, decoded.record)
        };
        match schema_version {
            LEGACY_JOB_REVISION_SCHEMA_VERSION if saw_v2 => {
                return Err(JobStoreError::MalformedRevision {
                    reason: "a legacy v1 revision appears after the v2 chain began",
                });
            }
            LEGACY_JOB_REVISION_SCHEMA_VERSION => {}
            JOB_REVISION_SCHEMA_VERSION => saw_v2 = true,
            found => {
                return Err(JobStoreError::UnsupportedSchema {
                    found,
                    supported: JOB_REVISION_SCHEMA_VERSION,
                });
            }
        }
        if record.local_job_id != *owner {
            return Err(JobStoreError::MalformedRevision {
                reason: "revision local job ID differs from its job directory",
            });
        }
        if let Some(previous) = &previous_record {
            validate_successor(previous, &record)?;
        }
        previous_record = Some(record);
    }
    Ok(revisions.into_iter().map(|scanned| scanned.entry).collect())
}

fn revision_directory_owner(directory: &Path) -> Result<LocalJobId, JobStoreError> {
    if directory.file_name() != Some(OsStr::new(REVISIONS_DIRECTORY)) {
        return Err(JobStoreError::MalformedLayout {
            reason: "revision scan path is not the managed revisions directory",
        });
    }
    let job = directory.parent().ok_or(JobStoreError::MalformedLayout {
        reason: "revisions directory has no owning job directory",
    })?;
    let owner = job
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(JobStoreError::MalformedLayout {
            reason: "job directory owner is not canonical UTF-8",
        })?;
    LocalJobId::new(owner.to_owned())
}

fn decode_revision_bytes(
    bytes: &[u8],
    revision: u64,
    previous_revision_sha256: Option<&str>,
) -> Result<DecodedRevision, JobStoreError> {
    serde_json::from_slice::<IgnoredAny>(bytes).map_err(|_| JobStoreError::MalformedRevision {
        reason: "revision is not valid JSON",
    })?;
    let schema = serde_json::from_slice::<RevisionSchemaProbe>(bytes)
        .map_err(|_| JobStoreError::MalformedRevision {
            reason: "revision has no unique numeric schema version",
        })?
        .schema_version;
    let record = match schema {
        LEGACY_JOB_REVISION_SCHEMA_VERSION => {
            if bytes.len() as u64 > MAX_LEGACY_JOB_REVISION_BYTES {
                return Err(JobStoreError::BoundExceeded {
                    kind: "legacy job revision bytes",
                    maximum: MAX_LEGACY_JOB_REVISION_BYTES,
                });
            }
            let record = serde_json::from_slice::<StoredJobV1>(bytes).map_err(|_| {
                JobStoreError::MalformedRevision {
                    reason: "revision fields do not match the formal v1 schema",
                }
            })?;
            if encode_legacy_revision(&record)? != bytes {
                return Err(JobStoreError::MalformedRevision {
                    reason: "revision bytes are not the canonical secret-free v1 encoding",
                });
            }
            record
        }
        JOB_REVISION_SCHEMA_VERSION => {
            let envelope = serde_json::from_slice::<StoredJobRevisionV2>(bytes).map_err(|_| {
                JobStoreError::MalformedRevision {
                    reason: "revision fields do not match the v2 envelope schema",
                }
            })?;
            let expected_previous = if revision == 1 {
                None
            } else {
                Some(
                    previous_revision_sha256.ok_or(JobStoreError::MalformedLayout {
                        reason: "a v2 revision is missing its predecessor file",
                    })?,
                )
            };
            if envelope.schema_version != JOB_REVISION_SCHEMA_VERSION
                || envelope.previous_revision_sha256.as_deref() != expected_previous
            {
                return Err(JobStoreError::MalformedRevision {
                    reason: "v2 predecessor binding differs from the immutable revision chain",
                });
            }
            if encode_revision_v2(&envelope.job, expected_previous)? != bytes {
                return Err(JobStoreError::MalformedRevision {
                    reason: "revision bytes are not the canonical secret-free v2 encoding",
                });
            }
            envelope.job
        }
        found => {
            return Err(JobStoreError::UnsupportedSchema {
                found,
                supported: JOB_REVISION_SCHEMA_VERSION,
            });
        }
    };
    if record.revision != revision {
        return Err(JobStoreError::MalformedRevision {
            reason: "payload revision differs from its filename",
        });
    }
    record.validate()?;
    if record.revision == 1 {
        validate_initial_job_revision(&record)?;
    }
    Ok(DecodedRevision {
        record,
        schema_version: schema,
        bytes: bytes.to_vec(),
    })
}

fn previous_revision_sha256(
    directory: &Path,
    revision: u64,
) -> Result<Option<String>, JobStoreError> {
    if revision == 1 {
        return Ok(None);
    }
    let expected = revision - 1;
    let mut found = None;
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("scan revision predecessor", source))?
    {
        let entry = entry.map_err(|source| io_error("read revision predecessor", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "revision predecessor filename is not UTF-8",
            })?;
        if is_revision_staging_name(&name) {
            continue;
        }
        let (candidate_revision, sha256) = parse_revision_filename(&name)?;
        if candidate_revision == expected && found.replace(sha256).is_some() {
            return Err(JobStoreError::MalformedLayout {
                reason: "revision predecessor is duplicated",
            });
        }
    }
    found.map(Some).ok_or(JobStoreError::MalformedLayout {
        reason: "revision predecessor is missing",
    })
}

fn read_decoded_revision(
    path: &Path,
    revision: u64,
    expected_sha256: &str,
) -> Result<DecodedRevision, JobStoreError> {
    let directory = path.parent().ok_or(JobStoreError::MalformedLayout {
        reason: "revision file has no parent directory",
    })?;
    let previous = previous_revision_sha256(directory, revision)?;
    read_decoded_revision_with_previous(path, revision, expected_sha256, previous.as_deref())
}

fn read_decoded_revision_with_previous(
    path: &Path,
    revision: u64,
    expected_sha256: &str,
    previous_revision_sha256: Option<&str>,
) -> Result<DecodedRevision, JobStoreError> {
    let mut file = open_private_revision_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect open job revision", source))?;
    if metadata.len() > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::BoundExceeded {
            kind: "job revision bytes",
            maximum: MAX_JOB_REVISION_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    (&mut file)
        .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read job revision", source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_JOB_REVISION_BYTES {
        return Err(JobStoreError::BoundExceeded {
            kind: "job revision bytes",
            maximum: MAX_JOB_REVISION_BYTES,
        });
    }
    verify_open_private_revision_file(&file, path)?;
    if sha256_hex(&bytes) != expected_sha256 {
        return Err(JobStoreError::MalformedRevision {
            reason: "revision bytes do not match the filename digest",
        });
    }
    decode_revision_bytes(&bytes, revision, previous_revision_sha256)
}

fn read_revision(
    path: &Path,
    revision: u64,
    expected_sha256: &str,
) -> Result<StoredJobV1, JobStoreError> {
    read_decoded_revision(path, revision, expected_sha256).map(|decoded| decoded.record)
}

fn read_job_revision(
    path: &Path,
    revision: u64,
    expected_sha256: &str,
    local_job_id: &LocalJobId,
) -> Result<StoredJobV1, JobStoreError> {
    let record = read_revision(path, revision, expected_sha256)?;
    if record.local_job_id != *local_job_id {
        return Err(JobStoreError::MalformedRevision {
            reason: "revision local job ID differs from its job directory",
        });
    }
    Ok(record)
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(Sha256::digest(bytes))
}

fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(SHA256_HEX_BYTES);
    for &byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(windows)]
fn ensure_private_directory(path: &Path) -> Result<File, JobStoreError> {
    use rustferry_core::windows_private_directory::{
        PrivateDirectoryErrorKind, create_private_directory,
    };

    match fs::symlink_metadata(path) {
        Ok(_) => open_windows_private_directory_read_guard_retry(
            path,
            "open existing private directory read guard",
        ),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            private_directory_before_create_checkpoint(path);
            match create_private_directory(path) {
                Ok(directory) => Ok(directory),
                Err(error) if error.kind() == PrivateDirectoryErrorKind::AlreadyExists => {
                    open_windows_private_directory_read_guard_retry(
                        path,
                        "open raced private directory read guard",
                    )
                }
                Err(error) => Err(windows_security_error("create private directory", &error)),
            }
        }
        Err(source) => Err(io_error("inspect private directory", source)),
    }
}

#[cfg(windows)]
fn private_directory_before_create_checkpoint(path: &Path) {
    #[cfg(not(test))]
    let _ = path;
    #[cfg(test)]
    {
        let pause = PRIVATE_DIRECTORY_RACE_TEST_CONTROL
            .lock()
            .expect("private-directory race test-control lock is not poisoned")
            .as_ref()
            .filter(|control| control.path == path)
            .map(|control| {
                (
                    std::sync::Arc::clone(&control.entered),
                    std::sync::Arc::clone(&control.release),
                )
            });
        if let Some((entered, release)) = pause {
            entered.wait();
            release.wait();
        }
    }
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<File, JobStoreError> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(source) = builder.create(path)
                && source.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(io_error("create private directory", source));
            }
        }
        Err(source) => return Err(io_error("inspect private directory", source)),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options
        .open(path)
        .map_err(|source| io_error("open private directory", source))?;
    verify_unix_private_directory(&directory, path)?;
    Ok(directory)
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_private_directory(path: &Path) -> Result<File, JobStoreError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create private directory", source)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect private directory", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JobStoreError::MalformedLayout {
            reason: "private directory is linked or not a directory",
        });
    }
    File::open(path).map_err(|source| io_error("open private directory", source))
}

fn open_existing_private_directory(path: &Path) -> Result<File, JobStoreError> {
    #[cfg(windows)]
    {
        open_windows_private_directory_read_guard_retry(
            path,
            "open existing private directory read guard",
        )
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let directory = options
            .open(path)
            .map_err(|source| io_error("open existing private directory", source))?;
        verify_unix_private_directory(&directory, path)?;
        Ok(directory)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("inspect existing private directory", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(JobStoreError::MalformedLayout {
                reason: "private directory is linked or not a directory",
            });
        }
        File::open(path).map_err(|source| io_error("open existing private directory", source))
    }
}

#[cfg(windows)]
fn open_windows_private_directory_read_guard_retry(
    path: &Path,
    operation: &'static str,
) -> Result<File, JobStoreError> {
    use std::{thread, time::Duration};

    use rustferry_core::windows_private_directory::open_private_directory_read_guard;

    const MAX_SHARING_RETRIES: usize = 32;
    for attempt in 0..=MAX_SHARING_RETRIES {
        match open_private_directory_read_guard(path) {
            Ok(directory) => return Ok(directory),
            Err(error) if error.os_code() == Some(32) && attempt < MAX_SHARING_RETRIES => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(windows_security_error(operation, &error)),
        }
    }
    unreachable!("bounded Windows directory-read-guard retry always returns")
}

fn open_private_directory_if_present(
    path: &Path,
    malformed_reason: &'static str,
) -> Result<Option<File>, JobStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            open_existing_private_directory(path).map(Some)
        }
        Ok(_) => Err(JobStoreError::MalformedLayout {
            reason: malformed_reason,
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("inspect existing private directory", source)),
    }
}

fn open_existing_private_lock(path: &Path) -> Result<Option<File>, JobStoreError> {
    match fs::symlink_metadata(path) {
        #[cfg(windows)]
        Ok(_) => rustferry_core::windows_private_directory::open_private_lock_file(path)
            .map(Some)
            .map_err(|error| windows_security_error("open private job lock", &error)),
        #[cfg(not(windows))]
        Ok(_) => open_private_revision_file(path).map(Some),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("inspect private job lock", source)),
    }
}

fn verify_private_lock_identity(lock: &File, path: &Path) -> Result<(), JobStoreError> {
    let linked = open_existing_private_lock(path)?.ok_or(JobStoreError::MalformedLayout {
        reason: "the acquired job lock is absent from its retained private layout",
    })?;
    let opened = same_file::Handle::from_file(
        lock.try_clone()
            .map_err(|source| io_error("clone acquired private job lock", source))?,
    )
    .map_err(|source| io_error("identify acquired private job lock", source))?;
    let linked = same_file::Handle::from_file(linked)
        .map_err(|source| io_error("identify linked private job lock", source))?;
    if opened != linked {
        return Err(JobStoreError::Security {
            operation: "revalidate private job lock",
            message: "the acquired lock is detached from the retained job layout".to_owned(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn verify_unix_private_directory(file: &File, path: &Path) -> Result<(), JobStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect open private directory", source))?;
    let linked = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect linked private directory", source))?;
    if !metadata.is_dir()
        || linked.file_type().is_symlink()
        || !linked.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.dev() != linked.dev()
        || metadata.ino() != linked.ino()
    {
        return Err(JobStoreError::Security {
            operation: "verify Unix private directory",
            message: "expected one stable non-symlink directory with mode 0700".to_owned(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn windows_security_error(
    operation: &'static str,
    error: &rustferry_core::windows_private_directory::PrivateDirectoryError,
) -> JobStoreError {
    JobStoreError::Security {
        operation,
        message: error.to_string(),
    }
}

#[cfg(windows)]
fn open_or_create_private_lock(path: &Path) -> Result<File, JobStoreError> {
    use rustferry_core::windows_private_directory::{
        PrivateDirectoryErrorKind, create_private_lock_file, open_private_lock_file,
    };

    match fs::symlink_metadata(path) {
        Ok(_) => open_private_lock_file(path)
            .map_err(|error| windows_security_error("open private job lock", &error)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            match create_private_lock_file(path) {
                Ok(file) => Ok(file),
                Err(error) if error.kind() == PrivateDirectoryErrorKind::AlreadyExists => {
                    open_private_lock_file(path).map_err(|error| {
                        windows_security_error("open raced private job lock", &error)
                    })
                }
                Err(error) => Err(windows_security_error("create private job lock", &error)),
            }
        }
        Err(source) => Err(io_error("inspect private job lock", source)),
    }
}

#[cfg(unix)]
fn open_or_create_private_lock(path: &Path) -> Result<File, JobStoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|source| io_error("open private job lock", source))?;
    verify_unix_private_file(&file, path, 1)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_or_create_private_lock(path: &Path) -> Result<File, JobStoreError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| io_error("open private job lock", source))
}

fn inspect_private_revision_file(path: &Path, maximum: u64) -> Result<(), JobStoreError> {
    let file = open_private_revision_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect private revision file", source))?;
    if metadata.len() > maximum {
        return Err(JobStoreError::BoundExceeded {
            kind: "job revision bytes",
            maximum,
        });
    }
    Ok(())
}

#[cfg(windows)]
fn open_private_revision_file(path: &Path) -> Result<File, JobStoreError> {
    rustferry_core::windows_private_directory::open_private_file(path)
        .map_err(|error| windows_security_error("open private job revision", &error))
}

#[cfg(windows)]
fn open_private_revision_file_for_sync(path: &Path) -> Result<File, JobStoreError> {
    rustferry_core::windows_private_directory::open_private_file_for_sync(path)
        .map_err(|error| windows_security_error("open private job revision for sync", &error))
}

#[cfg(not(windows))]
fn open_private_revision_file_for_sync(path: &Path) -> Result<File, JobStoreError> {
    open_private_revision_file(path)
}

#[cfg(unix)]
fn open_private_revision_file(path: &Path) -> Result<File, JobStoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|source| io_error("open private job revision", source))?;
    verify_unix_private_file(&file, path, 1)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_private_revision_file(path: &Path) -> Result<File, JobStoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect private job revision", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JobStoreError::MalformedLayout {
            reason: "job revision is linked or not a regular file",
        });
    }
    File::open(path).map_err(|source| io_error("open private job revision", source))
}

fn verify_open_private_revision_file(file: &File, path: &Path) -> Result<(), JobStoreError> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;

        rustferry_core::windows_private_directory::verify_private_file_handle(file.as_handle())
            .map_err(|error| windows_security_error("reverify private job revision", &error))?;
        verify_file_identity(file, path)?;
    }
    #[cfg(unix)]
    verify_unix_private_file(file, path, 1)?;
    #[cfg(all(not(unix), not(windows)))]
    verify_file_identity(file, path)?;
    Ok(())
}

fn verify_file_identity(file: &File, path: &Path) -> Result<(), JobStoreError> {
    let opened = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("clone private file handle", source))?,
    )
    .map_err(|source| io_error("identify open private file", source))?;
    let linked = same_file::Handle::from_path(path)
        .map_err(|source| io_error("identify linked private file", source))?;
    if opened != linked {
        return Err(JobStoreError::Security {
            operation: "verify private file identity",
            message: "the path no longer identifies the opened file".to_owned(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn verify_unix_private_file(
    file: &File,
    path: &Path,
    expected_links: u64,
) -> Result<(), JobStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect open private file", source))?;
    let linked = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect linked private file", source))?;
    if !metadata.is_file()
        || linked.file_type().is_symlink()
        || !linked.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != expected_links
        || metadata.dev() != linked.dev()
        || metadata.ino() != linked.ino()
    {
        return Err(JobStoreError::Security {
            operation: "verify Unix private file",
            message:
                "expected one stable non-symlink regular file with mode 0600 and exact link count"
                    .to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn publication_checkpoint(
    final_path: &Path,
    checkpoint: PublicationCheckpoint,
) -> Result<(), JobStoreError> {
    let control = {
        let mut control = PUBLICATION_TEST_CONTROL
            .lock()
            .expect("publication test-control lock is not poisoned");
        let matches = control.as_ref().is_some_and(|control| {
            control.final_path == final_path && control.checkpoint == checkpoint
        });
        matches.then(|| control.take().expect("matched test control is present"))
    };
    let Some(control) = control else {
        return Ok(());
    };
    match control.action {
        PublicationTestAction::Fail => Err(JobStoreError::CommitUncertain {
            reason: "injected immutable-revision publication uncertainty",
        }),
        PublicationTestAction::Pause { entered, release } => {
            entered.wait();
            release.wait();
            Ok(())
        }
    }
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "production checkpoint is a no-op while tests inject fallible crash boundaries"
)]
fn publication_checkpoint(
    _final_path: &Path,
    _checkpoint: PublicationCheckpoint,
) -> Result<(), JobStoreError> {
    Ok(())
}

fn publish_create_only(
    locked: &LockedJob,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), PublicationFailure> {
    #[cfg(windows)]
    {
        publish_create_only_platform(locked, final_path, bytes)
    }
    #[cfg(not(windows))]
    {
        publish_create_only_platform(locked, final_path, bytes).map_err(PublicationFailure::from)
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the retained-handle publication transaction keeps every uncertain exit auditable"
)]
fn publish_create_only_platform(
    locked: &LockedJob,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), PublicationFailure> {
    use rustferry_core::windows_private_directory::{
        PrivatePublicationPhase, create_private_file, publish_private_file_handle_create_new,
        verify_private_file_handle,
    };
    use std::os::windows::io::AsHandle as _;

    let directory = &locked.revisions;
    let staging_path = directory.join(format!(".revision-{}.tmp", Uuid::new_v4().simple()));
    let mut staging = create_private_file(&staging_path)
        .map_err(|error| windows_security_error("create private revision staging file", &error))
        .map_err(PublicationFailure::from)?;
    if let Err(source) = staging.write_all(bytes).and_then(|()| staging.sync_all()) {
        return Err(fail_unpublished_windows_staging(
            staging,
            io_error("write private revision staging file", source),
        )
        .into());
    }
    if let Err(error) = verify_private_file_handle(staging.as_handle()) {
        return Err(fail_unpublished_windows_staging(
            staging,
            windows_security_error("verify private revision staging file", &error),
        )
        .into());
    }
    let destination_name = final_path
        .file_name()
        .ok_or_else(|| invalid_record("revision destination has no filename"))
        .map_err(PublicationFailure::from)?;
    let mut final_file = match publish_private_file_handle_create_new(
        staging,
        locked.revisions_guard.as_handle(),
        destination_name,
    ) {
        Ok(file) => file,
        Err(error) => {
            let (phase, retained, error) = error.into_parts();
            if phase == PrivatePublicationPhase::Unpublished {
                return Err(fail_unpublished_windows_staging(
                    retained,
                    windows_security_error("publish immutable revision without overwrite", &error),
                )
                .into());
            }
            return Err(committed_windows_publication_failure(
                retained,
                "handle-bound Windows revision publication could not prove its final namespace",
            ));
        }
    };
    if let Err(error) = publication_checkpoint(final_path, PublicationCheckpoint::BeforeFinalSync) {
        return Err(PublicationFailure {
            error,
            retained_file: Some(final_file),
        });
    }
    if final_file.sync_all().is_err() {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision metadata could not be flushed",
        ));
    }
    if let Err(error) = publication_checkpoint(final_path, PublicationCheckpoint::FinalLinked) {
        return Err(PublicationFailure {
            error,
            retained_file: Some(final_file),
        });
    }
    if let Err(error) = publication_checkpoint(final_path, PublicationCheckpoint::StagingRemoved) {
        return Err(PublicationFailure {
            error,
            retained_file: Some(final_file),
        });
    }
    if final_file.rewind().is_err() {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision could not be rewound for readback",
        ));
    }
    let mut actual = Vec::with_capacity(bytes.len());
    if (&mut final_file)
        .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .is_err()
    {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision could not be reread",
        ));
    }
    if actual != bytes {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision bytes changed",
        ));
    }
    if verify_private_file_handle(final_file.as_handle()).is_err()
        || verify_file_identity(&final_file, final_path).is_err()
    {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision identity changed",
        ));
    }
    if let Err(error) = publication_checkpoint(final_path, PublicationCheckpoint::FinalReadBack) {
        return Err(PublicationFailure {
            error,
            retained_file: Some(final_file),
        });
    }
    if sync_directory(directory, &locked.revisions_guard).is_err() {
        return Err(committed_windows_publication_failure(
            final_file,
            "published Windows revision directory metadata could not be flushed",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn committed_windows_publication_failure(file: File, reason: &'static str) -> PublicationFailure {
    PublicationFailure {
        error: JobStoreError::CommitUncertain { reason },
        retained_file: Some(file),
    }
}

#[cfg(windows)]
fn fail_unpublished_windows_staging(staging: File, original: JobStoreError) -> JobStoreError {
    use rustferry_core::windows_private_directory::remove_private_file_handle;

    match remove_private_file_handle(staging) {
        Ok(()) => original,
        Err(_) => JobStoreError::RecoveryRequired {
            reason: "an unpublished Windows staging file could not be removed by handle",
        },
    }
}

#[cfg(unix)]
fn publish_create_only_platform(
    locked: &LockedJob,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), JobStoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let directory = &locked.revisions;
    let staging_path = directory.join(format!(".revision-{}.tmp", Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut staging = options
        .open(&staging_path)
        .map_err(|source| io_error("create private revision staging file", source))?;
    if let Err(source) = staging.write_all(bytes).and_then(|()| staging.sync_all()) {
        return Err(fail_unpublished_unix_staging(
            &staging,
            &staging_path,
            io_error("write private revision staging file", source),
        ));
    }
    if verify_unix_private_file(&staging, &staging_path, 1).is_err() {
        return Err(JobStoreError::RecoveryRequired {
            reason: "an unpublished Unix staging file violates the private-file policy",
        });
    }
    if let Err(source) = fs::hard_link(&staging_path, final_path) {
        return Err(fail_unpublished_unix_staging(
            &staging,
            &staging_path,
            io_error("publish immutable revision without overwrite", source),
        ));
    }
    verify_unix_private_file(&staging, &staging_path, 2).map_err(|_| {
        JobStoreError::CommitUncertain {
            reason: "published Unix file did not retain the exact two-link state",
        }
    })?;
    verify_file_identity(&staging, final_path).map_err(|_| JobStoreError::CommitUncertain {
        reason: "published Unix path differs from the staged file",
    })?;
    publication_checkpoint(final_path, PublicationCheckpoint::BeforeFinalSync)?;
    staging
        .sync_all()
        .map_err(|_| JobStoreError::CommitUncertain {
            reason: "published Unix revision metadata could not be flushed",
        })?;
    publication_checkpoint(final_path, PublicationCheckpoint::FinalLinked)?;
    fs::remove_file(&staging_path).map_err(|_| JobStoreError::CommitUncertain {
        reason: "published Unix file retains its staging link",
    })?;
    publication_checkpoint(final_path, PublicationCheckpoint::StagingRemoved)?;
    let mut final_file =
        open_private_revision_file(final_path).map_err(|_| JobStoreError::CommitUncertain {
            reason: "published Unix revision failed final private-file verification",
        })?;
    let mut actual = Vec::with_capacity(bytes.len());
    (&mut final_file)
        .take(MAX_JOB_REVISION_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|_| JobStoreError::CommitUncertain {
            reason: "published Unix revision could not be reread",
        })?;
    if actual != bytes {
        return Err(JobStoreError::CommitUncertain {
            reason: "published Unix revision bytes changed",
        });
    }
    verify_file_identity(&final_file, final_path).map_err(|_| JobStoreError::CommitUncertain {
        reason: "published Unix revision identity changed",
    })?;
    publication_checkpoint(final_path, PublicationCheckpoint::FinalReadBack)?;
    sync_directory(directory, &locked.revisions_guard)
}

#[cfg(all(not(unix), not(windows)))]
fn publish_create_only_platform(
    locked: &LockedJob,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), JobStoreError> {
    let directory = &locked.revisions;
    let staging_path = directory.join(format!(".revision-{}.tmp", Uuid::new_v4().simple()));
    let mut staging = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&staging_path)
        .map_err(|source| io_error("create private revision staging file", source))?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write private revision staging file", source))?;
    fs::hard_link(&staging_path, final_path)
        .map_err(|source| io_error("publish immutable revision without overwrite", source))?;
    verify_file_identity(&staging, final_path)?;
    publication_checkpoint(final_path, PublicationCheckpoint::FinalLinked)?;
    fs::remove_file(&staging_path)
        .map_err(|source| io_error("remove revision staging link", source))?;
    publication_checkpoint(final_path, PublicationCheckpoint::StagingRemoved)?;
    publication_checkpoint(final_path, PublicationCheckpoint::FinalReadBack)?;
    Ok(())
}

#[cfg(unix)]
fn remove_owned_unix_staging(file: &File, path: &Path) -> Result<(), JobStoreError> {
    verify_unix_private_file(file, path, 1)?;
    fs::remove_file(path)
        .map_err(|source| io_error("remove unpublished revision staging file", source))
}

#[cfg(unix)]
fn fail_unpublished_unix_staging(
    staging: &File,
    staging_path: &Path,
    original: JobStoreError,
) -> JobStoreError {
    match remove_owned_unix_staging(staging, staging_path) {
        Ok(()) => original,
        Err(_) => JobStoreError::RecoveryRequired {
            reason: "an unpublished Unix staging file could not be safely removed",
        },
    }
}

#[cfg(windows)]
fn sync_directory(_directory: &Path, guard: &File) -> Result<(), JobStoreError> {
    use std::os::windows::io::AsHandle as _;

    rustferry_core::windows_private_directory::sync_private_directory_handle(guard.as_handle())
        .map_err(|error| windows_security_error("sync private directory metadata", &error))
}

#[cfg(not(windows))]
fn sync_directory(_directory: &Path, guard: &File) -> Result<(), JobStoreError> {
    guard
        .sync_all()
        .map_err(|source| io_error("sync revision directory", source))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Barrier},
        thread,
    };

    use rustferry_github::provider::{
        GithubRunIdentityV1, GithubWorkflowDispatchReceiptV1, GithubWorkflowDispatchResumeV1,
    };
    use rustferry_remote::{
        ArtifactKind, BundleIdentifier, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
        CURRENT_PROTOCOL_VERSION, CleanupConfirmation, CompileToolchainEvidence,
        IOS_DEVICE_RUST_TARGET, IosArtifactType, IosDeviceBuildResult, IosDeviceProductExpectation,
        JobState, RemoteBuildEvent, RemoteBuildEventKind, RemoteErrorInfo,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningPlan, SigningTarget,
        SigningTargetKind, SourceArchive, SourceManifest, SourceManifestEntry, SourceMode,
        UnsignedAppInspection, UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection,
    };
    use serde_json::Value;
    use tempfile::TempDir;

    use super::*;

    const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn round_trip_preserves_append_only_revisions_and_latest() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-round-trip", 100);
        let receipt = fixture.store.create(&first).expect("create first revision");
        assert_eq!(receipt.revision, 1);
        assert!(!receipt.already_present);
        assert_eq!(receipt.sha256.len(), SHA256_HEX_BYTES);
        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), first);

        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_ms = 101;
        second.state = StoredJobState::Submitting;
        fixture
            .store
            .append(&second)
            .expect("append second revision");

        assert_eq!(
            fixture.store.revision(&second.local_job_id, 1).unwrap(),
            first
        );
        assert_eq!(fixture.store.latest(&second.local_job_id).unwrap(), second);
        let names = revision_names(&fixture.store, &second.local_job_id);
        assert_eq!(names.len(), 2);
        assert!(names[0].starts_with("00000000000000000001-"));
        assert!(names[1].starts_with("00000000000000000002-"));
    }

    #[test]
    fn fresh_v2_chain_binds_exact_predecessor_bytes_and_reopens() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v2-chain", 100);
        let first_receipt = fixture.store.create(&first).unwrap();
        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_ms = 101;
        second.state = StoredJobState::Submitting;
        let second_receipt = fixture.store.append(&second).unwrap();

        let entries = exact_revision_entries(&fixture.store, &first.local_job_id);
        assert_eq!(entries.len(), 2);
        let first_bytes = fs::read(&entries[0].path).unwrap();
        let second_bytes = fs::read(&entries[1].path).unwrap();
        let first_envelope = serde_json::from_slice::<StoredJobRevisionV2>(&first_bytes).unwrap();
        let second_envelope = serde_json::from_slice::<StoredJobRevisionV2>(&second_bytes).unwrap();
        assert_eq!(first_envelope.schema_version, JOB_REVISION_SCHEMA_VERSION);
        assert_eq!(first_envelope.previous_revision_sha256, None);
        assert_eq!(first_envelope.job, first);
        assert_eq!(second_envelope.schema_version, JOB_REVISION_SCHEMA_VERSION);
        assert_eq!(
            second_envelope.previous_revision_sha256.as_deref(),
            Some(first_receipt.sha256.as_str())
        );
        assert_eq!(second_envelope.job, second);
        assert_eq!(sha256_hex(&first_bytes), first_receipt.sha256);
        assert_eq!(sha256_hex(&second_bytes), second_receipt.sha256);

        let reopened = JobStore::open_at(fixture.store.root()).unwrap();
        assert_eq!(reopened.revision(&first.local_job_id, 1).unwrap(), first);
        assert_eq!(reopened.latest(&second.local_job_id).unwrap(), second);
        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert_eq!(read_only.latest(&second.local_job_id).unwrap(), second);
        assert_eq!(read_only.list_latest(1).unwrap()[0].revision, 2);
    }

    #[test]
    fn formal_v1_reads_byte_exact_and_migrates_create_only() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-formal-v1", 100);
        let legacy_bytes = encode_legacy_revision(&first).unwrap();
        let legacy_sha256 = sha256_hex(&legacy_bytes);
        publish_raw_revision(&fixture.store, &first.local_job_id, 1, &legacy_bytes);
        let legacy_path = exact_revision_entries(&fixture.store, &first.local_job_id)[0]
            .path
            .clone();

        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), first);
        assert_eq!(
            fixture.store.revision(&first.local_job_id, 1).unwrap(),
            first
        );
        assert_eq!(fixture.store.list_latest(1).unwrap()[0].revision, 1);
        let idempotent = fixture.store.create(&first).unwrap();
        assert!(idempotent.already_present);
        assert_eq!(idempotent.sha256, legacy_sha256);
        assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 1);

        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert_eq!(read_only.latest(&first.local_job_id).unwrap(), first);
        assert!(matches!(
            read_only.migrate_job(&first.local_job_id),
            Err(JobStoreError::ReadOnly)
        ));
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 1);

        let receipt = fixture.store.migrate_job(&first.local_job_id).unwrap();
        assert!(receipt.migrated);
        assert!(!receipt.already_present);
        assert_eq!(
            receipt.from_schema_version,
            LEGACY_JOB_REVISION_SCHEMA_VERSION
        );
        assert_eq!(receipt.to_schema_version, JOB_REVISION_SCHEMA_VERSION);
        let migrated = fixture.store.latest(&first.local_job_id).unwrap();
        let mut expected = first.clone();
        expected.revision = 2;
        assert_eq!(migrated, expected);
        assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
        let entries = exact_revision_entries(&fixture.store, &first.local_job_id);
        let envelope =
            serde_json::from_slice::<StoredJobRevisionV2>(&fs::read(&entries[1].path).unwrap())
                .unwrap();
        assert_eq!(
            envelope.previous_revision_sha256.as_deref(),
            Some(legacy_sha256.as_str())
        );
        assert_eq!(envelope.job, expected);

        let repeated = fixture.store.migrate_job(&first.local_job_id).unwrap();
        assert!(!repeated.migrated);
        assert!(repeated.already_present);
        assert_eq!(repeated.revision, 2);
        assert_eq!(repeated.sha256, receipt.sha256);
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 2);
    }

    #[test]
    fn ordinary_update_starts_v2_after_a_formal_v1_prefix() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v1-direct-update", 100);
        let legacy_bytes = encode_legacy_revision(&first).unwrap();
        let legacy_sha256 = sha256_hex(&legacy_bytes);
        publish_raw_revision(&fixture.store, &first.local_job_id, 1, &legacy_bytes);

        let receipt = fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Submitting;
                Ok(next)
            })
            .unwrap();
        let entries = exact_revision_entries(&fixture.store, &first.local_job_id);
        let bytes = fs::read(&entries[1].path).unwrap();
        let envelope = serde_json::from_slice::<StoredJobRevisionV2>(&bytes).unwrap();
        assert_eq!(
            envelope.previous_revision_sha256.as_deref(),
            Some(legacy_sha256.as_str())
        );
        assert_eq!(sha256_hex(&bytes), receipt.sha256);
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().revision,
            2
        );
    }

    #[test]
    fn identical_legacy_checkpoint_is_a_durable_noop() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v1-checkpoint-noop", 100);
        let first_bytes = encode_legacy_revision(&first).unwrap();
        publish_raw_revision(&fixture.store, &first.local_job_id, 1, &first_bytes);
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let resume = github_resume(&allocated);
        let second = project_github_resume(&first, &resume).unwrap();
        let second_bytes = encode_legacy_revision(&second).unwrap();
        publish_raw_revision(&fixture.store, &first.local_job_id, 2, &second_bytes);

        assert!(
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &resume)
                .unwrap()
                .is_none()
        );
        let entries = exact_revision_entries(&fixture.store, &first.local_job_id);
        assert_eq!(entries.len(), 2);
        assert_eq!(fs::read(&entries[1].path).unwrap(), second_bytes);
    }

    #[test]
    fn v2_chain_rejects_wrong_historical_binding_and_v1_downgrade() {
        let wrong = StoreFixture::new();
        let first = wrong.record("job-wrong-v2-edge", 100);
        let first_bytes = encode_revision_v2(&first, None).unwrap();
        publish_raw_revision(&wrong.store, &first.local_job_id, 1, &first_bytes);
        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_ms += 1;
        second.state = StoredJobState::Submitting;
        let second_bytes = encode_revision_v2(&second, Some(&"b".repeat(64))).unwrap();
        let second_sha256 = sha256_hex(&second_bytes);
        publish_raw_revision(&wrong.store, &first.local_job_id, 2, &second_bytes);
        let mut third = second.clone();
        third.revision = 3;
        third.updated_at_ms += 1;
        let third_bytes = encode_revision_v2(&third, Some(&second_sha256)).unwrap();
        publish_raw_revision(&wrong.store, &first.local_job_id, 3, &third_bytes);
        assert!(matches!(
            wrong.store.latest(&first.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "v2 predecessor binding differs from the immutable revision chain"
            })
        ));

        let downgrade = StoreFixture::new();
        let first = downgrade.record("job-v1-after-v2", 100);
        publish_raw_revision(
            &downgrade.store,
            &first.local_job_id,
            1,
            &encode_revision_v2(&first, None).unwrap(),
        );
        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_ms += 1;
        second.state = StoredJobState::Submitting;
        publish_raw_revision(
            &downgrade.store,
            &first.local_job_id,
            2,
            &encode_legacy_revision(&second).unwrap(),
        );
        assert!(matches!(
            downgrade.store.latest(&first.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "a legacy v1 revision appears after the v2 chain began"
            })
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn migration_publication_uncertainty_reconciles_exact_envelope() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        for (index, checkpoint) in [
            PublicationCheckpoint::BeforeFinalSync,
            PublicationCheckpoint::FinalLinked,
            PublicationCheckpoint::StagingRemoved,
            PublicationCheckpoint::FinalReadBack,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = StoreFixture::new();
            let first = fixture.record(&format!("job-v1-migration-uncertain-{index}"), 100);
            let legacy_bytes = encode_legacy_revision(&first).unwrap();
            let legacy_sha256 = sha256_hex(&legacy_bytes);
            publish_raw_revision(&fixture.store, &first.local_job_id, 1, &legacy_bytes);
            let mut migrated = first.clone();
            migrated.revision = 2;
            let bytes = encode_revision_v2(&migrated, Some(&legacy_sha256)).unwrap();
            let final_path = fixture
                .store
                .version_root()
                .join(first.local_job_id.as_str())
                .join(REVISIONS_DIRECTORY)
                .join(revision_filename(2, &sha256_hex(&bytes)));
            set_publication_test_control(PublicationTestControl {
                final_path,
                checkpoint,
                action: PublicationTestAction::Fail,
            });

            let receipt = fixture.store.migrate_job(&first.local_job_id).unwrap();
            assert!(receipt.migrated);
            assert!(receipt.already_present);
            assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), migrated);
            assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 2);
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn migration_and_writer_serialize_on_the_per_job_lock() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v1-migration-lock", 100);
        let legacy_bytes = encode_legacy_revision(&first).unwrap();
        let legacy_sha256 = sha256_hex(&legacy_bytes);
        publish_raw_revision(&fixture.store, &first.local_job_id, 1, &legacy_bytes);
        let mut migrated = first.clone();
        migrated.revision = 2;
        let migrated_bytes = encode_revision_v2(&migrated, Some(&legacy_sha256)).unwrap();
        let final_path = fixture
            .store
            .version_root()
            .join(first.local_job_id.as_str())
            .join(REVISIONS_DIRECTORY)
            .join(revision_filename(2, &sha256_hex(&migrated_bytes)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        set_publication_test_control(PublicationTestControl {
            final_path,
            checkpoint: PublicationCheckpoint::FinalLinked,
            action: PublicationTestAction::Pause {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        });
        let store = fixture.store.clone();
        let local_job_id = first.local_job_id.clone();
        let migration = thread::spawn(move || store.migrate_job(&local_job_id));
        entered.wait();

        let mut competing = first.clone();
        competing.revision = 2;
        competing.updated_at_ms += 1;
        competing.state = StoredJobState::Submitting;
        assert!(matches!(
            fixture.store.append(&competing),
            Err(JobStoreError::JobBusy { .. })
        ));

        release.wait();
        migration.join().unwrap().unwrap();
        let receipt = fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Submitting;
                Ok(next)
            })
            .unwrap();
        assert_eq!(receipt.revision, 3);
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 3);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn legacy_publication_pair_recovers_without_reencoding() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v1-pair-recovery", 100);
        drop(fixture.store.lock_job(&first.local_job_id, true).unwrap());
        let bytes = encode_legacy_revision(&first).unwrap();
        let staging = leave_revision_staging(&fixture.store, &first.local_job_id, &bytes, Some(1));
        assert!(staging.exists());

        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), first);
        assert!(!staging.exists());
        let entries = exact_revision_entries(&fixture.store, &first.local_job_id);
        assert_eq!(entries.len(), 1);
        assert_eq!(fs::read(&entries[0].path).unwrap(), bytes);
    }

    #[test]
    fn generated_ids_and_atomic_update_are_valid() {
        let generated = LocalJobId::generate();
        assert!(LocalJobId::new(generated.as_str()).is_ok());

        let fixture = StoreFixture::new();
        let first = fixture.record("job-update", 100);
        fixture.store.create(&first).unwrap();
        let receipt = fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Submitting;
                Ok(next)
            })
            .unwrap();

        assert_eq!(receipt.revision, 2);
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().state,
            StoredJobState::Submitting
        );
    }

    #[test]
    fn read_only_absent_store_never_creates_layout_or_lock() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("absent-store");
        let store = JobStore::open_at_read_only(&root).unwrap();
        let local_job_id = LocalJobId::new("job-absent-read-only").unwrap();

        assert!(store.list_latest(10).unwrap().is_empty());
        assert!(matches!(
            store.latest(&local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(matches!(
            store.create(&StoreFixture::new().record("job-read-only-write", 100)),
            Err(JobStoreError::ReadOnly)
        ));
        assert!(!root.exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn read_only_store_does_not_create_lock_or_recover_staging() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-read-only-existing", 100);
        fixture.store.create(&record).unwrap();
        let job = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str());
        let lock = job.join(LOCK_FILE);

        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert_eq!(read_only.latest(&record.local_job_id).unwrap(), record);
        assert!(lock.exists());

        let staging = leave_revision_staging(
            &fixture.store,
            &record.local_job_id,
            &encode_revision(&record).unwrap(),
            None,
        );
        assert!(matches!(
            read_only.latest(&record.local_job_id),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert!(staging.exists());
        assert!(lock.exists());
    }

    #[test]
    fn platform_config_retry_replays_the_missing_parent_durability_barrier() {
        let temporary = TempDir::new().unwrap();
        let platform_base = temporary.path().join("platform-config-base");
        {
            let mut installed = PLATFORM_CONFIG_BARRIER_TEST_CONTROL
                .lock()
                .expect("platform-config test-control lock is not poisoned");
            assert!(
                installed
                    .replace(PlatformConfigBarrierTestControl {
                        path: platform_base.clone(),
                        fail_once: Some(PlatformConfigBarrierCheckpoint::Parent),
                        attempts: Vec::new(),
                    })
                    .is_none()
            );
        }

        assert!(matches!(
            ensure_platform_config_base(&platform_base),
            Err(JobStoreError::Io {
                operation: "complete platform config durability barrier",
                ..
            })
        ));
        assert!(platform_base.is_dir());
        ensure_platform_config_base(&platform_base)
            .expect("retry must sync the existing base and its parent");

        let control = PLATFORM_CONFIG_BARRIER_TEST_CONTROL
            .lock()
            .expect("platform-config test-control lock is not poisoned")
            .take()
            .expect("platform-config test control remains installed");
        assert_eq!(
            control.attempts,
            vec![
                PlatformConfigBarrierCheckpoint::Base,
                PlatformConfigBarrierCheckpoint::Parent,
                PlatformConfigBarrierCheckpoint::Base,
                PlatformConfigBarrierCheckpoint::Parent,
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_default_store_uses_machine_local_data_directory() {
        let base = BaseDirs::new().unwrap();
        assert!(
            platform_store_base(&base) == base.data_local_dir(),
            "Windows durable jobs must use machine-local application data"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_layout_repair_coexists_with_retained_read_guards() {
        let fixture = StoreFixture::new();
        let readers = fixture
            .store
            .open_existing_store_layout()
            .unwrap()
            .expect("existing store layout");

        let repaired = fixture
            .store
            .ensure_store_layout()
            .expect("layout repair must share with retained readers");
        assert_eq!(readers.guards.len(), 3);
        assert_eq!(repaired.guards.len(), 3);
    }

    #[cfg(windows)]
    #[test]
    fn windows_raced_existing_directory_reopens_as_a_read_guard() {
        use rustferry_core::windows_private_directory::{
            create_private_directory, open_private_directory_read_guard,
        };

        let temporary = TempDir::new().unwrap();
        let raced_path = temporary.path().join("raced-private-directory");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        {
            let mut installed = PRIVATE_DIRECTORY_RACE_TEST_CONTROL
                .lock()
                .expect("private-directory race test-control lock is not poisoned");
            assert!(
                installed
                    .replace(PrivateDirectoryRaceTestControl {
                        path: raced_path.clone(),
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                    })
                    .is_none()
            );
        }

        let raced = raced_path.clone();
        let opener = thread::spawn(move || ensure_private_directory(&raced));
        entered.wait();
        drop(create_private_directory(&raced_path).expect("win the private-directory race"));
        let reader = open_private_directory_read_guard(&raced_path)
            .expect("retain a compatible existing-directory reader");
        release.wait();
        drop(
            opener
                .join()
                .expect("raced directory opener thread")
                .expect("raced-existing path must reopen without DELETE access"),
        );
        drop(reader);
        assert!(
            PRIVATE_DIRECTORY_RACE_TEST_CONTROL
                .lock()
                .expect("private-directory race test-control lock is not poisoned")
                .take()
                .is_some()
        );
    }

    #[test]
    fn unknown_append_and_partial_create_do_not_poison_listing() {
        let fixture = StoreFixture::new();
        let mut unknown = fixture.record("job-unknown-append", 100);
        unknown.revision = 2;
        assert!(matches!(
            fixture.store.append(&unknown),
            Err(JobStoreError::JobNotFound { .. })
        ));

        let incomplete = LocalJobId::new("job-incomplete-create").unwrap();
        drop(
            ensure_private_directory(&fixture.store.version_root().join(incomplete.as_str()))
                .unwrap(),
        );
        assert!(fixture.store.list_latest(10).unwrap().is_empty());
        assert!(matches!(
            fixture.store.latest(&incomplete),
            Err(JobStoreError::JobNotFound { .. })
        ));

        let malformed = StoreFixture::new();
        let malformed_id = LocalJobId::new("job-malformed-partial").unwrap();
        let job = malformed.store.version_root().join(malformed_id.as_str());
        drop(ensure_private_directory(&job).unwrap());
        drop(ensure_private_directory(&job.join(REVISIONS_DIRECTORY)).unwrap());
        fs::write(job.join("unexpected"), b"not a valid job-layout entry").unwrap();
        assert!(matches!(
            malformed.store.list_latest(10),
            Err(JobStoreError::MalformedLayout {
                reason: "job directory contains an unexpected or linked entry"
            })
        ));
    }

    #[test]
    fn identical_create_is_idempotent_without_overwrite() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-idempotent", 100);
        let first = fixture.store.create(&record).unwrap();
        let second = fixture.store.create(&record).unwrap();
        assert!(!first.already_present);
        assert!(second.already_present);
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(
            revision_names(&fixture.store, &record.local_job_id).len(),
            1
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn idempotent_success_reestablishes_file_and_directory_durability() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let record = fixture.record("job-idempotent-durability", 100);
        fixture.store.create(&record).unwrap();
        let first_path = only_revision_path(&fixture.store, &record.local_job_id);

        for _ in 0..2 {
            set_publication_test_control(PublicationTestControl {
                final_path: first_path.clone(),
                checkpoint: PublicationCheckpoint::IdempotentFinalSync,
                action: PublicationTestAction::Fail,
            });
            assert!(matches!(
                fixture.store.create(&record),
                Err(JobStoreError::CommitUncertain { .. })
            ));
        }
        assert!(fixture.store.create(&record).unwrap().already_present);

        let mut allocated = record.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let resume = github_resume(&allocated);
        let receipt = fixture
            .store
            .checkpoint_github_resume(&record.local_job_id, &resume)
            .unwrap()
            .expect("first provider checkpoint publishes a revision");
        let latest_path = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str())
            .join(REVISIONS_DIRECTORY)
            .join(revision_filename(receipt.revision, &receipt.sha256));
        set_publication_test_control(PublicationTestControl {
            final_path: latest_path,
            checkpoint: PublicationCheckpoint::IdempotentFinalSync,
            action: PublicationTestAction::Fail,
        });
        assert!(matches!(
            fixture
                .store
                .checkpoint_github_resume(&record.local_job_id, &resume),
            Err(JobStoreError::CommitUncertain { .. })
        ));
        assert!(
            fixture
                .store
                .checkpoint_github_resume(&record.local_job_id, &resume)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            revision_names(&fixture.store, &record.local_job_id).len(),
            2
        );
    }

    #[test]
    fn list_latest_is_deterministic_and_bounded() {
        let fixture = StoreFixture::new();
        let alpha = fixture.record("job-alpha", 200);
        let beta = fixture.record("job-beta", 200);
        let gamma = fixture.record("job-gamma", 300);
        fixture.store.create(&beta).unwrap();
        fixture.store.create(&gamma).unwrap();
        fixture.store.create(&alpha).unwrap();

        let listed = fixture.store.list_latest(2).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|record| record.local_job_id.as_str())
                .collect::<Vec<_>>(),
            vec!["job-gamma", "job-alpha"]
        );
        assert!(matches!(
            fixture.store.list_latest(0),
            Err(JobStoreError::BoundExceeded {
                kind: "jobs list limit",
                ..
            })
        ));
    }

    #[test]
    fn project_filtered_reads_require_exact_root_and_filesystem_identity() {
        let fixture = StoreFixture::new();
        let own = fixture.record("job-project-own", 300);
        let own_older = fixture.record("job-project-own-older", 200);
        let foreign_root = fixture.temporary.path().join("foreign-project");
        fs::create_dir(&foreign_root).unwrap();
        let foreign_root = foreign_root.canonicalize().unwrap();
        let foreign_identity = DirectoryFilesystemIdentity::capture(&foreign_root)
            .unwrap()
            .to_string();
        let mut foreign = fixture.record("job-project-foreign", 400);
        foreign.project.canonical_root = foreign_root.to_string_lossy().into_owned();
        foreign.project.filesystem_identity = foreign_identity.clone();
        fixture.store.create(&foreign).unwrap();
        fixture.store.create(&own_older).unwrap();
        fixture.store.create(&own).unwrap();

        let canonical_root = own.project.canonical_root.as_str();
        let filesystem_identity = own.project.filesystem_identity.as_str();
        assert_eq!(
            fixture
                .store
                .list_latest_for_project(canonical_root, filesystem_identity, 10)
                .unwrap()
                .into_iter()
                .map(|summary| summary.local_job_id)
                .collect::<Vec<_>>(),
            vec![own.local_job_id.clone(), own_older.local_job_id.clone()]
        );

        let retained_shared_reader = fixture.store.open_read_only_job(&own.local_job_id).unwrap();
        assert_eq!(
            fixture
                .store
                .latest_for_project(&own.local_job_id, canonical_root, filesystem_identity)
                .unwrap(),
            own
        );
        drop(retained_shared_reader);

        assert!(
            fixture
                .store
                .list_latest_for_project(canonical_root, &foreign_identity, 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .store
                .list_latest_for_project(&foreign.project.canonical_root, filesystem_identity, 10,)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            fixture
                .store
                .latest_for_project(&own.local_job_id, canonical_root, &foreign_identity,),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(matches!(
            fixture
                .store
                .list_latest_for_project(canonical_root, "not-an-identity", 10),
            Err(JobStoreError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn concurrent_different_revisions_never_clobber() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-race", 100);
        fixture.store.create(&first).unwrap();

        let mut left = first.clone();
        left.revision = 2;
        left.updated_at_ms = 101;
        left.state = StoredJobState::Submitting;
        let mut right = left.clone();
        right.state = StoredJobState::Failed;
        right.terminal_outcome = Some(StoredBuildOutcome::Failed);
        right.failure = Some(StoredFailureV1 {
            code: "provider_failed".to_owned(),
            retryable: true,
        });

        let store = Arc::new(fixture.store.clone());
        let barrier = Arc::new(Barrier::new(3));
        let left_result = spawn_append(store.clone(), barrier.clone(), left.clone());
        let right_result = spawn_append(store.clone(), barrier.clone(), right.clone());
        barrier.wait();
        let left_result = left_result.join().expect("left writer");
        let right_result = right_result.join().expect("right writer");

        let loser = match (left_result, right_result) {
            (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
            (left, right) => {
                panic!("expected exactly one concurrent success, got {left:?} and {right:?}")
            }
        };
        assert!(
            matches!(
                &loser,
                JobStoreError::RevisionConflict { .. } | JobStoreError::JobBusy { .. }
            ),
            "unexpected concurrent loser: {loser:?}"
        );
        let latest = store.latest(&first.local_job_id).unwrap();
        assert!(latest == left || latest == right);
        assert_eq!(revision_names(&store, &first.local_job_id).len(), 2);
    }

    #[test]
    fn future_schema_is_rejected_before_typed_decode() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-future", 100);
        let bytes = encode_revision_v2(&record, None)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        let bytes = String::from_utf8(bytes)
            .unwrap()
            .replacen("\"schema_version\":2", "\"schema_version\":3", 1)
            .into_bytes();
        publish_raw_revision(&fixture.store, &record.local_job_id, 1, &bytes);

        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::UnsupportedSchema {
                found: 3,
                supported: JOB_REVISION_SCHEMA_VERSION
            })
        ));
    }

    #[test]
    fn duplicate_schema_and_unknown_nested_request_fields_fail_closed() {
        let duplicate = StoreFixture::new();
        let duplicate_record = duplicate.record("job-duplicate-schema", 100);
        let canonical = String::from_utf8(encode_revision(&duplicate_record).unwrap()).unwrap();
        let duplicate_bytes = canonical
            .replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            )
            .into_bytes();
        publish_raw_revision(
            &duplicate.store,
            &duplicate_record.local_job_id,
            1,
            &duplicate_bytes,
        );
        assert!(matches!(
            duplicate.store.latest(&duplicate_record.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision has no unique numeric schema version"
            })
        ));

        let nested = StoreFixture::new();
        let nested_record = nested.record("job-unknown-request-field", 100);
        let canonical = String::from_utf8(encode_revision(&nested_record).unwrap()).unwrap();
        let nested_bytes = canonical
            .replacen(
                "\"request\":{",
                "\"request\":{\"authorization_header\":\"raw-secret-sentinel\",",
                1,
            )
            .into_bytes();
        publish_raw_revision(&nested.store, &nested_record.local_job_id, 1, &nested_bytes);
        assert!(matches!(
            nested.store.latest(&nested_record.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision bytes are not the canonical secret-free v1 encoding"
            })
        ));
    }

    #[test]
    fn malformed_and_oversized_revisions_fail_closed() {
        let malformed = StoreFixture::new();
        let malformed_id = LocalJobId::new("job-malformed").unwrap();
        publish_raw_revision(&malformed.store, &malformed_id, 1, b"{broken\n");
        assert!(matches!(
            malformed.store.latest(&malformed_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision is not valid JSON"
            })
        ));

        let oversized = StoreFixture::new();
        let oversized_id = LocalJobId::new("job-oversized").unwrap();
        let bytes = vec![
            b'x';
            usize::try_from(MAX_JOB_REVISION_BYTES)
                .expect("revision bound fits the platform")
                + 1
        ];
        publish_raw_revision(&oversized.store, &oversized_id, 1, &bytes);
        assert!(matches!(
            oversized.store.latest(&oversized_id),
            Err(JobStoreError::BoundExceeded {
                kind: "job revision bytes",
                maximum: MAX_JOB_REVISION_BYTES
            })
        ));
    }

    #[test]
    fn revision_filename_digest_detects_content_tampering() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-tampered", 100);
        fixture.store.create(&record).unwrap();
        let path = only_revision_path(&fixture.store, &record.local_job_id);
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.iter().position(|byte| *byte == b'1').unwrap();
        bytes[index] = b'2';
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision bytes do not match the filename digest"
            })
        ));
    }

    #[test]
    fn revision_local_job_id_is_bound_to_its_directory() {
        let fixture = StoreFixture::new();
        let requested = fixture.record("job-directory-binding", 100);
        let different = fixture.record("job-copied-revision", 100);
        publish_raw_revision(
            &fixture.store,
            &requested.local_job_id,
            1,
            &encode_revision(&different).unwrap(),
        );

        assert!(matches!(
            fixture.store.latest(&requested.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision local job ID differs from its job directory"
            })
        ));
    }

    #[test]
    fn historical_legacy_revision_cannot_change_its_directory_owner() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v1-history-owner", 100);
        let mut foreign = first.clone();
        foreign.local_job_id = LocalJobId::new("job-v1-history-foreign").unwrap();
        publish_raw_revision(
            &fixture.store,
            &first.local_job_id,
            1,
            &encode_legacy_revision(&foreign).unwrap(),
        );
        let mut owner_latest = first.clone();
        owner_latest.revision = 2;
        owner_latest.updated_at_ms += 1;
        owner_latest.state = StoredJobState::Submitting;
        publish_raw_revision(
            &fixture.store,
            &first.local_job_id,
            2,
            &encode_legacy_revision(&owner_latest).unwrap(),
        );

        assert!(matches!(
            fixture.store.latest(&first.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision local job ID differs from its job directory"
            })
        ));
        assert!(matches!(
            fixture.store.migrate_job(&first.local_job_id),
            Err(JobStoreError::MalformedRevision {
                reason: "revision local job ID differs from its job directory"
            })
        ));
    }

    #[test]
    fn historical_v2_revision_cannot_bypass_successor_validation() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-v2-history-transition", 200);
        let first_receipt = fixture.store.create(&first).unwrap();
        let mut regressed = first.clone();
        regressed.revision = 2;
        regressed.updated_at_ms = 150;
        let bytes = encode_revision_v2(&regressed, Some(&first_receipt.sha256)).unwrap();
        publish_raw_revision(&fixture.store, &first.local_job_id, 2, &bytes);

        assert!(matches!(
            fixture.store.latest(&first.local_job_id),
            Err(JobStoreError::InvalidRecord {
                reason: "revision timestamp moved backwards"
            })
        ));
        assert!(matches!(
            fixture.store.list_latest(1),
            Err(JobStoreError::InvalidRecord {
                reason: "revision timestamp moved backwards"
            })
        ));
    }

    #[test]
    fn identifiers_and_managed_paths_cannot_escape_store() {
        for value in [
            "", "../job", "job/name", "Job", "con", "com1", "lpt9", "job.",
        ] {
            assert!(LocalJobId::new(value).is_err(), "accepted {value:?}");
        }
        assert!(LocalJobId::new("job-valid_01").is_ok());

        let fixture = StoreFixture::new();
        let mut record = fixture.record("job-path", 100);
        record.log_location = Some("../outside.ndjson".to_owned());
        assert!(record.validate().is_err());
        record.log_location = Some("logs/job.ndjson".to_owned());
        assert!(record.validate().is_ok());
    }

    #[test]
    fn lifecycle_invariants_reject_terminal_regression_and_missing_evidence() {
        assert!(!StoredJobState::Succeeded.can_transition_to(StoredJobState::Running));
        assert!(!StoredJobState::Cancelled.can_transition_to(StoredJobState::Succeeded));
        assert!(!StoredJobState::Failed.can_transition_to(StoredJobState::Running));

        let fixture = StoreFixture::new();
        let mut record = fixture.record("job-artifact", 100);
        record.state = StoredJobState::ArtifactReady;
        assert!(record.validate().is_err());

        record.artifacts.push(fixture.artifact(false));
        assert!(record.validate().is_ok());
        record.state = StoredJobState::Succeeded;
        record.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        record.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        record.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        record.artifacts[0].local_path = Some(fixture.local_artifact_path());
        record.artifacts[0].local_file_identity = Some(fixture.local_artifact_identity());
        record.artifacts[0].locally_validated = true;
        assert!(record.validate().is_err());
        record.cleanup_status = StoredCleanupStatus::Confirmed;
        assert!(record.validate().is_ok());
    }

    #[test]
    fn successor_requires_exact_unknown_and_artifact_provenance() {
        let unknown_fixture = StoreFixture::new();
        let first = unknown_fixture.record("job-unknown-state", 100);
        unknown_fixture.store.create(&first).unwrap();
        let mut unknown = first.clone();
        unknown.revision = 2;
        unknown.updated_at_ms = 101;
        unknown.state = StoredJobState::Unknown;
        unknown.last_confirmed_state = Some(StoredJobState::Created);
        assert!(matches!(
            unknown_fixture.store.append(&unknown),
            Err(JobStoreError::InvalidRecord {
                reason: "unknown state must preserve the exact last confirmed state"
            })
        ));

        let artifact_fixture = StoreFixture::new();
        let artifact = persist_providerless_artifact_ready(
            &artifact_fixture,
            "job-artifact-provenance",
            vec![artifact_fixture.artifact(false)],
        );
        let mut replaced = artifact.clone();
        replaced.revision += 1;
        replaced.updated_at_ms += 1;
        replaced.artifacts[0].record.sha256 = "d".repeat(64);
        assert!(matches!(
            artifact_fixture.store.append(&replaced),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact identity, path, or validation regressed"
            })
        ));
    }

    #[test]
    fn unknown_cannot_invent_outcome_and_log_location_binds_once() {
        let unknown_fixture = StoreFixture::new();
        let first = unknown_fixture.record("job-unknown-outcome", 100);
        unknown_fixture.store.create(&first).unwrap();
        let mut unknown = first.clone();
        unknown.revision = 2;
        unknown.updated_at_ms = 101;
        unknown.state = StoredJobState::Unknown;
        unknown.last_confirmed_state = Some(first.state);
        unknown.terminal_outcome = Some(StoredBuildOutcome::Failed);
        unknown.failure = Some(StoredFailureV1 {
            code: "controller.observation_failed".to_owned(),
            retryable: true,
        });
        assert!(matches!(
            unknown_fixture.store.append(&unknown),
            Err(JobStoreError::InvalidRecord {
                reason: "unknown state cannot introduce a terminal build outcome"
            })
        ));

        let log_fixture = StoreFixture::new();
        let first = log_fixture.record("job-log-binding", 100);
        log_fixture.store.create(&first).unwrap();
        let mut bound = first.clone();
        bound.revision = 2;
        bound.updated_at_ms = 101;
        bound.log_location = Some("logs/job.ndjson".to_owned());
        log_fixture.store.append(&bound).unwrap();

        for replacement in [Some("logs/replaced.ndjson".to_owned()), None] {
            let mut changed = bound.clone();
            changed.revision = 3;
            changed.updated_at_ms = 102;
            changed.log_location = replacement;
            assert!(matches!(
                log_fixture.store.append(&changed),
                Err(JobStoreError::InvalidRecord {
                    reason: "managed log location changed between revisions"
                })
            ));
        }
    }

    #[test]
    fn recovery_from_unknown_cannot_regress_the_last_confirmed_artifact_phase() {
        let fixture = StoreFixture::new();
        let downloaded = persist_providerless_downloaded(&fixture, "job-unknown-downloaded");

        let mut unknown = downloaded.clone();
        unknown.revision += 1;
        unknown.updated_at_ms += 1;
        unknown.state = StoredJobState::Unknown;
        unknown.last_confirmed_state = Some(StoredJobState::Downloaded);
        fixture.store.append(&unknown).unwrap();

        let mut regressed = unknown;
        regressed.revision += 1;
        regressed.updated_at_ms += 1;
        regressed.state = StoredJobState::Queued;
        regressed.last_confirmed_state = Some(StoredJobState::Queued);
        assert!(matches!(
            fixture.store.append(&regressed),
            Err(JobStoreError::InvalidRecord {
                reason: "recovery from unknown regressed the last confirmed local phase"
            })
        ));
    }

    #[test]
    fn artifact_file_identity_is_required_canonical_and_bind_once() {
        let fixture = StoreFixture::new();
        let first = persist_providerless_artifact_ready(
            &fixture,
            "job-artifact-file-identity",
            vec![fixture.artifact(false)],
        );

        let mut intent = first.clone();
        intent.revision += 1;
        intent.updated_at_ms += 1;
        intent.state = StoredJobState::Downloading;
        intent.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        intent.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        fixture.store.append(&intent).unwrap();

        let mut missing = intent.clone();
        missing.revision += 1;
        missing.updated_at_ms += 1;
        missing.artifacts[0].local_path = Some(fixture.local_artifact_path());
        assert!(matches!(
            missing.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "local artifact path, file identity, and validation evidence are inconsistent"
            })
        ));

        missing.artifacts[0].local_file_identity = Some("not-an-identity".to_owned());
        assert!(matches!(
            missing.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "local artifact file identity is invalid"
            })
        ));

        missing.artifacts[0].local_file_identity = Some(fixture.local_artifact_identity());
        fixture.store.append(&missing).unwrap();

        let replacement_path = fixture.temporary.path().join("replacement-artifact.zip");
        fs::write(&replacement_path, b"replacement artifact identity fixture").unwrap();
        let replacement_identity = RegularFileFilesystemIdentity::capture(&replacement_path)
            .unwrap()
            .to_string();
        let mut replaced = missing;
        replaced.revision += 1;
        replaced.updated_at_ms += 1;
        replaced.state = StoredJobState::Downloaded;
        replaced.artifacts[0].local_file_identity = Some(replacement_identity);
        assert!(matches!(
            fixture.store.append(&replaced),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact identity, path, or validation regressed"
            })
        ));
    }

    #[test]
    fn project_and_artifact_filesystem_identities_are_canonical_and_unique() {
        let fixture = StoreFixture::new();
        let mut malformed_project = fixture.record("job-malformed-project-identity", 100);
        malformed_project.project.filesystem_identity = "not-a-directory-identity".to_owned();
        assert!(matches!(
            malformed_project.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "project filesystem identity is invalid"
            })
        ));

        let mut malformed_parent = fixture.record("job-malformed-parent-identity", 100);
        malformed_parent.state = StoredJobState::Downloading;
        malformed_parent.artifacts.push(fixture.artifact(false));
        malformed_parent.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        malformed_parent.artifacts[0].download_parent_identity =
            Some("not-a-directory-identity".to_owned());
        assert!(matches!(
            malformed_parent.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact download parent identity is invalid"
            })
        ));

        let mut duplicate_identity = fixture.record("job-duplicate-file-identity", 100);
        duplicate_identity.state = StoredJobState::Downloading;
        let first = fixture.artifact(true);
        let mut second = first.clone();
        second.record.artifact_id = "artifact-2".to_owned();
        second.record.file_name = "App.ipa".to_owned();
        second.record.sha256 = "d".repeat(64);
        let second_destination = fixture
            .project_root()
            .join("target")
            .join("ferry")
            .join("ios")
            .join("device")
            .join("App.ipa")
            .to_string_lossy()
            .into_owned();
        second.download_destination = Some(second_destination.clone());
        second.local_path = Some(second_destination);
        duplicate_identity.artifacts = vec![first, second];
        assert!(matches!(
            duplicate_identity.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "local artifact file identities must be unique"
            })
        ));
    }

    #[test]
    fn artifact_destinations_are_bound_to_the_exact_project_target_tree_and_parent() {
        let fixture = StoreFixture::new();
        let mut base = fixture.record("job-project-bound-destination", 100);
        base.state = StoredJobState::Downloading;
        base.artifacts.push(fixture.artifact(false));
        let parent_identity = fixture.local_artifact_parent_identity();

        let mut missing_parent = base.clone();
        missing_parent.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        assert!(matches!(
            missing_parent.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact destination and parent identity must be bound together"
            })
        ));

        let sibling = fixture
            .project_root()
            .parent()
            .unwrap()
            .join("project-sibling")
            .join("target")
            .join("ferry")
            .join("artifact.zip")
            .to_string_lossy()
            .into_owned();
        let mut outside = base.clone();
        outside.artifacts[0].download_destination = Some(sibling);
        outside.artifacts[0].download_parent_identity = Some(parent_identity.clone());
        assert!(matches!(
            outside.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact download destination is outside the exact project target/ferry tree"
            })
        ));

        let ready = persist_providerless_artifact_ready(
            &fixture,
            "job-project-bound-destination",
            vec![fixture.artifact(false)],
        );
        base = ready.clone();
        base.revision += 1;
        base.updated_at_ms += 1;
        base.state = StoredJobState::Downloading;
        base.last_confirmed_state = Some(StoredJobState::Downloading);
        base.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        base.artifacts[0].download_parent_identity = Some(parent_identity);
        fixture.store.append(&base).unwrap();
        let mut rebound = base.clone();
        rebound.revision += 1;
        rebound.updated_at_ms += 1;
        rebound.artifacts[0].download_parent_identity = Some(
            DirectoryFilesystemIdentity::capture(&fixture.project_root())
                .unwrap()
                .to_string(),
        );
        assert!(matches!(
            fixture.store.append(&rebound),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact identity, path, or validation regressed"
            })
        ));
    }

    #[test]
    fn download_destinations_precede_files_and_remain_unique_and_immutable() {
        let fixture = StoreFixture::new();
        let mut artifacts = vec![fixture.artifact(false)];
        let mut second_artifact = fixture.artifact(false);
        second_artifact.record.artifact_id = "artifact-2".to_owned();
        second_artifact.record.file_name = "App.ipa".to_owned();
        second_artifact.record.sha256 = "d".repeat(64);
        artifacts.push(second_artifact);
        let first = persist_providerless_artifact_ready(&fixture, "job-download-intent", artifacts);

        let first_destination = fixture.local_artifact_path();
        let second_destination = fixture
            .project_root()
            .join("target")
            .join("ferry")
            .join("ios")
            .join("device")
            .join("App.ipa")
            .to_string_lossy()
            .into_owned();
        assert!(!Path::new(&first_destination).exists());
        assert!(!Path::new(&second_destination).exists());
        let mut downloading = first.clone();
        downloading.revision += 1;
        downloading.updated_at_ms += 1;
        downloading.state = StoredJobState::Downloading;
        downloading.artifacts[0].download_destination = Some(first_destination.clone());
        downloading.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        downloading.artifacts[1].download_destination = Some(second_destination.clone());
        downloading.artifacts[1].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());

        let mut collapsed = downloading.clone();
        collapsed.artifacts[0].local_path = Some(first_destination.clone());
        collapsed.artifacts[0].local_file_identity = Some(fixture.local_artifact_identity());
        assert!(matches!(
            fixture.store.append(&collapsed),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact publication requires a previously durable destination intent"
            })
        ));
        fixture.store.append(&downloading).unwrap();

        let first_identity = fixture.local_artifact_identity();
        let mut partial = downloading.clone();
        partial.revision += 1;
        partial.updated_at_ms += 1;
        partial.artifacts[0].local_path = Some(first_destination.clone());
        partial.artifacts[0].local_file_identity = Some(first_identity.clone());
        fixture.store.append(&partial).unwrap();

        let mut mismatched = partial.clone();
        mismatched.revision += 1;
        mismatched.updated_at_ms += 1;
        mismatched.artifacts[1].local_path = Some(first_destination.clone());
        mismatched.artifacts[1].local_file_identity = Some(first_identity);
        assert!(matches!(
            mismatched.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "local artifact path differs from its immutable download destination"
            })
        ));

        let mut rebound = partial.clone();
        rebound.revision += 1;
        rebound.updated_at_ms += 1;
        rebound.artifacts[1].download_destination = Some(
            fixture
                .project_root()
                .join("target")
                .join("ferry")
                .join("ios")
                .join("device")
                .join("rebound.ipa")
                .to_string_lossy()
                .into_owned(),
        );
        assert!(matches!(
            fixture.store.append(&rebound),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact identity, path, or validation regressed"
            })
        ));

        let mut duplicate = downloading.clone();
        duplicate.revision += 1;
        duplicate.updated_at_ms += 1;
        duplicate.artifacts[1].download_destination = Some(first_destination);
        assert!(matches!(
            duplicate.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact download destinations must be unique"
            })
        ));

        let mut downloaded = partial;
        downloaded.revision += 1;
        downloaded.updated_at_ms += 1;
        downloaded.state = StoredJobState::Downloaded;
        assert!(matches!(
            downloaded.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "downloaded state requires local artifact paths"
            })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_download_destinations_reject_streams_devices_and_case_aliases() {
        let fixture = StoreFixture::new();
        let mut base = fixture.record("job-windows-download-path", 100);
        base.state = StoredJobState::Downloading;
        base.artifacts.push(fixture.artifact(false));

        for destination in [
            r"C:\Temp\artifact.zip:stream",
            r"\\?\C:\Temp\artifact.zip",
            r"C:\Temp\CON.txt",
            r"C:\Temp\folder\.\artifact.zip",
            r"C:\Temp\\artifact.zip",
        ] {
            let mut unsafe_record = base.clone();
            unsafe_record.artifacts[0].download_destination = Some(destination.to_owned());
            unsafe_record.artifacts[0].download_parent_identity =
                Some(fixture.local_artifact_parent_identity());
            assert!(
                unsafe_record.validate().is_err(),
                "accepted unsafe Windows destination {destination:?}"
            );
        }

        let mut aliases = base;
        let mut second = fixture.artifact(false);
        second.record.artifact_id = "artifact-2".to_owned();
        second.record.file_name = "App.ipa".to_owned();
        second.record.sha256 = "d".repeat(64);
        aliases.artifacts.push(second);
        let parent = PathBuf::from(fixture.local_artifact_path())
            .parent()
            .unwrap()
            .to_owned();
        aliases.artifacts[0].download_destination =
            Some(parent.join("Ärtifact.zip").to_string_lossy().into_owned());
        aliases.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        aliases.artifacts[1].download_destination =
            Some(parent.join("ärtifact.ZIP").to_string_lossy().into_owned());
        aliases.artifacts[1].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        assert!(matches!(
            aliases.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "artifact download destinations must be unique"
            })
        ));
    }

    #[test]
    fn expired_cleanup_pending_cannot_forge_confirmation() {
        let fixture = StoreFixture::new();
        let ready = persist_providerless_artifact_ready(
            &fixture,
            "job-expired-cleanup",
            vec![fixture.artifact(false)],
        );
        let mut expired = ready.clone();
        expired.revision += 1;
        expired.updated_at_ms += 1;
        expired.state = StoredJobState::Expired;
        expired.last_confirmed_state = Some(StoredJobState::Expired);
        expired.terminal_outcome = Some(StoredBuildOutcome::Expired);
        fixture.store.append(&expired).unwrap();

        let mut pending = expired.clone();
        pending.revision += 1;
        pending.updated_at_ms += 1;
        pending.state = StoredJobState::CleanupPending;
        pending.last_confirmed_state = Some(StoredJobState::Expired);
        pending.cleanup_status = StoredCleanupStatus::Pending;
        fixture.store.append(&pending).unwrap();

        let mut confirmed = pending.clone();
        confirmed.revision += 1;
        confirmed.updated_at_ms += 1;
        confirmed.state = StoredJobState::Expired;
        confirmed.cleanup_status = StoredCleanupStatus::Confirmed;
        assert!(matches!(
            fixture.store.append(&confirmed),
            Err(JobStoreError::InvalidRecord {
                reason: "confirmed or failed cleanup lacks a changed provider checkpoint"
            })
        ));
        let mut uncertain = confirmed;
        uncertain.cleanup_status = StoredCleanupStatus::Uncertain;
        fixture.store.append(&uncertain).unwrap();
        assert_eq!(
            fixture.store.latest(&expired.local_job_id).unwrap(),
            uncertain
        );
    }

    #[test]
    fn github_resume_cannot_be_removed_or_regressed() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-resume-regression", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let resume = github_resume(&allocated);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let first = fixture.store.latest(&first.local_job_id).unwrap();

        let mut regressed = first.clone();
        regressed.revision += 1;
        regressed.updated_at_ms = 101;
        regressed
            .provider_resume
            .as_mut()
            .unwrap()
            .publication_intent = false;
        regressed
            .provider_resume
            .as_mut()
            .unwrap()
            .publication_started_at_ms = 0;
        regressed
            .provider_resume
            .as_mut()
            .unwrap()
            .publication_quiescence_deadline_ms = u64::MAX;
        assert!(matches!(
            fixture.store.append(&regressed),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub provider resume checkpoint regressed between revisions"
            })
        ));

        let mut removed = first.clone();
        removed.revision += 1;
        removed.updated_at_ms = 101;
        removed.provider_resume = None;
        assert!(removed.validate().is_err());
        assert!(fixture.store.append(&removed).is_err());
    }

    #[test]
    fn direct_provider_revisions_require_the_canonical_reducer_projection() {
        let initial_fixture = StoreFixture::new();
        let mut initial = initial_fixture.record("job-initial-provider-resume", 100);
        initial.provider_job_id = Some(initial.operation_id.clone());
        initial.provider_resume = Some(github_resume(&initial));
        assert!(matches!(
            initial_fixture.store.create(&initial),
            Err(JobStoreError::InvalidRecord {
                reason: "the initial job revision cannot contain a provider checkpoint"
            })
        ));

        let fixture = StoreFixture::new();
        let first = fixture.record("job-direct-provider-projection", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let resume = github_resume(&allocated);
        let mut mismatched = project_github_resume(&first, &resume).unwrap();
        mismatched.state = StoredJobState::SourceReady;
        assert!(matches!(
            fixture.store.append(&mismatched),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub provider checkpoint differs from its canonical local projection"
            })
        ));

        let (first, resume) =
            checkpoint_through_external_github_cancellation(&fixture, "job-direct-run-binding");
        let mut malformed = fixture.store.latest(&first.local_job_id).unwrap();
        malformed.revision += 1;
        malformed.updated_at_ms += 1;
        malformed
            .provider_resume
            .as_mut()
            .unwrap()
            .run
            .as_mut()
            .unwrap()
            .workflow_path = ".github/workflows/other.yml".to_owned();
        assert!(matches!(
            fixture.store.append(&malformed),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub run identity is not exactly bound to the dispatch"
            })
        ));
        assert_eq!(
            fixture
                .store
                .latest(&first.local_job_id)
                .unwrap()
                .provider_resume,
            Some(resume)
        );
    }

    #[test]
    fn initial_revision_cannot_claim_local_artifacts_or_success() {
        let fixture = StoreFixture::new();
        let mut forged = fixture.record("job-forged-initial-success", 100);
        forged.state = StoredJobState::Succeeded;
        forged.last_confirmed_state = Some(StoredJobState::Succeeded);
        forged.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        forged.cleanup_status = StoredCleanupStatus::Confirmed;
        forged.artifacts.push(fixture.artifact(true));

        assert!(matches!(
            fixture.store.create(&forged),
            Err(JobStoreError::InvalidRecord {
                reason: "the initial revision must contain only pre-provider source-ready intent"
            })
        ));
        publish_raw_revision(
            &fixture.store,
            &forged.local_job_id,
            1,
            &encode_revision(&forged).unwrap(),
        );
        assert!(matches!(
            fixture.store.latest(&forged.local_job_id),
            Err(JobStoreError::InvalidRecord {
                reason: "the initial revision must contain only pre-provider source-ready intent"
            })
        ));
    }

    #[test]
    fn local_revisions_cannot_forge_provider_terminal_evidence() {
        let artifact_fixture = StoreFixture::new();
        let ready = persist_providerless_artifact_ready(
            &artifact_fixture,
            "job-forged-success",
            vec![artifact_fixture.artifact(false)],
        );
        let mut forged_success = ready.clone();
        forged_success.revision += 1;
        forged_success.updated_at_ms += 1;
        forged_success.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        assert!(matches!(
            artifact_fixture.store.append(&forged_success),
            Err(JobStoreError::InvalidRecord {
                reason: "provider-owned terminal outcome lacks a changed provider checkpoint"
            })
        ));

        let cancellation_fixture = StoreFixture::new();
        let first = cancellation_fixture.record("job-forged-cancellation", 100);
        cancellation_fixture.store.create(&first).unwrap();
        let mut requested = next_local_revision(&first, StoredJobState::CancellationRequested);
        requested.cancellation_status = StoredCancellationStatus::Requested;
        cancellation_fixture.store.append(&requested).unwrap();
        let mut forged_cancel = next_local_revision(&requested, StoredJobState::CleanupPending);
        forged_cancel.last_confirmed_state = Some(StoredJobState::CancellationRequested);
        forged_cancel.terminal_outcome = Some(StoredBuildOutcome::Cancelled);
        forged_cancel.cleanup_status = StoredCleanupStatus::Pending;
        forged_cancel.cancellation_status = StoredCancellationStatus::Confirmed;
        assert!(matches!(
            cancellation_fixture.store.append(&forged_cancel),
            Err(JobStoreError::InvalidRecord {
                reason: "provider-owned terminal outcome lacks a changed provider checkpoint"
            })
        ));
    }

    #[test]
    fn github_success_requires_a_completed_successful_bound_run() {
        let fixture = StoreFixture::new();
        let (first, success) = checkpoint_through_github_success(&fixture, "job-run-contradiction");
        let mut contradictory = success;
        contradictory.run.as_mut().unwrap().conclusion = Some(GithubRunConclusionV1::Failure);

        assert!(matches!(
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &contradictory),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub artifact success contradicts the bound run conclusion"
            })
        ));
    }

    #[test]
    fn top_level_github_artifacts_exactly_match_resume_manifests() {
        let fixture = StoreFixture::new();
        let (first, _) = checkpoint_through_github_success(&fixture, "job-phantom-artifact");
        let mut phantom = fixture.store.latest(&first.local_job_id).unwrap();
        phantom.revision += 1;
        phantom.updated_at_ms += 1;
        let mut artifact = fixture.artifact(false);
        artifact.record.artifact_id = "phantom-artifact".to_owned();
        artifact.record.file_name = "Phantom.ipa".to_owned();
        artifact.record.sha256 = "f".repeat(64);
        phantom.artifacts.push(artifact);

        assert!(matches!(
            fixture.store.append(&phantom),
            Err(JobStoreError::InvalidRecord {
                reason: "stored artifacts differ from the exact GitHub manifest set"
            })
        ));
    }

    #[test]
    fn github_numeric_principal_and_repository_identity_are_immutable() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-durable-identity", 100);
        fixture.store.create(&first).unwrap();

        let mut changed_principal = first.clone();
        changed_principal.revision = 2;
        changed_principal.updated_at_ms = 101;
        changed_principal.state = StoredJobState::Submitting;
        changed_principal.provider.principal = GithubPrincipalIdentityV1::User {
            id: 8,
            login: "example-user".to_owned(),
        };
        assert!(matches!(
            fixture.store.append(&changed_principal),
            Err(JobStoreError::InvalidRecord {
                reason: "immutable job identity changed between revisions"
            })
        ));

        let mut changed_repository = first.clone();
        changed_repository.revision = 2;
        changed_repository.updated_at_ms = 101;
        changed_repository.state = StoredJobState::Submitting;
        changed_repository.provider.execution_repository_id = 43;
        assert!(matches!(
            fixture.store.append(&changed_repository),
            Err(JobStoreError::InvalidRecord {
                reason: "immutable job identity changed between revisions"
            })
        ));

        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut mismatched_resume = github_resume(&allocated);
        mismatched_resume.principal = GithubPrincipalIdentityV1::User {
            id: 8,
            login: "example-user".to_owned(),
        };
        assert!(matches!(
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &mismatched_resume),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub provider resume identity differs from the local job"
            })
        ));

        let mut mismatched_resume = github_resume(&allocated);
        mismatched_resume.execution_repository_id = 43;
        assert!(matches!(
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &mismatched_resume),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub provider resume identity differs from the local job"
            })
        ));

        let mut missing_principal_id = fixture.record("job-missing-principal-id", 100);
        missing_principal_id.provider.principal = GithubPrincipalIdentityV1::User {
            id: 0,
            login: "example-user".to_owned(),
        };
        assert!(missing_principal_id.validate().is_err());
        let mut missing_repository_id = fixture.record("job-missing-repository-id", 100);
        missing_repository_id.provider.execution_repository_id = 0;
        assert!(missing_repository_id.validate().is_err());

        let mut repository_credential = fixture.record("job-repository-credential", 100);
        repository_credential.provider.principal = GithubPrincipalIdentityV1::RepositoryCredential;
        repository_credential.validate().unwrap();
        fixture.store.create(&repository_credential).unwrap();

        let mut missing_scoped_repository =
            fixture.record("job-unscoped-repository-credential", 100);
        missing_scoped_repository.provider.principal =
            GithubPrincipalIdentityV1::RepositoryCredential;
        missing_scoped_repository.provider.execution_repository_id = 0;
        assert!(matches!(
            missing_scoped_repository.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub repository credential requires a stable execution repository identity"
            })
        ));

        let mut allocated_repository_credential = repository_credential.clone();
        allocated_repository_credential.provider_job_id =
            Some(allocated_repository_credential.operation_id.clone());
        let mut mismatched_repository_resume = github_resume(&allocated_repository_credential);
        mismatched_repository_resume.execution_repository_id = 43;
        assert!(matches!(
            fixture.store.checkpoint_github_resume(
                &repository_credential.local_job_id,
                &mismatched_repository_resume,
            ),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub provider resume identity differs from the local job"
            })
        ));
    }

    #[test]
    fn repository_credential_dispatch_checkpoints_bind_trigger_receipt_and_run() {
        let fixture = StoreFixture::new();
        let mut first = fixture.record("job-repository-dispatch", 100);
        first.provider.principal = GithubPrincipalIdentityV1::RepositoryCredential;
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());

        let prepared = github_resume(&allocated);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &prepared)
            .expect("repository credential pre-dispatch checkpoint");

        let mut forged_push = prepared.clone();
        forged_push.prepared_dispatch_commit = Some("e".repeat(40));
        forged_push.dispatch_commit = Some("e".repeat(40));
        forged_push.run = Some(GithubRunIdentityV1 {
            run_id: 7,
            workflow_id: 8,
            workflow_path: forged_push.workflow_path.clone(),
            head_sha: "e".repeat(40),
            branch: forged_push
                .temporary_ref
                .strip_prefix("refs/heads/")
                .unwrap()
                .to_owned(),
            event: GithubRunEventV1::Push,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Queued,
            conclusion: None,
        });
        assert!(matches!(
            validate_github_resume_record_identity(&allocated, &forged_push),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub trigger-specific resume binding is invalid"
            })
        ));

        let mut dispatch = workflow_dispatch_resume(&allocated);
        bind_workflow_dispatch_receipt(&mut dispatch, 7);
        validate_github_resume_record_identity(&allocated, &dispatch)
            .expect("receipt-only dispatch checkpoint");
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &dispatch)
            .expect("persist receipt-only dispatch checkpoint");
        let reopened = JobStore::open_at(fixture.store.root()).expect("reopen dispatch store");
        let reopened_dispatch = reopened
            .latest(&first.local_job_id)
            .expect("reopened dispatch job");
        assert_eq!(reopened_dispatch.provider_run_id.as_deref(), Some("7"));
        assert!(
            reopened_dispatch
                .provider_resume
                .as_ref()
                .and_then(|resume| resume.workflow_dispatch.as_ref())
                .and_then(|workflow_dispatch| workflow_dispatch.receipt.as_ref())
                .is_some_and(|receipt| receipt.run_id == 7)
        );
        let mut malformed_receipt = dispatch.clone();
        malformed_receipt
            .workflow_dispatch
            .as_mut()
            .unwrap()
            .receipt
            .as_mut()
            .unwrap()
            .run_id = 0;
        assert!(matches!(
            validate_github_resume_record_identity(&allocated, &malformed_receipt),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub trigger-specific resume binding is invalid"
            })
        ));

        let dispatch_state = dispatch.workflow_dispatch.as_ref().unwrap();
        dispatch.run = Some(GithubRunIdentityV1 {
            run_id: 7,
            workflow_id: dispatch_state.workflow_id,
            workflow_path: dispatch_state.workflow_path.clone(),
            head_sha: dispatch_state.dispatch_revision.clone(),
            branch: dispatch_state.branch.clone(),
            event: GithubRunEventV1::WorkflowDispatch,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Queued,
            conclusion: None,
        });
        validate_github_resume_record_identity(&allocated, &dispatch)
            .expect("mapped workflow-dispatch run");

        let mut wrong_event = dispatch.clone();
        wrong_event.run.as_mut().unwrap().event = GithubRunEventV1::Push;
        assert!(matches!(
            validate_github_resume_record_identity(&allocated, &wrong_event),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub trigger-specific resume binding is invalid"
            })
        ));
    }

    #[test]
    fn github_checkpoint_sink_persists_and_deduplicates_under_lock() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-checkpoint-sink", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let resume = github_resume(&allocated);
        let mut sink =
            GithubJobStoreCheckpointSink::new(fixture.store.clone(), first.local_job_id.clone());

        sink.checkpoint(&resume).unwrap();
        sink.checkpoint(&resume).unwrap();

        let latest = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(latest.revision, 2);
        assert_eq!(latest.provider_resume.as_ref(), Some(&resume));
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 2);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn committed_publication_uncertainty_is_reconciled_exactly_under_lock() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        for (index, checkpoint) in [
            PublicationCheckpoint::BeforeFinalSync,
            PublicationCheckpoint::FinalLinked,
            PublicationCheckpoint::StagingRemoved,
            PublicationCheckpoint::FinalReadBack,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = StoreFixture::new();
            let first = fixture.record(&format!("job-uncertain-{index}"), 100);
            fixture.store.create(&first).unwrap();
            let mut next = first.clone();
            next.revision = 2;
            next.updated_at_ms = 101;
            next.state = StoredJobState::Submitting;
            let final_path = revision_path_for(&fixture.store, &next);
            set_publication_test_control(PublicationTestControl {
                final_path,
                checkpoint,
                action: PublicationTestAction::Fail,
            });

            let receipt = fixture
                .store
                .update(&first.local_job_id, |_| Ok(next.clone()))
                .expect("exact committed bytes reconcile to durable success");
            assert!(receipt.already_present);
            assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), next);

            let third = fixture
                .store
                .update(&first.local_job_id, |previous| {
                    let mut third = previous.clone();
                    third.revision += 1;
                    third.updated_at_ms += 1;
                    Ok(third)
                })
                .unwrap();
            assert_eq!(third.revision, 3);
        }
    }

    #[test]
    fn read_only_reader_reports_busy_during_an_active_writer() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-read-only-writer-race", 100);
        fixture.store.create(&first).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let store = fixture.store.clone();
        let local_job_id = first.local_job_id.clone();
        let writer_entered = Arc::clone(&entered);
        let writer_release = Arc::clone(&release);
        let writer = thread::spawn(move || {
            store.update(&local_job_id, |previous| {
                writer_entered.wait();
                writer_release.wait();
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Submitting;
                Ok(next)
            })
        });
        entered.wait();

        let busy = JobStore::open_at_read_only(fixture.store.root()).map(|read_only| {
            let latest = read_only.latest(&first.local_job_id);
            let revision = read_only.revision(&first.local_job_id, 1);
            (read_only, latest, revision)
        });

        release.wait();
        writer.join().unwrap().unwrap();
        let (read_only, latest, revision) = busy.unwrap();
        assert!(matches!(latest, Err(JobStoreError::JobBusy { .. })));
        assert!(matches!(revision, Err(JobStoreError::JobBusy { .. })));
        assert_eq!(read_only.latest(&first.local_job_id).unwrap().revision, 2);
    }

    #[cfg(windows)]
    #[test]
    fn read_only_reader_reaches_fs_lock_during_first_revision_publication() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let first = fixture.record("job-read-only-first-create", 100);
        let final_path = revision_path_for(&fixture.store, &first);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        set_publication_test_control(PublicationTestControl {
            final_path,
            checkpoint: PublicationCheckpoint::FinalLinked,
            action: PublicationTestAction::Pause {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        });
        let store = fixture.store.clone();
        let published = first.clone();
        let writer = thread::spawn(move || store.create(&published));
        entered.wait();

        let busy = JobStore::open_at_read_only(fixture.store.root())
            .and_then(|read_only| read_only.latest(&first.local_job_id));

        release.wait();
        writer.join().unwrap().unwrap();
        assert!(matches!(busy, Err(JobStoreError::JobBusy { .. })));
        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), first);
    }

    #[test]
    fn missing_lock_classification_rechecks_a_concurrent_first_create() {
        let fixture = StoreFixture::new();
        let local_job_id = LocalJobId::new("job-lock-recheck").unwrap();
        let locked = fixture.store.lock_job(&local_job_id, true).unwrap();

        assert!(matches!(
            fixture.store.missing_lock_error(&local_job_id),
            Ok(JobStoreError::JobBusy {
                local_job_id: busy
            }) if busy == local_job_id
        ));
        drop(locked);
    }

    #[cfg(windows)]
    #[test]
    fn writer_retains_every_store_ancestor_against_namespace_replacement() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-ancestor-guard", 100);
        fixture.store.create(&first).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let store = fixture.store.clone();
        let local_job_id = first.local_job_id.clone();
        let writer_entered = Arc::clone(&entered);
        let writer_release = Arc::clone(&release);
        let writer = thread::spawn(move || {
            store.update(&local_job_id, |previous| {
                writer_entered.wait();
                writer_release.wait();
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Submitting;
                Ok(next)
            })
        });
        entered.wait();

        let moved = fixture.store.root().join("v1-replaced");
        assert!(fs::rename(fixture.store.version_root(), &moved).is_err());
        assert!(!moved.exists());

        release.wait();
        writer.join().unwrap().unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().revision,
            2
        );
    }

    #[cfg(windows)]
    #[test]
    fn atomic_publication_retains_final_handle_against_unlink_or_replacement() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let first = fixture.record("job-final-handle-race", 100);
        fixture.store.create(&first).unwrap();
        let mut next = first.clone();
        next.revision = 2;
        next.updated_at_ms = 101;
        next.state = StoredJobState::Submitting;
        let final_path = revision_path_for(&fixture.store, &next);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        set_publication_test_control(PublicationTestControl {
            final_path: final_path.clone(),
            checkpoint: PublicationCheckpoint::FinalLinked,
            action: PublicationTestAction::Pause {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        });
        let store = fixture.store.clone();
        let local_job_id = first.local_job_id.clone();
        let writer = thread::spawn(move || store.update(&local_job_id, |_| Ok(next)));
        entered.wait();

        let replacement = final_path.with_extension("replacement");
        assert!(fs::remove_file(&final_path).is_err());
        assert!(fs::rename(&final_path, &replacement).is_err());
        assert!(!replacement.exists());

        release.wait();
        writer.join().unwrap().unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().revision,
            2
        );
    }

    #[test]
    fn semantic_retry_hash_is_canonical_and_ignores_only_operation_id() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-semantic-retry", 100);
        record.validate().unwrap();

        let mut arbitrary = record.clone();
        arbitrary.semantic_retry_sha256 = "b".repeat(64);
        assert!(matches!(
            arbitrary.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "semantic retry SHA-256 differs from the canonical request template"
            })
        ));

        let mut retry = record.request.clone();
        retry.operation_id = "operation-2".to_owned();
        assert_ne!(
            canonical_request_sha256(&record.request).unwrap(),
            canonical_request_sha256(&retry).unwrap()
        );
        assert_eq!(
            canonical_retry_template_sha256_v1(&record.request).unwrap(),
            canonical_retry_template_sha256_v1(&retry).unwrap()
        );
    }

    #[test]
    fn github_projection_tracks_provider_and_preserves_local_artifacts() {
        let fixture = StoreFixture::new();
        let (first, success) = checkpoint_through_github_success(&fixture, "job-projection");
        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.revision, 5);
        assert_eq!(projected.state, StoredJobState::ArtifactReady);
        assert_eq!(
            projected.terminal_outcome,
            Some(StoredBuildOutcome::Succeeded)
        );
        assert_eq!(projected.submitted_at_ms, Some(100));
        assert_eq!(projected.updated_at_ms, 104);
        assert_eq!(projected.artifacts, vec![fixture.artifact(false)]);

        let local_path = fixture.local_artifact_path();
        let local_file_identity = fixture.local_artifact_identity();
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 105;
                next.state = StoredJobState::Downloading;
                next.artifacts[0].download_destination = Some(local_path.clone());
                next.artifacts[0].download_parent_identity =
                    Some(fixture.local_artifact_parent_identity());
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 106;
                next.artifacts[0].local_path = Some(local_path.clone());
                next.artifacts[0].local_file_identity = Some(local_file_identity.clone());
                Ok(next)
            })
            .unwrap();

        let mut refreshed = success.clone();
        refreshed.run_discovery_attempts = 1;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &refreshed)
            .unwrap();
        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::Downloading);
        assert_eq!(
            projected.artifacts[0].local_path.as_deref(),
            Some(&*local_path)
        );
        assert_eq!(
            projected.artifacts[0].download_destination.as_deref(),
            Some(&*local_path)
        );
        assert_eq!(
            projected.artifacts[0].local_file_identity.as_deref(),
            Some(&*local_file_identity)
        );
        assert!(!projected.artifacts[0].locally_validated);
        assert_eq!(projected.updated_at_ms, 106);

        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 107;
                next.state = StoredJobState::Unknown;
                next.last_confirmed_state = Some(StoredJobState::Downloading);
                Ok(next)
            })
            .unwrap();
        refreshed.run_discovery_attempts = 2;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &refreshed)
            .unwrap();
        let recovered = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(recovered.state, StoredJobState::Downloading);
        assert_eq!(
            recovered.artifacts[0].local_file_identity,
            projected.artifacts[0].local_file_identity
        );
    }

    #[test]
    fn github_compile_evidence_is_projected_bound_and_immutable() {
        let fixture = StoreFixture::new();
        let (first, success) = checkpoint_through_github_success(&fixture, "job-compile-evidence");
        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(
            projected.compile_evidence.as_ref(),
            success.compile_evidence.as_ref()
        );
        assert_eq!(
            projected
                .provider_resume
                .as_ref()
                .and_then(|resume| resume.compile_evidence.as_ref()),
            projected.compile_evidence.as_ref()
        );

        let mut mismatched = projected.clone();
        mismatched.revision += 1;
        mismatched.updated_at_ms += 1;
        mismatched.compile_evidence.as_mut().unwrap().request_sha256 = "f".repeat(64);
        mismatched
            .provider_resume
            .as_mut()
            .unwrap()
            .compile_evidence
            .as_mut()
            .unwrap()
            .request_sha256 = "f".repeat(64);
        assert!(matches!(
            mismatched.validate(),
            Err(JobStoreError::InvalidRecord {
                reason: "compile evidence differs from the stored job or source"
            })
        ));

        let mut replaced = projected;
        replaced.revision += 1;
        replaced.updated_at_ms += 1;
        replaced.compile_evidence.as_mut().unwrap().worker_version = "0.2.0".to_owned();
        replaced
            .provider_resume
            .as_mut()
            .unwrap()
            .compile_evidence
            .as_mut()
            .unwrap()
            .worker_version = "0.2.0".to_owned();
        assert!(matches!(
            fixture.store.append(&replaced),
            Err(JobStoreError::InvalidRecord {
                reason: "verified provider evidence changed between revisions"
            })
        ));

        let mut missing = fixture.store.latest(&first.local_job_id).unwrap();
        missing.revision += 1;
        missing.updated_at_ms += 1;
        missing.compile_evidence = None;
        missing.provider_resume.as_mut().unwrap().compile_evidence = None;
        let missing_error = missing.validate().unwrap_err();
        assert!(
            matches!(
                &missing_error,
                JobStoreError::InvalidRecord {
                    reason: "GitHub manifests and compile evidence must bind atomically"
                }
            ),
            "unexpected error: {missing_error:?}"
        );
    }

    #[test]
    fn github_projection_preserves_controller_subphases_failures_and_cleanup() {
        let running = StoreFixture::new();
        let first = running.record("job-running-subphase", 100);
        running.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        running
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        resume.state = JobState::Running;
        push_github_event(
            &mut resume,
            101,
            "remote-build",
            RemoteBuildEventKind::PhaseStarted { message: None },
        );
        running
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        running
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 102;
                next.state = StoredJobState::SigningRunning;
                Ok(next)
            })
            .unwrap();
        resume.run_discovery_attempts = 1;
        running
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let projected = running.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::SigningRunning);
        assert_eq!(
            projected.last_confirmed_state,
            Some(StoredJobState::Running)
        );

        let cleanup = StoreFixture::new();
        let (first, mut success) =
            checkpoint_through_github_success(&cleanup, "job-cleanup-pending");
        cleanup
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 105;
                next.state = StoredJobState::CleanupPending;
                next.last_confirmed_state = Some(StoredJobState::ArtifactReady);
                next.cleanup_status = StoredCleanupStatus::Pending;
                Ok(next)
            })
            .unwrap();
        success.cleanup_requested = true;
        cleanup
            .store
            .checkpoint_github_resume(&first.local_job_id, &success)
            .unwrap();
        let projected = cleanup.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::CleanupPending);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Pending);
    }

    #[test]
    fn github_projection_preserves_local_failure_through_cleanup() {
        let fixture = StoreFixture::new();
        let (first, mut resume) = checkpoint_through_github_success(&fixture, "job-local-failure");
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 105;
                next.state = StoredJobState::Failed;
                next.failure = Some(StoredFailureV1 {
                    code: "artifact_download_failed".to_owned(),
                    retryable: true,
                });
                Ok(next)
            })
            .unwrap();
        resume.run_discovery_attempts = 1;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let failed = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(failed.state, StoredJobState::Failed);
        assert_eq!(failed.terminal_outcome, Some(StoredBuildOutcome::Succeeded));

        resume.state = JobState::Cleaning;
        resume.cleanup_requested = true;
        push_github_event(
            &mut resume,
            106,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let cleaning = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(cleaning.state, StoredJobState::CleanupPending);
        assert_eq!(cleaning.cleanup_status, StoredCleanupStatus::Pending);
        assert_eq!(cleaning.failure, failed.failure);

        resume.state = JobState::Cleaned;
        resume.temporary_ref_deleted = true;
        push_github_event(
            &mut resume,
            107,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id: first.operation_id.clone(),
                    completed_at_ms: 107,
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                },
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let cleaned = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(cleaned.state, StoredJobState::Failed);
        assert_eq!(cleaned.cleanup_status, StoredCleanupStatus::Confirmed);
        assert_eq!(cleaned.failure, failed.failure);
    }

    #[test]
    fn github_external_cancellation_is_confirmed_without_local_intent() {
        let rejected = StoreFixture::new();
        let first = rejected.record("job-provider-created-intent", 100);
        rejected.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut provider_intent = github_resume(&allocated);
        provider_intent.publication_intent = true;
        provider_intent.cancellation_requested = true;
        provider_intent.state = JobState::Cancelling;
        assert!(matches!(
            rejected
                .store
                .checkpoint_github_resume(&first.local_job_id, &provider_intent),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub cancellation callback lacks a controller-owned durable intent"
            })
        ));
        provider_intent.state = JobState::Cancelled;
        push_github_event(
            &mut provider_intent,
            101,
            "finished",
            RemoteBuildEventKind::OperationCancelled {
                reason: "github_run_cancelled".to_owned(),
                duration_ms: 1,
            },
        );
        assert!(matches!(
            rejected
                .store
                .checkpoint_github_resume(&first.local_job_id, &provider_intent),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub cancellation callback lacks a controller-owned durable intent"
            })
        ));

        let run_mismatch = StoreFixture::new();
        let first = run_mismatch.record("job-run-mismatch", 100);
        run_mismatch.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut mismatched = github_resume(&allocated);
        mismatched.publication_intent = true;
        mismatched.dispatch_commit = Some("e".repeat(40));
        mismatched.run = Some(GithubRunIdentityV1 {
            run_id: 7,
            workflow_id: 8,
            workflow_path: "wrong/workflow.yml".to_owned(),
            head_sha: "e".repeat(40),
            branch: format!("rustferry/builds/{}", first.operation_id),
            event: GithubRunEventV1::Push,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Completed,
            conclusion: Some(GithubRunConclusionV1::Cancelled),
        });
        mismatched.state = JobState::Cancelled;
        assert!(matches!(
            run_mismatch
                .store
                .checkpoint_github_resume(&first.local_job_id, &mismatched),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub run identity is not exactly bound to the dispatch"
            })
        ));

        let fixture = StoreFixture::new();
        let first = fixture.record("job-external-cancel", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();

        resume.state = JobState::Cancelled;
        push_github_event(
            &mut resume,
            101,
            "finished",
            RemoteBuildEventKind::OperationCancelled {
                reason: "github_run_cancelled".to_owned(),
                duration_ms: 1,
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();

        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::Cancelled);
        assert_eq!(
            projected.cancellation_status,
            StoredCancellationStatus::Confirmed
        );
        assert_eq!(
            projected.terminal_outcome,
            Some(StoredBuildOutcome::Cancelled)
        );
    }

    #[test]
    fn github_cancellation_intent_uncertainty_and_failed_race_are_conservative() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-cancel-race", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();

        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 101;
                next.state = StoredJobState::CancellationRequested;
                next.cancellation_status = StoredCancellationStatus::Requested;
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 102;
                next.cancellation_status = StoredCancellationStatus::Uncertain;
                Ok(next)
            })
            .unwrap();

        resume.state = JobState::Cancelling;
        resume.cancellation_requested = true;
        resume.cancellation_dispatched = true;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            fixture
                .store
                .latest(&first.local_job_id)
                .unwrap()
                .cancellation_status,
            StoredCancellationStatus::Uncertain
        );

        resume.state = JobState::Failed;
        push_github_failure_event(&mut resume, 103, "github.cancel_race", false);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::Failed);
        assert_eq!(
            projected.cancellation_status,
            StoredCancellationStatus::Failed
        );
        assert_eq!(
            projected.failure,
            Some(StoredFailureV1 {
                code: "github.cancel_race".to_owned(),
                retryable: false,
            })
        );
        let encoded = serde_json::to_value(&projected).unwrap();
        assert!(encoded["failure"].get("message").is_none());
        assert!(encoded["failure"].get("help").is_none());
    }

    #[test]
    fn github_cleaned_requires_proof_and_local_validation_for_success() {
        let unvalidated = StoreFixture::new();
        let (first, success) =
            checkpoint_through_github_success(&unvalidated, "job-cleaned-unvalidated");
        let mut no_proof = success.clone();
        no_proof.state = JobState::Cleaned;
        no_proof.cleanup_requested = true;
        no_proof.temporary_ref_deleted = true;
        assert!(matches!(
            unvalidated
                .store
                .checkpoint_github_resume(&first.local_job_id, &no_proof),
            Err(JobStoreError::InvalidRecord {
                reason: "cleaned GitHub state lacks exact resource-removal evidence"
            })
        ));

        let cleaned = github_cleaned_resume(success, 105);
        unvalidated
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();
        let projected = unvalidated.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::ArtifactReady);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);

        let validated = StoreFixture::new();
        let (first, success) =
            checkpoint_through_github_success(&validated, "job-cleaned-validated");
        advance_through_local_validation(&validated, &first.local_job_id);
        let cleaned = github_cleaned_resume(success, 108);
        validated
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();
        let projected = validated.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::Succeeded);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);
        assert!(projected.artifacts[0].locally_validated);
        assert!(projected.artifacts[0].local_path.is_some());
    }

    #[test]
    fn github_cleaned_preserves_controller_cleanup_overlay_until_final_validation() {
        let fixture = StoreFixture::new();
        let (first, success) =
            checkpoint_through_github_success(&fixture, "job-cleaned-controller-overlay");
        let local_path = fixture.local_artifact_path();
        let local_identity = fixture.local_artifact_identity();
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Downloading;
                next.artifacts[0].download_destination = Some(local_path.clone());
                next.artifacts[0].download_parent_identity =
                    Some(fixture.local_artifact_parent_identity());
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.artifacts[0].local_path = Some(local_path.clone());
                next.artifacts[0].local_file_identity = Some(local_identity.clone());
                Ok(next)
            })
            .unwrap();
        for state in [StoredJobState::Downloaded, StoredJobState::Validating] {
            fixture
                .store
                .update(&first.local_job_id, |previous| {
                    let mut next = previous.clone();
                    next.revision += 1;
                    next.updated_at_ms += 1;
                    next.state = state;
                    Ok(next)
                })
                .unwrap();
        }
        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::CleanupPending;
                next.last_confirmed_state = Some(StoredJobState::Validating);
                next.cleanup_status = StoredCleanupStatus::Pending;
                Ok(next)
            })
            .unwrap();

        let cleaned = github_cleaned_resume(success, 109);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();
        let pending = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(pending.state, StoredJobState::CleanupPending);
        assert_eq!(pending.cleanup_status, StoredCleanupStatus::Confirmed);
        assert!(!pending.artifacts[0].locally_validated);

        fixture
            .store
            .update(&first.local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms += 1;
                next.state = StoredJobState::Succeeded;
                next.artifacts[0].locally_validated = true;
                Ok(next)
            })
            .unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().state,
            StoredJobState::Succeeded
        );
    }

    #[test]
    fn github_publication_uncertainty_remains_distinct_from_cleanup_failure() {
        let uncertain = StoreFixture::new();
        let first = uncertain.record("job-publication-uncertain", 100);
        uncertain.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        uncertain
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        resume.publication_uncertain = true;
        uncertain
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            uncertain
                .store
                .latest(&first.local_job_id)
                .unwrap()
                .cleanup_status,
            StoredCleanupStatus::Uncertain
        );
    }

    #[test]
    fn github_cleanup_failure_can_retry_through_cleaning_to_cleaned() {
        let failed = StoreFixture::new();
        let (first, success) = checkpoint_through_github_success(&failed, "job-cleanup-failed");
        let mut cleanup_failed = success;
        cleanup_failed.state = JobState::CleanupFailed;
        cleanup_failed.cleanup_requested = true;
        cleanup_failed.temporary_ref_deleted = true;
        push_github_event(
            &mut cleanup_failed,
            105,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        push_github_event(
            &mut cleanup_failed,
            106,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id: first.operation_id.clone(),
                    completed_at_ms: 106,
                    workspace_removed: false,
                    signing_material_removed: false,
                    artifacts_retained: true,
                },
            },
        );
        failed
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleanup_failed)
            .unwrap();
        let projected = failed.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::CleanupFailed);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Failed);
        assert_eq!(
            projected.terminal_outcome,
            Some(StoredBuildOutcome::Succeeded)
        );
        assert_eq!(
            projected.failure,
            Some(StoredFailureV1 {
                code: "github.cleanup_failed".to_owned(),
                retryable: false,
            })
        );

        let mut retrying = cleanup_failed;
        retrying.state = JobState::Cleaning;
        push_github_event(
            &mut retrying,
            107,
            "cleanup-retry",
            RemoteBuildEventKind::CleanupStarted,
        );
        failed
            .store
            .checkpoint_github_resume(&first.local_job_id, &retrying)
            .unwrap();
        let projected = failed.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::CleanupPending);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Pending);
        assert_eq!(projected.failure, None);

        let mut cleaned = retrying;
        cleaned.state = JobState::Cleaned;
        let job_id = cleaned.job_id.clone();
        push_github_event(
            &mut cleaned,
            108,
            "cleanup-retry",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id,
                    completed_at_ms: 108,
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                },
            },
        );
        failed
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();
        let projected = failed.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::ArtifactReady);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);
        assert_eq!(projected.failure, None);
    }

    #[test]
    fn github_cleanup_confirmation_requires_prior_started_evidence() {
        let fixture = StoreFixture::new();
        let (first, mut resume) =
            checkpoint_through_github_success(&fixture, "job-cleanup-event-order");
        resume.state = JobState::CleanupFailed;
        resume.cleanup_requested = true;
        resume.temporary_ref_deleted = true;
        push_github_event(
            &mut resume,
            105,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id: first.operation_id.clone(),
                    completed_at_ms: 105,
                    workspace_removed: false,
                    signing_material_removed: false,
                    artifacts_retained: true,
                },
            },
        );
        push_github_event(
            &mut resume,
            106,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );

        assert!(matches!(
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &resume),
            Err(JobStoreError::InvalidRecord {
                reason: "GitHub cleanup confirmation identity or ordering is invalid"
            })
        ));
    }

    #[test]
    fn github_cleanup_retry_can_checkpoint_directly_from_failed_to_cleaned() {
        let fixture = StoreFixture::new();
        let (first, success) =
            checkpoint_through_github_success(&fixture, "job-cleanup-direct-retry");
        let mut failed = success;
        failed.state = JobState::CleanupFailed;
        failed.cleanup_requested = true;
        failed.temporary_ref_deleted = true;
        push_github_event(
            &mut failed,
            105,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        let job_id = failed.job_id.clone();
        push_github_event(
            &mut failed,
            106,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id: job_id.clone(),
                    completed_at_ms: 106,
                    workspace_removed: false,
                    signing_material_removed: false,
                    artifacts_retained: true,
                },
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &failed)
            .unwrap();

        let mut cleaned = failed;
        cleaned.state = JobState::Cleaned;
        push_github_event(
            &mut cleaned,
            107,
            "cleanup-retry",
            RemoteBuildEventKind::CleanupStarted,
        );
        push_github_event(
            &mut cleaned,
            108,
            "cleanup-retry",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id,
                    completed_at_ms: 108,
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                },
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();

        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::ArtifactReady);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);
        assert_eq!(projected.failure, None);
    }

    #[test]
    fn github_cancelled_cleanup_retry_converges_with_or_without_cleaning_checkpoint() {
        for via_cleaning in [false, true] {
            let fixture = StoreFixture::new();
            let local_job_id = if via_cleaning {
                "job-cancelled-cleanup-via-cleaning"
            } else {
                "job-cancelled-cleanup-direct"
            };
            let (first, mut failed) =
                checkpoint_through_external_github_cancellation(&fixture, local_job_id);
            failed.state = JobState::CleanupFailed;
            failed.cleanup_requested = true;
            failed.temporary_ref_deleted = true;
            push_github_event(
                &mut failed,
                102,
                "cleanup",
                RemoteBuildEventKind::CleanupStarted,
            );
            let job_id = failed.job_id.clone();
            push_github_event(
                &mut failed,
                103,
                "cleanup",
                RemoteBuildEventKind::CleanupFinished {
                    confirmation: CleanupConfirmation {
                        job_id: job_id.clone(),
                        completed_at_ms: 103,
                        workspace_removed: false,
                        signing_material_removed: false,
                        artifacts_retained: true,
                    },
                },
            );
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &failed)
                .unwrap();
            let projected = fixture.store.latest(&first.local_job_id).unwrap();
            assert_eq!(projected.state, StoredJobState::CleanupFailed);
            assert_eq!(
                projected.terminal_outcome,
                Some(StoredBuildOutcome::Cancelled)
            );
            assert_eq!(
                projected
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.as_str()),
                Some("github.cleanup_failed")
            );

            persist_test_cleanup_pending(&fixture, &first.local_job_id);

            if via_cleaning {
                failed.state = JobState::Cleaning;
                push_github_event(
                    &mut failed,
                    104,
                    "cleanup-retry",
                    RemoteBuildEventKind::CleanupStarted,
                );
                fixture
                    .store
                    .checkpoint_github_resume(&first.local_job_id, &failed)
                    .unwrap();
                let projected = fixture.store.latest(&first.local_job_id).unwrap();
                assert_eq!(projected.state, StoredJobState::CleanupPending);
                assert_eq!(projected.failure, None);
            }

            let mut cleaned = failed;
            cleaned.state = JobState::Cleaned;
            if !via_cleaning {
                push_github_event(
                    &mut cleaned,
                    104,
                    "cleanup-retry",
                    RemoteBuildEventKind::CleanupStarted,
                );
            }
            push_github_event(
                &mut cleaned,
                105,
                "cleanup-retry",
                RemoteBuildEventKind::CleanupFinished {
                    confirmation: CleanupConfirmation {
                        job_id,
                        completed_at_ms: 105,
                        workspace_removed: true,
                        signing_material_removed: true,
                        artifacts_retained: true,
                    },
                },
            );
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &cleaned)
                .unwrap();
            let projected = fixture.store.latest(&first.local_job_id).unwrap();
            assert_eq!(projected.state, StoredJobState::Cancelled);
            assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);
            assert_eq!(projected.failure, None);
        }
    }

    #[test]
    fn github_cleanup_retry_recovers_from_an_unknown_overlay() {
        for via_cleaning in [false, true] {
            let fixture = StoreFixture::new();
            let local_job_id = if via_cleaning {
                "job-unknown-cleanup-via-cleaning"
            } else {
                "job-unknown-cleanup-direct"
            };
            let (first, resume) =
                checkpoint_through_external_github_cancellation(&fixture, local_job_id);
            let mut failed = github_cleanup_failed_resume(resume, 102);
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &failed)
                .unwrap();
            fixture
                .store
                .update(&first.local_job_id, |previous| {
                    let mut unknown = previous.clone();
                    unknown.revision += 1;
                    unknown.updated_at_ms += 1;
                    unknown.state = StoredJobState::Unknown;
                    unknown.last_confirmed_state = Some(StoredJobState::Cancelled);
                    Ok(unknown)
                })
                .unwrap();

            push_github_event(
                &mut failed,
                104,
                "cleanup-retry",
                RemoteBuildEventKind::CleanupStarted,
            );
            if via_cleaning {
                failed.state = JobState::Cleaning;
                fixture
                    .store
                    .checkpoint_github_resume(&first.local_job_id, &failed)
                    .unwrap();
            }
            failed.state = JobState::Cleaned;
            let job_id = failed.job_id.clone();
            push_github_event(
                &mut failed,
                105,
                "cleanup-retry",
                RemoteBuildEventKind::CleanupFinished {
                    confirmation: CleanupConfirmation {
                        job_id,
                        completed_at_ms: 105,
                        workspace_removed: true,
                        signing_material_removed: true,
                        artifacts_retained: true,
                    },
                },
            );
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &failed)
                .unwrap();

            let recovered = fixture.store.latest(&first.local_job_id).unwrap();
            assert_eq!(recovered.state, StoredJobState::Cancelled);
            assert_eq!(
                recovered.last_confirmed_state,
                Some(StoredJobState::Cancelled)
            );
            assert_eq!(recovered.cleanup_status, StoredCleanupStatus::Confirmed);
            assert_eq!(recovered.failure, None);
        }
    }

    #[test]
    fn controller_cleanup_uncertainty_can_retry_to_exact_confirmation() {
        for via_cleaning in [false, true] {
            let fixture = StoreFixture::new();
            let local_job_id = if via_cleaning {
                "job-controller-cleanup-via-cleaning"
            } else {
                "job-controller-cleanup-direct"
            };
            let (first, mut resume) = checkpoint_through_github_success(&fixture, local_job_id);
            fixture
                .store
                .update(&first.local_job_id, |previous| {
                    let mut uncertain = previous.clone();
                    uncertain.revision += 1;
                    uncertain.updated_at_ms += 1;
                    uncertain.state = StoredJobState::Failed;
                    uncertain.cleanup_status = StoredCleanupStatus::Uncertain;
                    uncertain.failure = Some(StoredFailureV1 {
                        code: "controller.cleanup_unconfirmed".to_owned(),
                        retryable: true,
                    });
                    Ok(uncertain)
                })
                .unwrap();
            persist_test_cleanup_pending(&fixture, &first.local_job_id);

            resume.cleanup_requested = true;
            push_github_event(
                &mut resume,
                107,
                "cleanup-retry",
                RemoteBuildEventKind::CleanupStarted,
            );
            if via_cleaning {
                resume.state = JobState::Cleaning;
                fixture
                    .store
                    .checkpoint_github_resume(&first.local_job_id, &resume)
                    .unwrap();
            }
            resume.state = JobState::Cleaned;
            resume.temporary_ref_deleted = true;
            let job_id = resume.job_id.clone();
            push_github_event(
                &mut resume,
                108,
                "cleanup-retry",
                RemoteBuildEventKind::CleanupFinished {
                    confirmation: CleanupConfirmation {
                        job_id,
                        completed_at_ms: 108,
                        workspace_removed: true,
                        signing_material_removed: true,
                        artifacts_retained: true,
                    },
                },
            );
            fixture
                .store
                .checkpoint_github_resume(&first.local_job_id, &resume)
                .unwrap();

            let recovered = fixture.store.latest(&first.local_job_id).unwrap();
            assert_eq!(recovered.state, StoredJobState::ArtifactReady);
            assert_eq!(recovered.cleanup_status, StoredCleanupStatus::Confirmed);
            assert_eq!(recovered.failure, None);
        }
    }

    #[test]
    fn github_proven_absent_publication_confirms_cleanup_without_cleaned_event() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-publication-absent", 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        resume.prepared_dispatch_commit = Some("e".repeat(40));
        resume.publication_absence_first_observed_at_ms = 101;
        resume.publication_absence_observations = 1;
        resume.publication_quiescence_deadline_ms = 101 + GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            fixture
                .store
                .latest(&first.local_job_id)
                .unwrap()
                .updated_at_ms,
            101
        );

        resume.publication_absent = true;
        resume.publication_absence_observations = 2;
        resume.temporary_ref_deleted = true;
        resume.state = JobState::Failed;
        push_github_failure_event(
            &mut resume,
            102 + GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS,
            "github.publication_absent",
            false,
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();

        let projected = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(projected.state, StoredJobState::Failed);
        assert_eq!(projected.cleanup_status, StoredCleanupStatus::Confirmed);
    }

    #[test]
    fn retry_requires_parent_and_preserves_lineage() {
        let fixture = StoreFixture::new();
        let mut invalid = fixture.record("job-retry", 100);
        invalid.retry_lineage.attempt = 1;
        assert!(invalid.validate().is_err());
        invalid.retry_lineage.parent_job_id = Some(LocalJobId::new("job-parent").unwrap());
        assert!(invalid.validate().is_ok());

        fixture.store.create(&invalid).unwrap();
        let mut changed = invalid.clone();
        changed.revision = 2;
        changed.updated_at_ms = 101;
        changed.state = StoredJobState::Submitting;
        changed.retry_lineage.parent_job_id = Some(LocalJobId::new("job-other-parent").unwrap());
        assert!(matches!(
            fixture.store.append(&changed),
            Err(JobStoreError::InvalidRecord {
                reason: "immutable job identity changed between revisions"
            })
        ));
    }

    #[test]
    fn serialized_record_contains_no_secret_value_or_transport_fields() {
        let fixture = StoreFixture::new();
        let mut record = fixture.record("job-secret-audit", 100);
        record.provider_job_id = Some(record.operation_id.clone());
        record.provider_resume = Some(github_resume(&record));
        record.validate().expect("typed provider resume");
        let encoded = String::from_utf8(encode_revision(&record).unwrap()).unwrap();
        let encoded_value = serde_json::from_str::<Value>(&encoded).unwrap();
        assert_eq!(encoded_value["provider"]["principal"]["id"], 7);
        assert_eq!(encoded_value["provider"]["execution_repository_id"], 42);
        assert!(encoded_value["provider"].get("account").is_none());
        for forbidden in [
            "raw-secret-sentinel",
            "github_token",
            "authorization_header",
            "signed_url",
            "p12_bytes",
            "provisioning_bytes",
        ] {
            assert!(!encoded.contains(forbidden), "serialized {forbidden}");
        }

        let mut malicious = serde_json::to_value(record.provider_resume.unwrap()).unwrap();
        malicious["authorization_header"] = Value::from("raw-secret-sentinel");
        assert!(serde_json::from_value::<GithubJobResumeV1>(malicious).is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn staging_crash_residue_is_recovered_without_clobber() {
        let fixture = StoreFixture::new();
        let first = fixture.record("job-staging-recovery", 100);
        fixture.store.create(&first).unwrap();

        let orphan = leave_revision_staging(
            &fixture.store,
            &first.local_job_id,
            &encode_revision(&first).unwrap(),
            None,
        );
        assert!(orphan.exists());
        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), first);
        assert!(!orphan.exists());

        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_ms = 101;
        second.state = StoredJobState::Submitting;
        let pair = leave_revision_staging(
            &fixture.store,
            &first.local_job_id,
            &encode_revision_v2(
                &second,
                Some(&sha256_hex(&encode_revision_v2(&first, None).unwrap())),
            )
            .unwrap(),
            Some(second.revision),
        );
        assert!(pair.exists());
        assert_eq!(fixture.store.latest(&first.local_job_id).unwrap(), second);
        assert!(!pair.exists());
        assert_eq!(revision_names(&fixture.store, &first.local_job_id).len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn unix_store_objects_are_private_and_links_fail_closed() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = StoreFixture::new();
        let record = fixture.record("job-unix-private", 100);
        fixture.store.create(&record).unwrap();
        let job = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str());
        let revision = only_revision_path(&fixture.store, &record.local_job_id);
        for directory in [
            fixture.store.root().to_path_buf(),
            job.clone(),
            job.join(REVISIONS_DIRECTORY),
        ] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let metadata = fs::metadata(&revision).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let alias = fixture.temporary.path().join("revision-alias.json");
        fs::hard_link(&revision, alias).unwrap();
        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));
        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert!(matches!(
            read_only.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));

        let symlink_fixture = StoreFixture::new();
        let symlink_record = symlink_fixture.record("job-unix-symlink", 100);
        symlink_fixture.store.create(&symlink_record).unwrap();
        let revision = only_revision_path(&symlink_fixture.store, &symlink_record.local_job_id);
        let original = symlink_fixture.temporary.path().join("original.json");
        fs::rename(&revision, &original).unwrap();
        std::os::unix::fs::symlink(&original, &revision).unwrap();
        assert!(
            symlink_fixture
                .store
                .latest(&symlink_record.local_job_id)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_objects_use_verified_private_dacls() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-windows-acl", 100);
        fixture.store.create(&record).unwrap();
        let job = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str());
        let revisions = job.join(REVISIONS_DIRECTORY);
        let revision = only_revision_path(&fixture.store, &record.local_job_id);
        let lock = job.join(LOCK_FILE);

        for directory in [fixture.store.root(), job.as_path(), revisions.as_path()] {
            rustferry_core::windows_private_directory::open_private_directory(directory)
                .expect("private Windows directory");
        }
        rustferry_core::windows_private_directory::open_private_file(&lock)
            .expect("private Windows lock");
        rustferry_core::windows_private_directory::open_private_file(&revision)
            .expect("private Windows revision");
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlinked_revision_is_rejected() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-windows-link", 100);
        fixture.store.create(&record).unwrap();
        let revision = only_revision_path(&fixture.store, &record.local_job_id);
        let alias = fixture.temporary.path().join("revision-alias.json");
        fs::hard_link(&revision, alias).unwrap();

        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));
        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert!(matches!(
            read_only.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_revision_is_rejected_when_symlink_creation_is_available() {
        use std::os::windows::fs::symlink_file;

        let fixture = StoreFixture::new();
        let record = fixture.record("job-windows-reparse", 100);
        fixture.store.create(&record).unwrap();
        let revision = only_revision_path(&fixture.store, &record.local_job_id);
        let original = fixture.temporary.path().join("original-revision.json");
        fs::rename(&revision, &original).unwrap();
        if let Err(error) = symlink_file(&original, &revision) {
            fs::rename(&original, &revision).unwrap();
            assert!(error.raw_os_error().is_some());
            return;
        }

        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));
        let read_only = JobStore::open_at_read_only(fixture.store.root()).unwrap();
        assert!(matches!(
            read_only.latest(&record.local_job_id),
            Err(JobStoreError::Security { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_permissive_existing_config_root_is_rejected() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("ordinary-config");
        fs::create_dir(&root).unwrap();
        assert!(matches!(
            JobStore::open_at(root),
            Err(JobStoreError::Security { .. })
        ));
        let root = temporary.path().join("ordinary-config");
        assert!(matches!(
            JobStore::open_at_read_only(root),
            Err(JobStoreError::Security { .. })
        ));
    }

    fn spawn_append(
        store: Arc<JobStore>,
        barrier: Arc<Barrier>,
        record: StoredJobV1,
    ) -> thread::JoinHandle<Result<RevisionReceipt, JobStoreError>> {
        thread::spawn(move || {
            barrier.wait();
            store.append(&record)
        })
    }

    #[cfg(windows)]
    fn leave_revision_staging(
        store: &JobStore,
        local_job_id: &LocalJobId,
        bytes: &[u8],
        publish_revision: Option<u64>,
    ) -> PathBuf {
        use rustferry_core::windows_private_directory::create_private_staging_file;

        let locked = store.lock_job(local_job_id, false).unwrap();
        let path = locked
            .revisions
            .join(format!(".revision-{}.tmp", Uuid::new_v4().simple()));
        let mut file = create_private_staging_file(&path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        if let Some(revision) = publish_revision {
            fs::hard_link(
                &path,
                locked
                    .revisions
                    .join(revision_filename(revision, &sha256_hex(bytes))),
            )
            .unwrap();
        }
        drop(file);
        drop(locked);
        path
    }

    #[cfg(unix)]
    fn leave_revision_staging(
        store: &JobStore,
        local_job_id: &LocalJobId,
        bytes: &[u8],
        publish_revision: Option<u64>,
    ) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt as _;

        let locked = store.lock_job(local_job_id, false).unwrap();
        let path = locked
            .revisions
            .join(format!(".revision-{}.tmp", Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        if let Some(revision) = publish_revision {
            fs::hard_link(
                &path,
                locked
                    .revisions
                    .join(revision_filename(revision, &sha256_hex(bytes))),
            )
            .unwrap();
        }
        drop(file);
        drop(locked);
        path
    }

    fn publish_raw_revision(
        store: &JobStore,
        local_job_id: &LocalJobId,
        revision: u64,
        bytes: &[u8],
    ) {
        let locked = store
            .lock_job(local_job_id, true)
            .expect("raw revision lock");
        let digest = sha256_hex(bytes);
        let path = locked.revisions.join(revision_filename(revision, &digest));
        publish_create_only(&locked, &path, bytes).expect("publish raw revision");
    }

    fn revision_names(store: &JobStore, local_job_id: &LocalJobId) -> Vec<String> {
        let revisions = store
            .version_root()
            .join(local_job_id.as_str())
            .join(REVISIONS_DIRECTORY);
        let mut names = fs::read_dir(revisions)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| {
                Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn exact_revision_entries(store: &JobStore, local_job_id: &LocalJobId) -> Vec<RevisionEntry> {
        scan_revision_files(
            &store
                .version_root()
                .join(local_job_id.as_str())
                .join(REVISIONS_DIRECTORY),
        )
        .unwrap()
    }

    fn revision_path_for(store: &JobStore, record: &StoredJobV1) -> PathBuf {
        let previous = if record.revision == 1 {
            None
        } else {
            let revisions = scan_revision_files(
                &store
                    .version_root()
                    .join(record.local_job_id.as_str())
                    .join(REVISIONS_DIRECTORY),
            )
            .unwrap();
            Some(
                revisions
                    .iter()
                    .find(|entry| entry.revision + 1 == record.revision)
                    .expect("revision predecessor")
                    .sha256
                    .clone(),
            )
        };
        let bytes = encode_revision_v2(record, previous.as_deref()).unwrap();
        store
            .version_root()
            .join(record.local_job_id.as_str())
            .join(REVISIONS_DIRECTORY)
            .join(revision_filename(record.revision, &sha256_hex(&bytes)))
    }

    fn set_publication_test_control(control: PublicationTestControl) {
        let mut installed = PUBLICATION_TEST_CONTROL
            .lock()
            .expect("publication test-control lock is not poisoned");
        assert!(installed.replace(control).is_none());
    }

    fn only_revision_path(store: &JobStore, local_job_id: &LocalJobId) -> PathBuf {
        let revisions = store
            .version_root()
            .join(local_job_id.as_str())
            .join(REVISIONS_DIRECTORY);
        fs::read_dir(revisions)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .expect("one revision")
    }

    pub(super) struct StoreFixture {
        temporary: TempDir,
        pub(super) store: JobStore,
    }

    impl StoreFixture {
        pub(super) fn new() -> Self {
            let temporary = TempDir::new().expect("temporary directory");
            let root = temporary.path().join("rustferry-config");
            let store = JobStore::open_at(root).expect("private job store");
            Self { temporary, store }
        }

        pub(super) fn record(&self, local_job_id: &str, updated_at_ms: u64) -> StoredJobV1 {
            let mut request = request();
            request.operation_id = format!("operation-{local_job_id}");
            StoredJobV1 {
                schema_version: JOB_STORE_SCHEMA_VERSION,
                local_job_id: LocalJobId::new(local_job_id).unwrap(),
                revision: 1,
                project: StoredProjectIdentityV1 {
                    canonical_root: self.project_root().to_string_lossy().into_owned(),
                    filesystem_identity: DirectoryFilesystemIdentity::capture(&self.project_root())
                        .unwrap()
                        .to_string(),
                    application_identifier: request.bundle_identifier.clone(),
                },
                provider: StoredProviderIdentityV1 {
                    provider: GITHUB_PROVIDER_ID.to_owned(),
                    provider_config_sha256: "a".repeat(64),
                    principal: GithubPrincipalIdentityV1::User {
                        id: 7,
                        login: "example-user".to_owned(),
                    },
                    execution_repository: "https://github.com/example/iphone-app".to_owned(),
                    execution_repository_id: 42,
                },
                provider_job_id: None,
                provider_run_id: None,
                operation_id: request.operation_id.clone(),
                request_sha256: canonical_request_sha256(&request).unwrap(),
                semantic_retry_sha256: canonical_retry_template_sha256_v1(&request).unwrap(),
                source: StoredSourceIdentityV1 {
                    revision: request.source_revision.clone(),
                    manifest_sha256: request.source.sha256.clone(),
                },
                target: "iphone".to_owned(),
                profile: request.profile,
                signing_mode: request.signing.mode,
                request,
                created_at_ms: 100,
                submitted_at_ms: None,
                updated_at_ms,
                state: StoredJobState::SourceReady,
                last_confirmed_state: Some(StoredJobState::SourceReady),
                terminal_outcome: None,
                compile_evidence: None,
                signed_cleanup_evidence: None,
                artifacts: Vec::new(),
                log_location: None,
                cleanup_status: StoredCleanupStatus::NotStarted,
                retry_lineage: StoredRetryLineageV1 {
                    attempt: 0,
                    parent_job_id: None,
                    child_job_ids: Vec::new(),
                },
                cancellation_status: StoredCancellationStatus::NotRequested,
                failure: None,
                provider_resume: None,
            }
        }

        pub(super) fn artifact(&self, validated: bool) -> StoredArtifactV1 {
            StoredArtifactV1 {
                record: ArtifactRecord {
                    artifact_id: "artifact-1".to_owned(),
                    kind: ArtifactKind::Xcarchive,
                    file_name: "App-unsigned.xcarchive.zip".to_owned(),
                    size: 42,
                    sha256: "c".repeat(64),
                    media_type: Some("application/zip".to_owned()),
                },
                download_destination: validated.then(|| self.local_artifact_path()),
                download_parent_identity: validated.then(|| self.local_artifact_parent_identity()),
                local_path: validated.then(|| self.local_artifact_path()),
                local_file_identity: validated.then(|| self.local_artifact_identity()),
                locally_validated: validated,
            }
        }

        pub(super) fn local_artifact_path(&self) -> String {
            self.project_root()
                .join("target")
                .join("ferry")
                .join("ios")
                .join("device")
                .join("App-unsigned.xcarchive.zip")
                .to_string_lossy()
                .into_owned()
        }

        pub(super) fn local_artifact_parent_identity(&self) -> String {
            let parent = PathBuf::from(self.local_artifact_path())
                .parent()
                .expect("artifact parent")
                .to_owned();
            fs::create_dir_all(&parent).unwrap();
            DirectoryFilesystemIdentity::capture(&parent)
                .unwrap()
                .to_string()
        }

        fn project_root(&self) -> PathBuf {
            self.temporary.path().canonicalize().unwrap()
        }

        pub(super) fn local_artifact_identity(&self) -> String {
            let path = PathBuf::from(self.local_artifact_path());
            if !path.exists() {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b"local artifact identity fixture").unwrap();
            }
            RegularFileFilesystemIdentity::capture(&path)
                .unwrap()
                .to_string()
        }
    }

    fn next_local_revision(previous: &StoredJobV1, state: StoredJobState) -> StoredJobV1 {
        let mut next = previous.clone();
        next.revision += 1;
        next.updated_at_ms += 1;
        next.state = state;
        next.last_confirmed_state = Some(state);
        next
    }

    pub(super) fn persist_providerless_artifact_ready(
        fixture: &StoreFixture,
        local_job_id: &str,
        artifacts: Vec<StoredArtifactV1>,
    ) -> StoredJobV1 {
        let first = fixture.record(local_job_id, 100);
        fixture.store.create(&first).unwrap();
        let submitting = next_local_revision(&first, StoredJobState::Submitting);
        fixture.store.append(&submitting).unwrap();
        let running = next_local_revision(&submitting, StoredJobState::Running);
        fixture.store.append(&running).unwrap();
        let mut ready = next_local_revision(&running, StoredJobState::ArtifactReady);
        ready.artifacts = artifacts;
        fixture.store.append(&ready).unwrap();
        ready
    }

    fn persist_providerless_downloaded(fixture: &StoreFixture, local_job_id: &str) -> StoredJobV1 {
        let ready = persist_providerless_artifact_ready(
            fixture,
            local_job_id,
            vec![fixture.artifact(false)],
        );
        let mut intent = next_local_revision(&ready, StoredJobState::Downloading);
        intent.artifacts[0].download_destination = Some(fixture.local_artifact_path());
        intent.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        fixture.store.append(&intent).unwrap();
        let mut published = next_local_revision(&intent, StoredJobState::Downloading);
        published.artifacts[0].local_path = Some(fixture.local_artifact_path());
        published.artifacts[0].local_file_identity = Some(fixture.local_artifact_identity());
        fixture.store.append(&published).unwrap();
        let mut validated = next_local_revision(&published, StoredJobState::Downloading);
        validated.artifacts[0].locally_validated = true;
        fixture.store.append(&validated).unwrap();
        let downloaded = next_local_revision(&validated, StoredJobState::Downloaded);
        fixture.store.append(&downloaded).unwrap();
        downloaded
    }

    fn persist_test_cleanup_pending(fixture: &StoreFixture, local_job_id: &LocalJobId) {
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut pending = previous.clone();
                pending.revision += 1;
                pending.updated_at_ms += 1;
                pending.state = StoredJobState::CleanupPending;
                pending.cleanup_status = StoredCleanupStatus::Pending;
                Ok(pending)
            })
            .unwrap();
    }

    fn push_github_event(
        resume: &mut GithubJobResumeV1,
        timestamp_ms: u64,
        phase: &str,
        kind: RemoteBuildEventKind,
    ) {
        let sequence = u64::try_from(resume.events.len()).unwrap() + 1;
        let event = RemoteBuildEvent::new(
            resume.operation_id.clone(),
            resume.job_id.clone(),
            timestamp_ms,
            GITHUB_PROVIDER_ID,
            phase,
            sequence,
            kind,
        )
        .unwrap();
        resume.events.push(event);
    }

    fn github_manifest(fixture: &StoreFixture, record: &StoredJobV1) -> ArtifactManifest {
        let mut manifest = ArtifactManifest::new(&record.operation_id, &record.operation_id);
        manifest.provider = GITHUB_PROVIDER_ID.to_owned();
        manifest.source_repository = record.request.source_repository.clone();
        manifest.source_revision = record.source.revision.clone();
        manifest.source_sha256 = record.source.manifest_sha256.clone();
        manifest.artifacts.push(fixture.artifact(false).record);
        manifest
    }

    fn github_compile_evidence(record: &StoredJobV1) -> CompilePhaseEvidence {
        let product = &record.request.product;
        let expectation = UnsignedXcarchiveExpectation {
            app_directory_name: product.app_directory_name.clone(),
            bundle_identifier: record.request.bundle_identifier.clone(),
            executable: product.executable.clone(),
            app_version: product.app_version.clone(),
            build_number: product.build_number.clone(),
            minimum_os: record.request.minimum_ios_version.clone(),
            sdk_version: "26.0".to_owned(),
            sdk_build_version: "23A".to_owned(),
            nested_bundles: product.nested_bundles.clone(),
            required_resources: BTreeMap::new(),
        };
        CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: record.operation_id.clone(),
            provider: GITHUB_PROVIDER_ID.to_owned(),
            request_sha256: record.request_sha256.clone(),
            source_sha256: record.request.source.sha256.clone(),
            cargo_lock_sha256: "6".repeat(64),
            config_sha256: "7".repeat(64),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 26.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "26.0".to_owned(),
                iphoneos_sdk_version: "26.0".to_owned(),
                iphoneos_sdk_build_version: "23A".to_owned(),
                developer_directory_sha256: "8".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: SourceArchive {
                    size: 1,
                    sha256: "9".repeat(64),
                },
                contents: record.request.source.clone(),
                expectation,
            },
            archive_inspection: UnsignedXcarchiveInspection {
                application_path: format!("Applications/{}", product.app_directory_name),
                architectures: vec!["arm64".to_owned()],
                app: UnsignedAppInspection {
                    app_directory_name: product.app_directory_name.clone(),
                    bundle_identifier: record.request.bundle_identifier.clone(),
                    executable: product.executable.clone(),
                    main_executable: Vec::new(),
                    nested_executables: BTreeMap::new(),
                    extensions: Vec::new(),
                    resources: BTreeMap::new(),
                    entries: Vec::new(),
                },
                entries: Vec::new(),
            },
            started_at_unix_seconds: 1_700_000_000,
            finished_at_unix_seconds: 1_700_000_060,
        }
    }

    fn push_github_failure_event(
        resume: &mut GithubJobResumeV1,
        timestamp_ms: u64,
        code: &str,
        retryable: bool,
    ) {
        let duration_ms = timestamp_ms.saturating_sub(resume.created_at_ms);
        let result = IosDeviceBuildResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: resume.operation_id.clone(),
            job_id: resume.job_id.clone(),
            state: JobState::Failed,
            artifacts: Vec::new(),
            cleanup: None,
        };
        push_github_event(
            resume,
            timestamp_ms,
            "finished",
            RemoteBuildEventKind::OperationFinished {
                success: false,
                duration_ms,
                result: Some(result),
                error: Some(RemoteErrorInfo {
                    code: code.to_owned(),
                    message: "sanitized provider failure".to_owned(),
                    help: Some("safe provider recovery guidance".to_owned()),
                    retryable,
                }),
            },
        );
    }

    pub(super) fn checkpoint_through_github_success(
        fixture: &StoreFixture,
        local_job_id: &str,
    ) -> (StoredJobV1, GithubJobResumeV1) {
        let first = fixture.record(local_job_id, 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        resume.publication_intent = true;
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().state,
            StoredJobState::Submitting
        );

        resume.state = JobState::Queued;
        push_github_event(
            &mut resume,
            101,
            "queue",
            RemoteBuildEventKind::JobQueued { position: None },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().state,
            StoredJobState::Queued
        );

        resume.state = JobState::Running;
        push_github_event(
            &mut resume,
            102,
            "remote-build",
            RemoteBuildEventKind::PhaseStarted {
                message: Some("sanitized worker phase".to_owned()),
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        assert_eq!(
            fixture.store.latest(&first.local_job_id).unwrap().state,
            StoredJobState::Running
        );

        resume.state = JobState::Succeeded;
        let dispatch_commit = "e".repeat(40);
        resume.prepared_dispatch_commit = Some(dispatch_commit.clone());
        resume.dispatch_commit = Some(dispatch_commit.clone());
        resume.run = Some(GithubRunIdentityV1 {
            run_id: 7,
            workflow_id: 8,
            workflow_path: resume.workflow_path.clone(),
            head_sha: dispatch_commit,
            branch: resume
                .temporary_ref
                .strip_prefix("refs/heads/")
                .unwrap()
                .to_owned(),
            event: GithubRunEventV1::Push,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Completed,
            conclusion: Some(GithubRunConclusionV1::Success),
        });
        let manifest = attach_github_verified_artifacts(fixture, &first, &mut resume);
        push_github_event(
            &mut resume,
            103,
            "artifacts",
            RemoteBuildEventKind::ArtifactValidated {
                artifact: manifest.clone(),
            },
        );
        let result = IosDeviceBuildResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: resume.operation_id.clone(),
            job_id: resume.job_id.clone(),
            state: JobState::Succeeded,
            artifacts: vec![manifest],
            cleanup: None,
        };
        push_github_event(
            &mut resume,
            104,
            "finished",
            RemoteBuildEventKind::OperationFinished {
                success: true,
                duration_ms: 4,
                result: Some(result),
                error: None,
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        (first, resume)
    }

    fn checkpoint_through_external_github_cancellation(
        fixture: &StoreFixture,
        local_job_id: &str,
    ) -> (StoredJobV1, GithubJobResumeV1) {
        let first = fixture.record(local_job_id, 100);
        fixture.store.create(&first).unwrap();
        let mut allocated = first.clone();
        allocated.provider_job_id = Some(allocated.operation_id.clone());
        let mut resume = github_resume(&allocated);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();

        let dispatch_commit = "e".repeat(40);
        resume.prepared_dispatch_commit = Some(dispatch_commit.clone());
        resume.dispatch_commit = Some(dispatch_commit.clone());
        resume.run = Some(GithubRunIdentityV1 {
            run_id: 7,
            workflow_id: 8,
            workflow_path: resume.workflow_path.clone(),
            head_sha: dispatch_commit,
            branch: resume
                .temporary_ref
                .strip_prefix("refs/heads/")
                .unwrap()
                .to_owned(),
            event: GithubRunEventV1::Push,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Completed,
            conclusion: Some(GithubRunConclusionV1::Cancelled),
        });
        resume.state = JobState::Cancelled;
        push_github_event(
            &mut resume,
            101,
            "finished",
            RemoteBuildEventKind::OperationCancelled {
                reason: "github_run_cancelled".to_owned(),
                duration_ms: 1,
            },
        );
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &resume)
            .unwrap();
        (first, resume)
    }

    pub(super) fn github_cleaned_resume(
        mut resume: GithubJobResumeV1,
        started_at_ms: u64,
    ) -> GithubJobResumeV1 {
        resume.state = JobState::Cleaned;
        resume.cleanup_requested = true;
        resume.temporary_ref_deleted = true;
        push_github_event(
            &mut resume,
            started_at_ms,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        let job_id = resume.job_id.clone();
        push_github_event(
            &mut resume,
            started_at_ms + 1,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id,
                    completed_at_ms: started_at_ms + 1,
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                },
            },
        );
        resume
    }

    fn github_cleanup_failed_resume(
        mut resume: GithubJobResumeV1,
        started_at_ms: u64,
    ) -> GithubJobResumeV1 {
        resume.state = JobState::CleanupFailed;
        resume.cleanup_requested = true;
        resume.temporary_ref_deleted = true;
        push_github_event(
            &mut resume,
            started_at_ms,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        let job_id = resume.job_id.clone();
        push_github_event(
            &mut resume,
            started_at_ms + 1,
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id,
                    completed_at_ms: started_at_ms + 1,
                    workspace_removed: false,
                    signing_material_removed: false,
                    artifacts_retained: true,
                },
            },
        );
        resume
    }

    fn attach_github_verified_artifacts(
        fixture: &StoreFixture,
        record: &StoredJobV1,
        resume: &mut GithubJobResumeV1,
    ) -> ArtifactManifest {
        let manifest = github_manifest(fixture, record);
        resume.compile_evidence = Some(github_compile_evidence(record));
        resume.manifests.push(manifest.clone());
        manifest
    }

    pub(super) fn advance_through_local_validation(
        fixture: &StoreFixture,
        local_job_id: &LocalJobId,
    ) {
        let local_path = fixture.local_artifact_path();
        let local_file_identity = fixture.local_artifact_identity();
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 105;
                next.state = StoredJobState::Downloading;
                next.artifacts[0].download_destination = Some(local_path.clone());
                next.artifacts[0].download_parent_identity =
                    Some(fixture.local_artifact_parent_identity());
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 106;
                next.artifacts[0].local_path = Some(local_path.clone());
                next.artifacts[0].local_file_identity = Some(local_file_identity.clone());
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 107;
                next.state = StoredJobState::Downloaded;
                Ok(next)
            })
            .unwrap();
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut next = previous.clone();
                next.revision += 1;
                next.updated_at_ms = 108;
                next.state = StoredJobState::Validating;
                next.artifacts[0].locally_validated = true;
                Ok(next)
            })
            .unwrap();
    }

    fn request() -> IosDeviceBuildRequest {
        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.iphone").unwrap(),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        };
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-1".to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.iphone".to_owned(),
            minimum_ios_version: "16.0".to_owned(),
            product: IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: SourceMode::Git,
            source_repository: Some("https://github.com/example/iphone-app".to_owned()),
            source_revision: Some(SOURCE_REVISION.to_owned()),
            source: empty_source_manifest(),
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        }
    }

    fn workflow_dispatch_resume(record: &StoredJobV1) -> GithubJobResumeV1 {
        let mut resume = github_resume(record);
        let dispatch_revision = "e".repeat(40);
        let branch = resume
            .temporary_ref
            .strip_prefix("refs/heads/")
            .expect("temporary branch")
            .to_owned();
        let run_name = format!(
            "rustferry-v1|{}|{}|{}|{}",
            resume.operation_id, resume.request_sha256, resume.source_revision, dispatch_revision
        );
        let body = format!(
            "{{\"ref\":\"{branch}\",\"inputs\":{{\"operation_id\":\"{}\",\"request_sha256\":\"{}\",\"source_revision\":\"{}\",\"dispatch_revision\":\"{dispatch_revision}\"}}}}",
            resume.operation_id, resume.request_sha256, resume.source_revision
        );
        resume.prepared_dispatch_commit = Some(dispatch_revision.clone());
        resume.dispatch_commit = Some(dispatch_revision.clone());
        resume.workflow_dispatch = Some(Box::new(GithubWorkflowDispatchResumeV1 {
            schema_version: 1,
            workflow_id: 8,
            workflow_path: resume.workflow_path.clone(),
            branch,
            operation_id: resume.operation_id.clone(),
            request_sha256: resume.request_sha256.clone(),
            source_revision: resume.source_revision.clone(),
            dispatch_revision,
            body_sha256: lower_hex(Sha256::digest(body.as_bytes())),
            run_name,
            uncertain: true,
            receipt: None,
        }));
        resume
    }

    fn bind_workflow_dispatch_receipt(resume: &mut GithubJobResumeV1, run_id: u64) {
        let dispatch = resume
            .workflow_dispatch
            .as_mut()
            .expect("workflow dispatch");
        dispatch.receipt = Some(GithubWorkflowDispatchReceiptV1 {
            run_id,
            workflow_id: dispatch.workflow_id,
            workflow_path: dispatch.workflow_path.clone(),
            branch: dispatch.branch.clone(),
            dispatch_revision: dispatch.dispatch_revision.clone(),
            run_name: dispatch.run_name.clone(),
        });
        dispatch.uncertain = false;
    }

    fn github_resume(record: &StoredJobV1) -> GithubJobResumeV1 {
        GithubJobResumeV1 {
            schema_version: 1,
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: record.provider.provider_config_sha256.clone(),
            principal: record.provider.principal.clone(),
            execution_repository: record.provider.execution_repository.clone(),
            execution_repository_id: record.provider.execution_repository_id,
            source_repository: "https://github.com/example/iphone-app".to_owned(),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_path: ".github/workflows/rustferry-goal3-iphone.yml".to_owned(),
            workflow_sha256: "d".repeat(64),
            temporary_ref: format!("refs/heads/rustferry/builds/{}", record.operation_id),
            operation_id: record.operation_id.clone(),
            job_id: record.provider_job_id.clone().unwrap(),
            request: record.request.clone(),
            request_sha256: record.request_sha256.clone(),
            source_revision: record.source.revision.clone().unwrap(),
            git_snapshot: None,
            prepared_dispatch_commit: None,
            dispatch_commit: None,
            workflow_dispatch: None,
            run: None,
            created_at_ms: record.created_at_ms,
            publication_started_at_ms: record.created_at_ms,
            publication_quiescence_deadline_ms: record
                .created_at_ms
                .saturating_add(GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS),
            publication_absence_first_observed_at_ms: 0,
            state: JobState::Created,
            publication_intent: true,
            publication_uncertain: false,
            publication_absent: false,
            publication_not_attempted: false,
            publication_process_fenced: true,
            publication_lease_scope_sha256: Some("a".repeat(64)),
            publication_absence_observations: 0,
            cancellation_requested: false,
            cancellation_dispatched: false,
            cleanup_requested: false,
            remove_artifacts_requested: false,
            artifacts_removed: false,
            temporary_ref_deleted: false,
            verification_pending_event: false,
            run_discovery_attempts: 0,
            run_discovery_deadline_ms: record.created_at_ms,
            manifests: Vec::new(),
            compile_evidence: None,
            signed_cleanup_evidence: None,
            events: Vec::new(),
        }
    }

    fn empty_source_manifest() -> SourceManifest {
        let entries = vec![
            SourceManifestEntry {
                path: "Cargo.lock".to_owned(),
                size: 0,
                sha256: "6".repeat(64),
                executable: false,
            },
            SourceManifestEntry {
                path: "ferry.toml".to_owned(),
                size: 0,
                sha256: "7".repeat(64),
                executable: false,
            },
        ];
        let mut digest = Sha256::new();
        digest.update(b"rustferry-source-manifest-v1\0");
        digest.update(1_u64.to_be_bytes());
        digest.update(b".");
        digest.update(u64::try_from(entries.len()).unwrap().to_be_bytes());
        for entry in &entries {
            digest.update(u64::try_from(entry.path.len()).unwrap().to_be_bytes());
            digest.update(entry.path.as_bytes());
            digest.update(entry.size.to_be_bytes());
            digest.update(u64::try_from(entry.sha256.len()).unwrap().to_be_bytes());
            digest.update(entry.sha256.as_bytes());
            digest.update([u8::from(entry.executable)]);
        }
        digest.update(0_u64.to_be_bytes());
        SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries,
            total_size: 0,
            sha256: lower_hex(digest.finalize()),
        }
    }
}
