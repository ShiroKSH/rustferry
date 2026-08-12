//! Crash-recoverable administrative operations for the v1 job store.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;

use rustferry_core::process_control::{ProcessFileLease, try_acquire_process_file_lease};
use serde::{Deserialize, Serialize};

#[allow(
    clippy::wildcard_imports,
    reason = "this child module intentionally composes the private v1 store primitives"
)]
use super::*;

const ADMIN_LOCK_FILE: &str = "_admin.lock";
const ADMIN_TRANSACTIONS_DIRECTORY: &str = "_transactions";
const TOMBSTONES_DIRECTORY: &str = "_tombstones";
const OPERATION_RESERVATIONS_DIRECTORY: &str = "_operation-reservations";
const EVENTS_DIRECTORY: &str = "events";
const ARTIFACT_REMOVALS_DIRECTORY: &str = "artifact-removals";
const OPERATION_LOCK_FILE: &str = "operation.lock";
const MANAGED_LOG_LOCATION: &str = "events/v1";
const ADMIN_TRANSACTION_SCHEMA_VERSION: u32 = 1;
const MANAGED_EVENT_SCHEMA_VERSION: u32 = 1;
const PRUNE_TOMBSTONE_SCHEMA_VERSION: u32 = 1;
const CONSUMED_OPERATION_SCHEMA_VERSION: u32 = 1;
const MAX_ADMIN_TRANSACTION_FILES: usize = MAX_STORED_JOBS * 4;
const MAX_ARTIFACT_REMOVAL_OVERLAYS_PER_JOB: usize = MAX_ARTIFACTS * 64;

/// Maximum canonical bytes in one managed event record.
pub const MAX_MANAGED_EVENT_BYTES: u64 = 8 * 1024;
/// Maximum managed event records retained for one job.
pub const MAX_MANAGED_EVENTS_PER_JOB: usize = 65_536;
/// Maximum managed event records accepted by one append.
pub const MAX_MANAGED_EVENT_BATCH: usize = 256;
/// Maximum managed event records returned by one read.
pub const MAX_MANAGED_EVENT_PAGE: usize = 1_000;
/// Maximum total canonical managed-event bytes retained for one job.
pub const MAX_MANAGED_EVENT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum jobs in one prune transaction.
pub const MAX_PRUNE_JOBS: usize = 1_000;

/// Canonical cross-command reference to one provider artifact owned by a local job.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedArtifactRefV1 {
    /// Owner job.
    pub local_job_id: LocalJobId,
    /// Exact provider artifact identifier from the persisted manifest.
    pub provider_artifact_id: String,
}

/// Durable machine-local artifact-removal state, separate from immutable job provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedArtifactRemovalState {
    /// No removal overlay exists.
    Available,
    /// Exact intent is durable; completion must be reconciled.
    Intent,
    /// Handle-bound removal completed.
    Removed,
    /// Absence, replacement, or an OS error prevented exact completion proof.
    Uncertain,
}

/// Artifact plus the latest removal overlay exposed to list/show callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedArtifactViewV1 {
    /// Canonical unambiguous reference.
    pub artifact_ref: ManagedArtifactRefV1,
    /// Immutable provider artifact record.
    pub record: ArtifactRecord,
    /// Persisted local path, never cleared after removal.
    pub local_path: Option<String>,
    /// Persisted exact file identity, never rebound.
    pub local_file_identity: Option<String>,
    /// Latest external removal state.
    pub removal_state: ManagedArtifactRemovalState,
    /// Latest overlay timestamp, if removal started.
    pub removal_updated_at_ms: Option<u64>,
}

/// Exact result of one durable artifact-removal attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedArtifactRemovalReceiptV1 {
    /// Canonical artifact reference.
    pub artifact_ref: ManagedArtifactRefV1,
    /// Persisted result.
    pub state: ManagedArtifactRemovalState,
    /// Whether the same terminal overlay was already durable.
    pub already_complete: bool,
}

/// Origin of one already-sanitized managed event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEventSource {
    /// Local controller lifecycle.
    Controller,
    /// Remote provider lifecycle.
    Provider,
    /// Remote worker lifecycle.
    Worker,
}

/// Severity of one already-sanitized managed event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEventLevel {
    /// Informational lifecycle event.
    Info,
    /// Recoverable or cautionary lifecycle event.
    Warning,
    /// Terminal or actionable failure event.
    Error,
}

/// One unsequenced, bounded, already-sanitized event payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedJobEventInputV1 {
    /// Stable origin without provider payloads.
    pub source: ManagedEventSource,
    /// Optional immutable sequence in that source's own namespace. Restart-safe ingestion must set
    /// this together with `source_event_sha256`, including for one-record polls.
    pub source_sequence: Option<u64>,
    /// Required canonical source-event digest whenever `source_sequence` is present.
    pub source_event_sha256: Option<String>,
    /// Event timestamp in Unix milliseconds.
    pub occurred_at_ms: u64,
    /// Optional exact lifecycle phase for stable filtering.
    pub phase: Option<String>,
    /// Stable severity.
    pub level: ManagedEventLevel,
    /// Stable path-safe event code.
    pub code: String,
    /// Optional pre-sanitized single-line display text.
    pub message: Option<String>,
}

impl ManagedJobEventInputV1 {
    fn validate(&self) -> Result<(), JobStoreError> {
        validate_identifier("managed_event.code", &self.code)?;
        if let Some(phase) = &self.phase {
            validate_identifier("managed_event.phase", phase)?;
        }
        match (self.source_sequence, self.source_event_sha256.as_deref()) {
            (None, None) => {}
            (Some(sequence), Some(sha256)) if sequence > 0 => {
                validate_sha256("managed_event.source_event_sha256", sha256)?;
            }
            _ => {
                return Err(invalid_record(
                    "managed event source sequence and digest must bind together",
                ));
            }
        }
        if let Some(message) = &self.message {
            validate_managed_event_message(message)?;
        }
        Ok(())
    }
}

/// One owner-bound event after the store assigned its global sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedJobEventV1 {
    /// Managed-event schema; exactly one.
    pub schema_version: u32,
    /// Job that exclusively owns this event store.
    pub local_job_id: LocalJobId,
    /// Contiguous sequence starting at one.
    pub sequence: u64,
    /// Event timestamp in Unix milliseconds.
    pub occurred_at_ms: u64,
    /// Optional exact lifecycle phase for stable filtering.
    pub phase: Option<String>,
    /// Stable origin without provider payloads.
    pub source: ManagedEventSource,
    /// Optional immutable sequence in that source's own namespace.
    pub source_sequence: Option<u64>,
    /// Canonical source-event digest paired with `source_sequence`.
    pub source_event_sha256: Option<String>,
    /// Stable severity.
    pub level: ManagedEventLevel,
    /// Stable path-safe event code.
    pub code: String,
    /// Optional pre-sanitized single-line display text.
    pub message: Option<String>,
}

impl ManagedJobEventV1 {
    /// Validate ownership, sequence, text safety, and encoded bounds.
    fn validate_for(&self, owner: &LocalJobId) -> Result<Vec<u8>, JobStoreError> {
        if self.schema_version != MANAGED_EVENT_SCHEMA_VERSION {
            return Err(invalid_record("managed event schema is unsupported"));
        }
        if &self.local_job_id != owner || self.sequence == 0 {
            return Err(invalid_record("managed event owner or sequence is invalid"));
        }
        self.as_input().validate()?;
        encode_bounded_json(
            "managed event",
            self,
            MAX_MANAGED_EVENT_BYTES,
            "encode managed event",
        )
    }

    fn as_input(&self) -> ManagedJobEventInputV1 {
        ManagedJobEventInputV1 {
            source: self.source,
            source_sequence: self.source_sequence,
            source_event_sha256: self.source_event_sha256.clone(),
            occurred_at_ms: self.occurred_at_ms,
            phase: self.phase.clone(),
            level: self.level,
            code: self.code.clone(),
            message: self.message.clone(),
        }
    }
}

/// Result of one managed-event append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedEventAppendReceipt {
    /// Owner job.
    pub local_job_id: LocalJobId,
    /// First sequence assigned to a newly appended record, if any.
    pub first_appended_sequence: Option<u64>,
    /// Last durable sequence after the append, or zero for an empty store.
    pub last_sequence: u64,
    /// Number of new immutable records published.
    pub appended: usize,
    /// Number of identical records reconciled as already present.
    pub already_present: usize,
    /// Store-assigned records in caller input order, including deduplicated replays.
    pub assigned: Vec<ManagedJobEventV1>,
}

/// One bounded page from the canonical managed event sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedEventPageV1 {
    /// Owner job.
    pub local_job_id: LocalJobId,
    /// Canonically ordered event records.
    pub events: Vec<ManagedJobEventV1>,
    /// Last returned sequence, or the requested cursor if empty.
    pub next_after_sequence: u64,
    /// Whether another record follows this page.
    pub has_more: bool,
}

/// Mutating or bounded-poll operation class sharing one exclusive job lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobOperationKind {
    /// Provider submission/build mutation.
    Build,
    /// Provider cancellation mutation.
    Cancel,
    /// Artifact download/publication mutation.
    Download,
    /// One bounded provider log-fetch poll.
    Logs,
    /// Retry-lineage mutation.
    Retry,
    /// Exact local artifact removal.
    ArtifactRemoval,
    /// Complete-lineage snapshot-release and job-tree pruning.
    Prune,
}

/// Process-lifetime per-job lease. Dropping it marks the operation complete.
pub struct JobOperationLease {
    local_job_id: LocalJobId,
    kind: JobOperationKind,
    store_version_root: PathBuf,
    store_identity: DirectoryFilesystemIdentity,
    _lease: ProcessFileLease,
    _guards: Vec<File>,
}

impl std::fmt::Debug for JobOperationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobOperationLease")
            .field("local_job_id", &self.local_job_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl JobOperationLease {
    /// Return the exact owner job.
    #[must_use]
    pub fn local_job_id(&self) -> &LocalJobId {
        &self.local_job_id
    }

    /// Return the operation class selected by the caller.
    #[must_use]
    pub const fn kind(&self) -> JobOperationKind {
        self.kind
    }

    fn validate_owner(
        &self,
        store: &JobStore,
        locked: &LockedJob,
        local_job_id: &LocalJobId,
        kind: JobOperationKind,
    ) -> Result<(), JobStoreError> {
        if self.local_job_id != *local_job_id || self.kind != kind {
            return Err(invalid_record(
                "operation requires its exact owner job and operation kind",
            ));
        }
        let version_root = fs::canonicalize(store.version_root())
            .map_err(|source| io_error("resolve operation lease job store", source))?;
        if version_root != self.store_version_root {
            return Err(invalid_record(
                "operation lease belongs to a different job store path",
            ));
        }
        let identity = locked_store_identity(locked)?;
        if identity != self.store_identity {
            return Err(invalid_record(
                "operation lease belongs to a different job store identity",
            ));
        }
        Ok(())
    }
}

/// Exclusive proof that no durable job currently owns one snapshot operation identifier.
pub struct VacantSnapshotOperationLease {
    operation_id: String,
    store_version_root: PathBuf,
    store_identity: DirectoryFilesystemIdentity,
    _lease: ProcessFileLease,
    _guards: Vec<File>,
}

impl std::fmt::Debug for VacantSnapshotOperationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VacantSnapshotOperationLease")
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl VacantSnapshotOperationLease {
    /// Return the exact currently vacant operation identifier.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    fn validate_owner(&self, store: &JobStore, operation_id: &str) -> Result<(), JobStoreError> {
        if self.operation_id != operation_id {
            return Err(invalid_record(
                "snapshot operation lease differs from the requested operation",
            ));
        }
        let version_root = fs::canonicalize(store.version_root())
            .map_err(|source| io_error("resolve snapshot operation job store", source))?;
        if version_root != self.store_version_root {
            return Err(invalid_record(
                "snapshot operation lease belongs to a different job store path",
            ));
        }
        let identity =
            DirectoryFilesystemIdentity::capture(&store.version_root()).map_err(|error| {
                retained_directory_error("identify snapshot operation store", &error)
            })?;
        if identity != self.store_identity {
            return Err(invalid_record(
                "snapshot operation lease belongs to a different job store identity",
            ));
        }
        Ok(())
    }
}

/// Initial revision plus the continuously held operation authority returned after creation.
#[derive(Debug)]
pub struct LeasedJobCreationReceipt {
    /// Exact initial immutable revision.
    pub revision: RevisionReceipt,
    /// Build lease acquired before the vacant-operation lease was released.
    pub operation_lease: JobOperationLease,
}

/// Reciprocal retry publication plus continuously held child Build authority.
#[derive(Debug)]
pub struct LeasedRetryLineageReceipt {
    /// Exact durable parent/child transaction result.
    pub lineage: RetryLineageReceipt,
    /// Child Build lease acquired before releasing the operation vacancy.
    pub operation_lease: JobOperationLease,
}

/// Read-only durable owner of one provider snapshot operation.
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotOperationOwnerV1 {
    /// Exact local job whose latest active revision owns the operation.
    pub local_job_id: LocalJobId,
    /// Latest exact durable job revision, including whether a provider checkpoint exists.
    pub record: StoredJobV1,
}

/// Read-only ownership result while attempting to reserve one snapshot operation.
#[derive(Debug)]
pub enum SnapshotOperationVacancyV1 {
    /// No durable owner exists and the exclusive store-wide reservation remains held.
    Vacant(VacantSnapshotOperationLease),
    /// An exact active durable owner already exists; recovery must inspect that record.
    Owned(Box<SnapshotOperationOwnerV1>),
}

/// Sorted exact per-job authority retained across snapshot release and final prune publication.
pub struct PruneLeaseSet {
    initial_plan: PrunePlanV1,
    release_authorization_sha256: String,
    leases: BTreeMap<LocalJobId, JobOperationLease>,
}

impl std::fmt::Debug for PruneLeaseSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PruneLeaseSet")
            .field("initial_plan", &self.initial_plan)
            .field(
                "release_authorization_sha256",
                &self.release_authorization_sha256,
            )
            .field("leased_job_ids", &self.leases.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PruneLeaseSet {
    /// Return the exact caller-confirmed plan bound to this complete lease set.
    #[must_use]
    pub fn initial_plan(&self) -> &PrunePlanV1 {
        &self.initial_plan
    }

    /// Borrow one exact retained Prune lease; the complete set remains owned by this value.
    #[must_use]
    pub fn lease(&self, local_job_id: &LocalJobId) -> Option<&JobOperationLease> {
        self.leases.get(local_job_id)
    }
}

/// Durable provider checkpoint phase observed for one retained snapshot keepalive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruneSnapshotReleaseStateV1 {
    /// Terminal source cleanup is complete; release intent is not yet durable.
    Required,
    /// Exact complete-lineage release intent is durable and must be resumed.
    Intent,
    /// Exact keepalive absence is already durably checkpointed.
    Released,
}

/// One exact provider snapshot keepalive release authorized by a held complete-lineage lease set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneSnapshotReleaseV1 {
    /// Exact local job whose provider checkpoint will advance.
    pub local_job_id: LocalJobId,
    /// Exact provider operation/job identifier.
    pub operation_id: String,
    /// Stable digest over the complete lineage component and cutoff.
    pub complete_lineage_authorization_sha256: String,
    /// Durable provider phase observed while every component lease remains held.
    pub state: PruneSnapshotReleaseStateV1,
}

/// Exact retry transaction result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryLineageReceipt {
    /// Parent revision that durably names the child.
    pub parent: RevisionReceipt,
    /// Child's immutable initial revision.
    pub child: RevisionReceipt,
    /// Immutable transaction authority binding this exact lineage edge.
    pub binding: RetryLineageBindingV1,
}

/// Stable authority recovered from one immutable retry transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryLineageBindingV1 {
    /// SHA-256 of the exact canonical retry transaction bytes.
    pub authorization_sha256: String,
    /// Parent revision observed before the reciprocal lineage mutation.
    pub parent_before_revision: u64,
    /// Parent revision that first names the child.
    pub parent_next_revision: u64,
    /// Exact durable child identifier.
    pub child_job_id: LocalJobId,
    /// Exact provider operation identifier owned by the child.
    pub child_operation_id: String,
    /// Persisted parent/source policy; caller flags never replace it on restart.
    pub options: RetryLineageOptionsV1,
}

/// Parent-outcome policy for an explicit retry transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryParentPolicyV1 {
    /// Require failed, cancelled, or expired parent state.
    RequireUnsuccessful,
    /// Explicitly permit one fully evidenced successful parent.
    AllowSuccessful,
}

/// Source-template policy durably bound into a retry transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrySourcePolicyV1 {
    /// Preserve the exact source and canonical semantic retry hash.
    Exact,
    /// Reuse a retained Git snapshot archive while regenerating the operation-bound descriptor.
    ExactGitSnapshot {
        /// SHA-256 of the exact retained parent archive.
        source_archive_sha256: String,
    },
    /// Use a freshly validated Git snapshot and bind explicit caller confirmation.
    RecapturedGitSnapshot {
        /// Domain-separated digest returned by [`retry_recapture_confirmation_sha256`].
        confirmation_sha256: String,
        /// Exact public-object upload consent accepted by the caller.
        #[serde(default)]
        snapshot_consent_sha256: String,
        /// SHA-256 of the exact private staged archive.
        #[serde(default)]
        source_archive_sha256: String,
    },
}

/// Explicit retry policy journaled before either lineage revision changes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryLineageOptionsV1 {
    /// Whether a fully evidenced successful parent is explicitly permitted.
    pub parent_policy: RetryParentPolicyV1,
    /// Whether source identity stays exact or is recaptured through `GitSnapshot`.
    pub source_policy: RetrySourcePolicyV1,
}

impl Default for RetryLineageOptionsV1 {
    fn default() -> Self {
        Self {
            parent_policy: RetryParentPolicyV1::RequireUnsuccessful,
            source_policy: RetrySourcePolicyV1::Exact,
        }
    }
}

/// Derive the exact confirmation digest for one recaptured `GitSnapshot` retry.
///
/// # Errors
///
/// Returns a typed validation error unless the child is a valid `GitSnapshot` request with a new
/// operation and the same project/provider/target/profile/signing identity as its parent.
pub fn retry_recapture_confirmation_sha256(
    parent: &StoredJobV1,
    child: &StoredJobV1,
) -> Result<String, JobStoreError> {
    validate_retry_common_identity(parent, child)?;
    if child.request.source_mode != rustferry_remote::SourceMode::GitSnapshot {
        return Err(invalid_record(
            "recaptured retry source must use a published Git snapshot",
        ));
    }
    let mut expected_request = parent.request.clone();
    expected_request
        .operation_id
        .clone_from(&child.operation_id);
    expected_request.source_mode = child.request.source_mode;
    expected_request
        .source_repository
        .clone_from(&child.request.source_repository);
    expected_request
        .source_revision
        .clone_from(&child.request.source_revision);
    expected_request.source.clone_from(&child.request.source);
    if child.request != expected_request {
        return Err(invalid_record(
            "recaptured retry changed a non-source request field",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"rustferry-job-retry-recaptured-v1\0");
    digest.update(parent.local_job_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(parent.revision.to_be_bytes());
    digest.update(child.local_job_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(child.operation_id.as_bytes());
    digest.update([0]);
    digest.update(child.request_sha256.as_bytes());
    digest.update(child.semantic_retry_sha256.as_bytes());
    digest.update(child.source.manifest_sha256.as_bytes());
    if let Some(revision) = &child.source.revision {
        digest.update(revision.as_bytes());
    }
    Ok(lower_hex(digest.finalize()))
}

/// One exact candidate in a dry-run prune plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PruneCandidateV1 {
    /// Job selected as part of a complete retry-lineage component.
    pub local_job_id: LocalJobId,
    /// Provider operation permanently consumed by this durable job.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    /// Exact final revision.
    pub revision: u64,
    /// Digest embedded in the exact final revision filename.
    pub revision_sha256: String,
    /// Final update timestamp.
    pub updated_at_ms: u64,
    /// Immutable retry attempt.
    pub attempt: u32,
    /// Immutable retry parent.
    pub parent_job_id: Option<LocalJobId>,
    /// Complete ordered retry children.
    pub child_job_ids: Vec<LocalJobId>,
    /// Stable digest over this complete connected lineage component and prune cutoff.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub complete_lineage_authorization_sha256: String,
    /// Whether this exact job owns Git snapshot keepalive provenance that must be released.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_git_snapshot_keepalive: bool,
}

/// Deterministic dry-run plan; execution revalidates every exact revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrunePlanV1 {
    /// Jobs must be terminal and strictly older than this timestamp.
    pub terminal_before_ms: u64,
    /// Original bounded component-selection limit, retained for exact replanning.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub selection_max_jobs: usize,
    /// Exact complete-lineage candidates ordered oldest then by ID.
    pub candidates: Vec<PruneCandidateV1>,
}

/// Result of one crash-recoverable prune transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneReceiptV1 {
    /// Canonical transaction digest.
    pub transaction_sha256: String,
    /// Jobs removed or already absent behind exact tombstones.
    pub pruned_job_ids: Vec<LocalJobId>,
    /// Whether a prior crash or identical caller had already completed it.
    pub already_complete: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetryTransactionV1 {
    schema_version: u32,
    parent_before_revision: u64,
    parent_before_sha256: String,
    parent_next: StoredJobV1,
    child: StoredJobV1,
    options: RetryLineageOptionsV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PruneTransactionV1 {
    schema_version: u32,
    pruned_at_ms: u64,
    plan: PrunePlanV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PruneReleaseAuthorizationV1 {
    schema_version: u32,
    plan: PrunePlanV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AdminTransactionV1 {
    Retry(Box<RetryTransactionV1>),
    PruneRelease(PruneReleaseAuthorizationV1),
    Prune(PruneTransactionV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PruneTombstoneV1 {
    schema_version: u32,
    pruned_at_ms: u64,
    transaction_sha256: String,
    candidate: PruneCandidateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConsumedOperationV1 {
    schema_version: u32,
    operation_id: String,
    local_job_id: LocalJobId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRemovalOverlayV1 {
    schema_version: u32,
    revision: u64,
    artifact_ref: ManagedArtifactRefV1,
    expected_path: String,
    expected_file_identity: String,
    expected_sha256: String,
    expected_size: u64,
    state: ManagedArtifactRemovalState,
    updated_at_ms: u64,
}

struct AdminLayout {
    _guards: Vec<File>,
    transactions_guard: File,
    transactions: PathBuf,
    tombstones_guard: File,
    tombstones: PathBuf,
    lock: HeldFileLock,
}

struct ManagedEventEntry {
    sequence: u64,
    sha256: String,
    path: PathBuf,
    bytes: u64,
}

struct PreparedManagedEvent {
    event: ManagedJobEventV1,
    bytes: Vec<u8>,
    final_path: PathBuf,
}

#[cfg(test)]
static MANAGED_EVENT_PUBLICATION_TEST_CONTROL: std::sync::Mutex<Option<PathBuf>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
#[derive(Clone)]
struct PruneReleasePublicationTestControl {
    version_root: PathBuf,
    barrier: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
static PRUNE_RELEASE_PUBLICATION_TEST_CONTROL: std::sync::Mutex<
    Option<PruneReleasePublicationTestControl>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
#[derive(Clone)]
struct InitialCreateOwnerTestControl {
    operation_id: String,
    arrived: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
static INITIAL_CREATE_OWNER_TEST_CONTROL: std::sync::Mutex<Option<InitialCreateOwnerTestControl>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
#[derive(Clone)]
struct PrunePublicationLockTestControl {
    local_job_id: LocalJobId,
    candidate_locks_held: std::sync::mpsc::Sender<()>,
    allow_publication: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
    transaction_published: std::sync::mpsc::Sender<()>,
    allow_lock_release: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
    candidate_locks_released: std::sync::mpsc::Sender<()>,
    allow_finish: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}

#[cfg(test)]
static PRUNE_PUBLICATION_LOCK_TEST_CONTROL: std::sync::Mutex<
    Option<PrunePublicationLockTestControl>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn await_prune_release_publication_test_barrier(store: &JobStore) {
    let control = PRUNE_RELEASE_PUBLICATION_TEST_CONTROL
        .lock()
        .expect("prune publication test-control lock is not poisoned")
        .as_ref()
        .filter(|control| control.version_root == store.version_root())
        .cloned();
    if let Some(control) = control {
        control.barrier.wait();
    }
}

#[cfg(test)]
fn await_initial_create_owner_test_control(operation_id: &str) {
    let control = INITIAL_CREATE_OWNER_TEST_CONTROL
        .lock()
        .expect("initial-create test-control lock is not poisoned")
        .as_ref()
        .filter(|control| control.operation_id == operation_id)
        .cloned();
    if let Some(control) = control {
        control.arrived.wait();
        control.release.wait();
    }
}

#[cfg(not(test))]
fn await_initial_create_owner_test_control(_operation_id: &str) {}

#[cfg(test)]
fn prune_publication_lock_test_control(
    locked: &BTreeMap<LocalJobId, LockedJob>,
) -> Option<PrunePublicationLockTestControl> {
    PRUNE_PUBLICATION_LOCK_TEST_CONTROL
        .lock()
        .expect("prune-publication test-control lock is not poisoned")
        .as_ref()
        .filter(|control| locked.contains_key(&control.local_job_id))
        .cloned()
}

#[cfg(test)]
fn wait_for_prune_publication_test_signal(
    receiver: &std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    phase: &'static str,
) {
    receiver
        .lock()
        .expect("prune-publication signal receiver is not poisoned")
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{phase}"));
}

#[cfg(test)]
fn await_prune_publication_validation_test_control(locked: &BTreeMap<LocalJobId, LockedJob>) {
    let control = prune_publication_lock_test_control(locked);
    if let Some(control) = control {
        control
            .candidate_locks_held
            .send(())
            .expect("waiting_for_candidate_locks: test receiver dropped");
        wait_for_prune_publication_test_signal(
            &control.allow_publication,
            "waiting_for_publication",
        );
    }
}

#[cfg(not(test))]
fn await_prune_publication_validation_test_control(_locked: &BTreeMap<LocalJobId, LockedJob>) {}

#[cfg(test)]
fn await_prune_transaction_published_test_control(locked: &BTreeMap<LocalJobId, LockedJob>) {
    let control = prune_publication_lock_test_control(locked);
    if let Some(control) = control {
        control
            .transaction_published
            .send(())
            .expect("waiting_for_publication: test receiver dropped");
        wait_for_prune_publication_test_signal(
            &control.allow_lock_release,
            "waiting_for_worker_completion",
        );
    }
}

#[cfg(not(test))]
fn await_prune_transaction_published_test_control(_locked: &BTreeMap<LocalJobId, LockedJob>) {}

#[cfg(test)]
fn await_prune_candidate_locks_released_test_control(identifiers: &[LocalJobId]) {
    let control = PRUNE_PUBLICATION_LOCK_TEST_CONTROL
        .lock()
        .expect("prune-publication test-control lock is not poisoned")
        .as_ref()
        .filter(|control| identifiers.contains(&control.local_job_id))
        .cloned();
    if let Some(control) = control {
        control
            .candidate_locks_released
            .send(())
            .expect("waiting_for_worker_completion: test receiver dropped");
        wait_for_prune_publication_test_signal(
            &control.allow_finish,
            "waiting_for_worker_completion",
        );
    }
}

fn acquire_operation_lease_from_locked(
    store: &JobStore,
    local_job_id: &LocalJobId,
    kind: JobOperationKind,
    locked: LockedJob,
) -> Result<JobOperationLease, JobStoreError> {
    let job = store.version_root().join(local_job_id.as_str());
    let lease_path = job.join(OPERATION_LOCK_FILE);
    let lease = try_acquire_process_file_lease(&lease_path)
        .map_err(|source| io_error("acquire long-operation job lease", source))?
        .ok_or_else(|| JobStoreError::JobBusy {
            local_job_id: local_job_id.clone(),
        })?;
    inspect_private_revision_file(&lease_path, 0)?;
    let job_guard = locked.guards.last().ok_or(JobStoreError::MalformedLayout {
        reason: "job lease omitted its retained job-directory guard",
    })?;
    sync_directory(&job, job_guard)?;
    let store_version_root = fs::canonicalize(store.version_root())
        .map_err(|source| io_error("resolve operation lease job store", source))?;
    let store_identity = locked_store_identity(&locked)?;

    let LockedJob {
        lock,
        mut guards,
        revisions_guard,
        revisions: _,
    } = locked;
    drop(lock);
    guards.push(revisions_guard);
    Ok(JobOperationLease {
        local_job_id: local_job_id.clone(),
        kind,
        store_version_root,
        store_identity,
        _lease: lease,
        _guards: guards,
    })
}

fn acquire_snapshot_operation_reservation(
    store: &JobStore,
    operation_id: &str,
) -> Result<VacantSnapshotOperationLease, JobStoreError> {
    store.ensure_writable()?;
    validate_identifier("operation_id", operation_id)?;
    reject_pending_admin_transactions(store)?;
    let store_layout = store.ensure_store_layout()?;
    let reservations = store.version_root().join(OPERATION_RESERVATIONS_DIRECTORY);
    let reservations_guard = ensure_private_directory(&reservations)?;
    let lease_path = reservations.join(format!("{}.lock", sha256_hex(operation_id.as_bytes())));
    let lease = try_acquire_process_file_lease(&lease_path)
        .map_err(|source| io_error("acquire snapshot operation reservation", source))?
        .ok_or(JobStoreError::RecoveryRequired {
            reason: "another process is reserving the snapshot operation",
        })?;
    inspect_private_revision_file(&lease_path, 0)?;
    let consumed_path = reservations.join(format!("{}.used", sha256_hex(operation_id.as_bytes())));
    if read_consumed_snapshot_operation_at(&consumed_path, operation_id)?.is_some() {
        return Err(invalid_record(
            "provider operation was permanently consumed by a pruned job",
        ));
    }
    sync_directory(&reservations, &reservations_guard)?;
    let store_version_root = fs::canonicalize(store.version_root())
        .map_err(|source| io_error("resolve snapshot operation job store", source))?;
    let store_identity = DirectoryFilesystemIdentity::capture(&store.version_root())
        .map_err(|error| retained_directory_error("identify snapshot operation store", &error))?;
    let mut guards = store_layout.guards;
    guards.push(reservations_guard);
    Ok(VacantSnapshotOperationLease {
        operation_id: operation_id.to_owned(),
        store_version_root,
        store_identity,
        _lease: lease,
        _guards: guards,
    })
}

fn consumed_operation_path(store: &JobStore, operation_id: &str) -> PathBuf {
    store
        .version_root()
        .join(OPERATION_RESERVATIONS_DIRECTORY)
        .join(format!("{}.used", sha256_hex(operation_id.as_bytes())))
}

fn read_consumed_snapshot_operation(
    store: &JobStore,
    operation_id: &str,
) -> Result<Option<ConsumedOperationV1>, JobStoreError> {
    validate_identifier("operation_id", operation_id)?;
    let reservations = store.version_root().join(OPERATION_RESERVATIONS_DIRECTORY);
    let Some(_guard) = open_private_directory_if_present(
        &reservations,
        "operation reservation entry is linked or not a directory",
    )?
    else {
        return Ok(None);
    };
    let path = consumed_operation_path(store, operation_id);
    read_consumed_snapshot_operation_at(&path, operation_id)
}

fn read_consumed_snapshot_operation_at(
    path: &Path,
    operation_id: &str,
) -> Result<Option<ConsumedOperationV1>, JobStoreError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("inspect consumed operation marker", source)),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > 8 * 1024 =>
        {
            return Err(JobStoreError::MalformedLayout {
                reason: "consumed operation marker is linked or malformed",
            });
        }
        Ok(_) => {}
    }
    let bytes = read_private_bounded_file(path, 8 * 1024)?;
    let marker: ConsumedOperationV1 =
        serde_json::from_slice(&bytes).map_err(|source| JobStoreError::Serialization {
            operation: "decode consumed operation marker",
            source,
        })?;
    let canonical = encode_bounded_json(
        "consumed operation marker bytes",
        &marker,
        8 * 1024,
        "encode consumed operation marker",
    )?;
    if canonical != bytes
        || marker.schema_version != CONSUMED_OPERATION_SCHEMA_VERSION
        || marker.operation_id != operation_id
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "consumed operation marker binding is invalid",
        });
    }
    Ok(Some(marker))
}

fn reject_consumed_snapshot_operation(
    store: &JobStore,
    operation_id: &str,
) -> Result<(), JobStoreError> {
    if read_consumed_snapshot_operation(store, operation_id)?.is_some() {
        return Err(invalid_record(
            "provider operation was permanently consumed by a pruned job",
        ));
    }
    Ok(())
}

fn reject_consumed_snapshot_operation_while_reserved(
    store: &JobStore,
    operation_id: &str,
) -> Result<(), JobStoreError> {
    if read_consumed_snapshot_operation_at(
        &consumed_operation_path(store, operation_id),
        operation_id,
    )?
    .is_some()
    {
        return Err(invalid_record(
            "provider operation was permanently consumed by a pruned job",
        ));
    }
    Ok(())
}

fn scan_snapshot_operation_owner(
    store: &JobStore,
    operation_id: &str,
) -> Result<Option<(LocalJobId, StoredJobV1)>, JobStoreError> {
    let mut owner = None;
    for (local_job_id, (_, record)) in scan_active_jobs(store)? {
        if record.operation_id == operation_id && owner.replace((local_job_id, record)).is_some() {
            return Err(JobStoreError::MalformedLayout {
                reason: "multiple durable jobs own one provider operation",
            });
        }
    }
    Ok(owner)
}

pub(super) fn create_initial_job_serialized(
    store: &JobStore,
    record: &StoredJobV1,
) -> Result<RevisionReceipt, JobStoreError> {
    reject_tombstoned_local_job_id(store, &record.local_job_id)?;
    let reservation = acquire_snapshot_operation_reservation(store, &record.operation_id)?;
    reservation.validate_owner(store, &record.operation_id)?;
    if let Some((owner_id, _)) = scan_snapshot_operation_owner(store, &record.operation_id)? {
        if owner_id != record.local_job_id {
            return Err(invalid_record(
                "provider operation already belongs to another durable job",
            ));
        }
        await_initial_create_owner_test_control(&record.operation_id);
        reject_consumed_snapshot_operation_while_reserved(store, &record.operation_id)?;
        let receipt = store.append_inner(record, false)?;
        drop(reservation);
        return Ok(receipt);
    }
    reject_consumed_snapshot_operation_while_reserved(store, &record.operation_id)?;
    let locked = store.lock_job(&record.local_job_id, true)?;
    recover_revision_staging(&locked)?;
    if !scan_revision_files(&locked.revisions)?.is_empty() {
        return Err(invalid_record(
            "initial job target gained a revision without owning its operation",
        ));
    }
    reject_consumed_snapshot_operation_while_reserved(store, &record.operation_id)?;
    let receipt = publish_admin_job_revision(&locked, record, true, None)?;
    drop(locked);
    drop(reservation);
    Ok(receipt)
}

impl JobStore {
    /// Acquire exclusive proof that no durable job owns one snapshot operation.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, busy, existing-owner, recovery, identity, or storage error.
    pub fn try_acquire_vacant_snapshot_operation_lease(
        &self,
        operation_id: &str,
    ) -> Result<SnapshotOperationVacancyV1, JobStoreError> {
        let reservation = acquire_snapshot_operation_reservation(self, operation_id)?;
        if let Some((local_job_id, record)) = scan_snapshot_operation_owner(self, operation_id)? {
            return Ok(SnapshotOperationVacancyV1::Owned(Box::new(
                SnapshotOperationOwnerV1 {
                    local_job_id,
                    record,
                },
            )));
        }
        reject_consumed_snapshot_operation_while_reserved(self, operation_id)?;
        Ok(SnapshotOperationVacancyV1::Vacant(reservation))
    }

    /// Return the latest active durable owner of one provider snapshot operation.
    ///
    /// This performs no mutation and fails closed while any administrative transaction is
    /// incomplete, so recovery discovery cannot mistake a pending retry child for an orphan.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, pending-recovery, malformed-layout, or storage error.
    pub fn snapshot_operation_owner(
        &self,
        operation_id: &str,
    ) -> Result<Option<SnapshotOperationOwnerV1>, JobStoreError> {
        validate_identifier("operation_id", operation_id)?;
        reject_pending_admin_transactions(self)?;
        reject_consumed_snapshot_operation(self, operation_id)?;
        let read_only = JobStore {
            root: self.root.clone(),
            access: JobStoreAccess::ReadOnly,
        };
        let owner = scan_snapshot_operation_owner(&read_only, operation_id)?.map(
            |(local_job_id, record)| SnapshotOperationOwnerV1 {
                local_job_id,
                record,
            },
        );
        reject_consumed_snapshot_operation(&read_only, operation_id)?;
        Ok(owner)
    }

    /// Publish an initial job and retain its Build lease without an ownership gap.
    ///
    /// # Errors
    ///
    /// Returns a typed vacancy, validation, publication, lease, identity, or storage error.
    pub fn create_with_operation_lease(
        &self,
        vacancy: VacantSnapshotOperationLease,
        record: &StoredJobV1,
    ) -> Result<LeasedJobCreationReceipt, JobStoreError> {
        vacancy.validate_owner(self, &record.operation_id)?;
        reject_tombstoned_local_job_id(self, &record.local_job_id)?;
        if scan_snapshot_operation_owner(self, &record.operation_id)?.is_some() {
            return Err(invalid_record(
                "snapshot operation acquired a durable owner before publication",
            ));
        }
        reject_consumed_snapshot_operation_while_reserved(self, &record.operation_id)?;
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
        let locked = self.lock_job(&record.local_job_id, true)?;
        recover_revision_staging(&locked)?;
        if !scan_revision_files(&locked.revisions)?.is_empty() {
            return Err(invalid_record(
                "snapshot operation target acquired a job revision before publication",
            ));
        }
        reject_consumed_snapshot_operation_while_reserved(self, &record.operation_id)?;
        let revision = publish_admin_job_revision(&locked, record, true, None)?;
        let operation_lease = acquire_operation_lease_from_locked(
            self,
            &record.local_job_id,
            JobOperationKind::Build,
            locked,
        )?;
        drop(vacancy);
        Ok(LeasedJobCreationReceipt {
            revision,
            operation_lease,
        })
    }

    /// Try to acquire the one process-lifetime long-operation lease for a job.
    ///
    /// A live holder always yields [`JobStoreError::JobBusy`]. The operating system releases the
    /// lease when its holder exits, so callers never break a lease using timestamps or PID reuse.
    /// A `Logs` holder covers one fetch-and-append poll and must be dropped before follow-mode
    /// sleeping. A `Build` holder covers a bounded store/provider mutation, not the whole remote
    /// run, so cancellation can acquire the lease between operations. A consuming mutation also
    /// verifies the canonical store path and retained filesystem identity captured by this lease.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, busy, private-storage, or I/O error.
    pub fn try_acquire_operation_lease(
        &self,
        local_job_id: &LocalJobId,
        kind: JobOperationKind,
    ) -> Result<JobOperationLease, JobStoreError> {
        self.ensure_writable()?;
        reject_pending_transaction_for_job(self, local_job_id)?;
        if kind != JobOperationKind::Prune {
            reject_active_prune_release_for_job(self, local_job_id)?;
        }
        let locked = self.lock_job(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        let revisions = scan_revision_files(&locked.revisions)?;
        let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: local_job_id.clone(),
        })?;
        drop(read_job_revision(
            &latest.path,
            latest.revision,
            &latest.sha256,
            local_job_id,
        )?);

        acquire_operation_lease_from_locked(self, local_job_id, kind, locked)
    }

    /// Read the exact latest job while proving a borrowed operation lease's store, job, and kind.
    ///
    /// # Errors
    ///
    /// Returns a typed foreign-store, wrong-job, wrong-kind, missing-job, recovery, or storage
    /// error. The lease remains owned by the caller.
    pub fn latest_under_operation_lease(
        &self,
        local_job_id: &LocalJobId,
        kind: JobOperationKind,
        lease: &JobOperationLease,
    ) -> Result<StoredJobV1, JobStoreError> {
        self.ensure_writable()?;
        reject_pending_transaction_for_job(self, local_job_id)?;
        let locked = self.lock_job(local_job_id, false)?;
        recover_revision_staging(&locked)?;
        lease.validate_owner(self, &locked, local_job_id, kind)?;
        latest_locked(&locked, local_job_id)
    }

    /// Append one bounded contiguous batch to the job-owned managed event store.
    ///
    /// Identical already-published sequences deduplicate. A different record at an existing
    /// sequence or a skipped sequence fails closed. The first append binds the fixed managed
    /// `log_location` in a full immutable job revision before publishing events. Multi-record
    /// batches require a paired source sequence and digest on every input so a crash prefix can be
    /// retried without ambiguity. One unsequenced input remains valid for local best-effort events,
    /// but retrying it after [`JobStoreError::CommitUncertain`] can append a duplicate; provider-log
    /// and other restart-safe flows must always supply the immutable pair.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, ordering, bound, lock, publication, or storage error.
    #[allow(
        clippy::too_many_lines,
        reason = "the bounded append keeps validation, deduplication, sequencing, and publication under one job lock"
    )]
    pub fn append_managed_events(
        &self,
        local_job_id: &LocalJobId,
        updated_at_ms: u64,
        events: &[ManagedJobEventInputV1],
    ) -> Result<ManagedEventAppendReceipt, JobStoreError> {
        self.ensure_writable()?;
        if events.len() > MAX_MANAGED_EVENT_BATCH {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event append batch",
                maximum: MAX_MANAGED_EVENT_BATCH as u64,
            });
        }
        if events.len() > 1 && events.iter().any(|event| event.source_sequence.is_none()) {
            return Err(invalid_record(
                "multi-record managed event append requires immutable source identity for every record",
            ));
        }
        let mut batch_by_source = BTreeMap::new();
        for event in events {
            event.validate()?;
            if let Some(source_sequence) = event.source_sequence
                && let Some(existing) =
                    batch_by_source.insert((event.source, source_sequence), event)
                && existing != event
            {
                return Err(invalid_record(
                    "managed source-event replay differs within one append batch",
                ));
            }
        }

        self.bind_managed_event_location(local_job_id, updated_at_ms)?;
        let locked = lock_job_for_short_admin_append(self, local_job_id)?;
        recover_revision_staging(&locked)?;
        let latest = latest_locked(&locked, local_job_id)?;
        if latest.log_location.as_deref() != Some(MANAGED_LOG_LOCATION) {
            return Err(invalid_record(
                "job log location is not the managed v1 event store",
            ));
        }
        let managed = ensure_managed_event_directory(self, &locked, local_job_id)?;
        recover_managed_staging(&managed)?;
        let existing = scan_managed_event_files(&managed, local_job_id)?;
        let mut by_sequence = BTreeMap::new();
        let mut by_source = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for entry in existing {
            total_bytes = total_bytes.saturating_add(entry.bytes);
            let event = read_managed_event(&entry, local_job_id)?;
            if let (Some(source_sequence), Some(_)) =
                (event.source_sequence, event.source_event_sha256.as_ref())
                && by_source
                    .insert((event.source, source_sequence), event.clone())
                    .is_some()
            {
                return Err(JobStoreError::MalformedRevision {
                    reason: "managed event source sequence is duplicated",
                });
            }
            by_sequence.insert(entry.sequence, entry);
        }
        if by_sequence.len() > MAX_MANAGED_EVENTS_PER_JOB
            || total_bytes > MAX_MANAGED_EVENT_TOTAL_BYTES
        {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event store",
                maximum: MAX_MANAGED_EVENTS_PER_JOB as u64,
            });
        }

        let mut appended = 0;
        let mut already_present = 0;
        let mut assigned = Vec::with_capacity(events.len());
        let mut prepared = Vec::with_capacity(events.len());
        let mut expected = by_sequence
            .last_key_value()
            .map_or(1, |(sequence, _)| sequence.saturating_add(1));
        for input in events {
            let source_key = input
                .source_sequence
                .map(|source_sequence| (input.source, source_sequence));
            if let Some(existing) = source_key.as_ref().and_then(|key| by_source.get(key)) {
                if existing.as_input() != *input {
                    return Err(invalid_record(
                        "managed source-event replay differs from its immutable payload",
                    ));
                }
                already_present += 1;
                assigned.push(existing.clone());
                continue;
            }
            if by_sequence.len().saturating_add(prepared.len()) >= MAX_MANAGED_EVENTS_PER_JOB {
                return Err(JobStoreError::BoundExceeded {
                    kind: "managed event records",
                    maximum: MAX_MANAGED_EVENTS_PER_JOB as u64,
                });
            }
            let event = ManagedJobEventV1 {
                schema_version: MANAGED_EVENT_SCHEMA_VERSION,
                local_job_id: local_job_id.clone(),
                sequence: expected,
                occurred_at_ms: input.occurred_at_ms,
                phase: input.phase.clone(),
                source: input.source,
                source_sequence: input.source_sequence,
                source_event_sha256: input.source_event_sha256.clone(),
                level: input.level,
                code: input.code.clone(),
                message: input.message.clone(),
            };
            let bytes = event.validate_for(local_job_id)?;
            let sha256 = sha256_hex(&bytes);
            total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or(
                JobStoreError::BoundExceeded {
                    kind: "managed event bytes",
                    maximum: MAX_MANAGED_EVENT_TOTAL_BYTES,
                },
            )?;
            if total_bytes > MAX_MANAGED_EVENT_TOTAL_BYTES {
                return Err(JobStoreError::BoundExceeded {
                    kind: "managed event bytes",
                    maximum: MAX_MANAGED_EVENT_TOTAL_BYTES,
                });
            }
            let final_path = managed
                .revisions
                .join(managed_event_filename(event.sequence, &sha256));
            if let Some(key) = source_key {
                by_source.insert(key, event.clone());
            }
            assigned.push(event.clone());
            prepared.push(PreparedManagedEvent {
                event,
                bytes,
                final_path,
            });
            appended += 1;
            expected = expected.saturating_add(1);
        }

        let first_appended_sequence = prepared.first().map(|prepared| prepared.event.sequence);
        for prepared in prepared {
            #[cfg(test)]
            managed_event_publication_checkpoint(&prepared.final_path)?;
            publish_managed_bytes(
                &managed,
                &prepared.final_path,
                &prepared.bytes,
                MAX_MANAGED_EVENT_BYTES,
            )?;
        }

        Ok(ManagedEventAppendReceipt {
            local_job_id: local_job_id.clone(),
            first_appended_sequence,
            last_sequence: expected.saturating_sub(1),
            appended,
            already_present,
            assigned,
        })
    }

    /// Read one bounded canonical page of managed job events after an exclusive sequence cursor.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, not-found, lock, malformed-record, or storage error.
    pub fn read_managed_events(
        &self,
        local_job_id: &LocalJobId,
        after_sequence: u64,
        limit: usize,
    ) -> Result<ManagedEventPageV1, JobStoreError> {
        if limit == 0 || limit > MAX_MANAGED_EVENT_PAGE {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event page",
                maximum: MAX_MANAGED_EVENT_PAGE as u64,
            });
        }
        reject_pending_transaction_for_job(self, local_job_id)?;
        let (record, locked) = if self.access == JobStoreAccess::ReadOnly {
            let opened = self.open_read_only_job(local_job_id)?;
            let latest = latest_read_only(&opened, local_job_id)?;
            (latest, ManagedJobReadGuard::ReadOnly(opened))
        } else {
            let opened = self.lock_job(local_job_id, false)?;
            recover_revision_staging(&opened)?;
            let latest = latest_locked(&opened, local_job_id)?;
            (latest, ManagedJobReadGuard::ReadWrite(opened))
        };
        if record.log_location.is_none() {
            return Ok(ManagedEventPageV1 {
                local_job_id: local_job_id.clone(),
                events: Vec::new(),
                next_after_sequence: after_sequence,
                has_more: false,
            });
        }
        if record.log_location.as_deref() != Some(MANAGED_LOG_LOCATION) {
            return Err(invalid_record(
                "job log location is not managed by this store",
            ));
        }
        let managed = open_managed_event_directory(self, &locked, local_job_id)?;
        let entries = scan_managed_event_files(&managed, local_job_id)?;
        let mut selected = entries
            .into_iter()
            .filter(|entry| entry.sequence > after_sequence)
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        let has_more = selected.len() > limit;
        selected.truncate(limit);
        let mut events = Vec::with_capacity(selected.len());
        for entry in &selected {
            events.push(read_managed_event(entry, local_job_id)?);
        }
        let next_after_sequence = events.last().map_or(after_sequence, |event| event.sequence);
        Ok(ManagedEventPageV1 {
            local_job_id: local_job_id.clone(),
            events,
            next_after_sequence,
            has_more,
        })
    }

    fn bind_managed_event_location(
        &self,
        local_job_id: &LocalJobId,
        updated_at_ms: u64,
    ) -> Result<(), JobStoreError> {
        for attempt in 0..4_096 {
            let result = self.update_optional(local_job_id, |previous| {
                match previous.log_location.as_deref() {
                    Some(MANAGED_LOG_LOCATION) => return Ok(None),
                    Some(_) => {
                        return Err(invalid_record(
                            "job log location was already bound outside the managed event store",
                        ));
                    }
                    None => {}
                }
                let mut next = previous.clone();
                next.revision = previous.revision.saturating_add(1);
                next.updated_at_ms = updated_at_ms.max(previous.updated_at_ms);
                next.log_location = Some(MANAGED_LOG_LOCATION.to_owned());
                Ok(Some(next))
            });
            match result {
                Ok(receipt) => {
                    drop(receipt);
                    return Ok(());
                }
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

    /// List artifacts with their immutable path provenance and external removal overlay.
    ///
    /// `None` lists all active jobs; `Some` restricts the result to one exact owner.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, lock, record, overlay, or storage error.
    pub fn list_managed_artifacts(
        &self,
        local_job_id: Option<&LocalJobId>,
    ) -> Result<Vec<ManagedArtifactViewV1>, JobStoreError> {
        reject_pending_admin_transactions(self)?;
        let records = if let Some(local_job_id) = local_job_id {
            let record = self.latest(local_job_id)?;
            BTreeMap::from([(local_job_id.clone(), record)])
        } else {
            scan_active_jobs(self)?
                .into_iter()
                .map(|(identifier, (_, record))| (identifier, record))
                .collect()
        };
        let mut views = Vec::new();
        for (identifier, record) in records {
            let overlays = read_artifact_overlays(self, &identifier)?;
            for artifact in record.artifacts {
                let artifact_ref = ManagedArtifactRefV1 {
                    local_job_id: identifier.clone(),
                    provider_artifact_id: artifact.record.artifact_id.clone(),
                };
                let overlay = overlays.get(&artifact_ref.provider_artifact_id);
                views.push(ManagedArtifactViewV1 {
                    artifact_ref,
                    record: artifact.record,
                    local_path: artifact.local_path,
                    local_file_identity: artifact.local_file_identity,
                    removal_state: overlay
                        .map_or(ManagedArtifactRemovalState::Available, |overlay| {
                            overlay.state
                        }),
                    removal_updated_at_ms: overlay.map(|overlay| overlay.updated_at_ms),
                });
            }
        }
        views.sort_by(|left, right| left.artifact_ref.cmp(&right.artifact_ref));
        Ok(views)
    }

    /// Resolve one canonical artifact reference, rejecting a bare ID shared by multiple jobs.
    ///
    /// # Errors
    ///
    /// Returns not-found, ambiguity, malformed-record, lock, or storage errors.
    pub fn resolve_managed_artifact(
        &self,
        provider_artifact_id: &str,
        local_job_id: Option<&LocalJobId>,
    ) -> Result<ManagedArtifactViewV1, JobStoreError> {
        validate_identifier("provider_artifact_id", provider_artifact_id)?;
        let mut matches = self
            .list_managed_artifacts(local_job_id)?
            .into_iter()
            .filter(|artifact| artifact.artifact_ref.provider_artifact_id == provider_artifact_id);
        let first = matches
            .next()
            .ok_or_else(|| JobStoreError::ArtifactNotFound {
                provider_artifact_id: provider_artifact_id.to_owned(),
            })?;
        if matches.next().is_some() {
            return Err(JobStoreError::ArtifactReferenceAmbiguous {
                provider_artifact_id: provider_artifact_id.to_owned(),
            });
        }
        Ok(first)
    }

    /// Whether this platform provides handle-bound exact artifact deletion.
    #[must_use]
    pub const fn supports_exact_artifact_removal(&self) -> bool {
        cfg!(windows)
    }

    /// Persist exact artifact-removal intent, remove only the retained expected file, then append
    /// a removed or uncertain overlay without clearing immutable job provenance.
    ///
    /// # Errors
    ///
    /// Returns a typed platform-support, lease-owner, reference, record, lock, publication, or
    /// storage error. Exact removal/replacement failures are represented as a durable `uncertain`
    /// receipt.
    #[allow(
        clippy::too_many_lines,
        reason = "intent reconciliation and exact handle-bound removal remain under one owner job lock"
    )]
    pub fn remove_managed_artifact(
        &self,
        lease: &JobOperationLease,
        artifact_ref: &ManagedArtifactRefV1,
        updated_at_ms: u64,
    ) -> Result<ManagedArtifactRemovalReceiptV1, JobStoreError> {
        self.ensure_writable()?;
        if !self.supports_exact_artifact_removal() {
            return Err(JobStoreError::ArtifactRemovalUnsupported);
        }
        validate_identifier("provider_artifact_id", &artifact_ref.provider_artifact_id)?;
        let locked = self.lock_job(&artifact_ref.local_job_id, false)?;
        lease.validate_owner(
            self,
            &locked,
            &artifact_ref.local_job_id,
            JobOperationKind::ArtifactRemoval,
        )?;
        recover_revision_staging(&locked)?;
        let record = latest_locked(&locked, &artifact_ref.local_job_id)?;
        let artifact = record
            .artifacts
            .iter()
            .find(|artifact| artifact.record.artifact_id == artifact_ref.provider_artifact_id)
            .ok_or_else(|| invalid_record("artifact reference is not owned by the local job"))?;
        let expected_path = artifact
            .local_path
            .clone()
            .ok_or_else(|| invalid_record("artifact has no published local path"))?;
        let expected_file_identity = artifact
            .local_file_identity
            .clone()
            .ok_or_else(|| invalid_record("artifact has no published local file identity"))?;
        let directory = ensure_artifact_overlay_directory(self, &locked, artifact_ref)?;
        recover_managed_staging(&directory)?;
        let mut overlays = scan_artifact_overlays(&directory, artifact_ref)?;
        let mut previous = None;
        for overlay in &overlays {
            validate_artifact_overlay(artifact, overlay, previous)?;
            previous = Some(overlay);
        }
        if let Some(latest) = overlays.last()
            && latest.state == ManagedArtifactRemovalState::Removed
        {
            return Ok(ManagedArtifactRemovalReceiptV1 {
                artifact_ref: artifact_ref.clone(),
                state: ManagedArtifactRemovalState::Removed,
                already_complete: true,
            });
        }
        let additional_overlays = if overlays
            .last()
            .is_some_and(|latest| latest.state == ManagedArtifactRemovalState::Intent)
        {
            1
        } else {
            2
        };
        if overlays.len().saturating_add(additional_overlays)
            > MAX_ARTIFACT_REMOVAL_OVERLAYS_PER_JOB
        {
            return Err(JobStoreError::BoundExceeded {
                kind: "artifact removal overlays",
                maximum: MAX_ARTIFACT_REMOVAL_OVERLAYS_PER_JOB as u64,
            });
        }

        let intent = if let Some(latest) = overlays
            .last()
            .filter(|latest| latest.state == ManagedArtifactRemovalState::Intent)
        {
            latest.clone()
        } else {
            let intent = ArtifactRemovalOverlayV1 {
                schema_version: 1,
                revision: overlays
                    .last()
                    .map_or(1, |overlay| overlay.revision.saturating_add(1)),
                artifact_ref: artifact_ref.clone(),
                expected_path,
                expected_file_identity,
                expected_sha256: artifact.record.sha256.clone(),
                expected_size: artifact.record.size,
                state: ManagedArtifactRemovalState::Intent,
                updated_at_ms: overlays.last().map_or(updated_at_ms, |overlay| {
                    overlay.updated_at_ms.max(updated_at_ms)
                }),
            };
            validate_artifact_overlay(artifact, &intent, overlays.last())?;
            publish_artifact_overlay(&directory, &intent)?;
            overlays.push(intent.clone());
            intent
        };

        let state = remove_exact_persisted_artifact(&intent);
        let result = ArtifactRemovalOverlayV1 {
            schema_version: 1,
            revision: intent.revision.saturating_add(1),
            artifact_ref: artifact_ref.clone(),
            expected_path: intent.expected_path.clone(),
            expected_file_identity: intent.expected_file_identity.clone(),
            expected_sha256: intent.expected_sha256.clone(),
            expected_size: intent.expected_size,
            state,
            updated_at_ms: intent.updated_at_ms.max(updated_at_ms),
        };
        validate_artifact_overlay(artifact, &result, Some(&intent))?;
        let already_complete = publish_artifact_overlay(&directory, &result)?;
        Ok(ManagedArtifactRemovalReceiptV1 {
            artifact_ref: artifact_ref.clone(),
            state,
            already_complete,
        })
    }
}

fn lock_job_for_short_admin_append(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<LockedJob, JobStoreError> {
    for attempt in 0..4_096 {
        match store.lock_job(local_job_id, false) {
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

enum ManagedJobReadGuard {
    ReadWrite(LockedJob),
    ReadOnly(ReadOnlyJob),
}

fn locked_store_identity(locked: &LockedJob) -> Result<DirectoryFilesystemIdentity, JobStoreError> {
    let version_guard_index =
        locked
            .guards
            .len()
            .checked_sub(2)
            .ok_or(JobStoreError::MalformedLayout {
                reason: "job lock omitted its retained store-version guard",
            })?;
    let version_guard = &locked.guards[version_guard_index];
    rustferry_core::directory_identity_from_file(version_guard).map_err(|error| {
        retained_directory_error("identify retained operation lease job store", &error)
    })
}

fn latest_locked(
    locked: &LockedJob,
    local_job_id: &LocalJobId,
) -> Result<StoredJobV1, JobStoreError> {
    let revisions = scan_revision_files(&locked.revisions)?;
    let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
        local_job_id: local_job_id.clone(),
    })?;
    read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id)
}

fn latest_read_only(
    opened: &ReadOnlyJob,
    local_job_id: &LocalJobId,
) -> Result<StoredJobV1, JobStoreError> {
    let revisions = scan_revision_files(&opened.revisions)?;
    let latest = revisions.last().ok_or_else(|| JobStoreError::JobNotFound {
        local_job_id: local_job_id.clone(),
    })?;
    read_job_revision(&latest.path, latest.revision, &latest.sha256, local_job_id)
}

fn ensure_managed_event_directory(
    store: &JobStore,
    locked: &LockedJob,
    local_job_id: &LocalJobId,
) -> Result<LockedJob, JobStoreError> {
    let job = store.version_root().join(local_job_id.as_str());
    let events = job.join(EVENTS_DIRECTORY);
    let events_guard = ensure_private_directory(&events)?;
    sync_directory(&events, &events_guard)?;
    let job_guard = locked.guards.last().ok_or(JobStoreError::MalformedLayout {
        reason: "managed event store omitted its retained job-directory guard",
    })?;
    sync_directory(&job, job_guard)?;
    Ok(LockedJob {
        lock: locked.lock.clone(),
        guards: Vec::new(),
        revisions_guard: events_guard,
        revisions: events,
    })
}

fn open_managed_event_directory(
    store: &JobStore,
    locked: &ManagedJobReadGuard,
    local_job_id: &LocalJobId,
) -> Result<LockedJob, JobStoreError> {
    let events = store
        .version_root()
        .join(local_job_id.as_str())
        .join(EVENTS_DIRECTORY);
    let events_guard = open_private_directory_if_present(
        &events,
        "managed event entry is linked or not a directory",
    )?
    .ok_or(JobStoreError::MalformedLayout {
        reason: "bound managed event directory is missing",
    })?;
    let lock = match locked {
        ManagedJobReadGuard::ReadWrite(locked) => locked.lock.clone(),
        ManagedJobReadGuard::ReadOnly(opened) => opened.lock.clone(),
    };
    Ok(LockedJob {
        lock,
        guards: Vec::new(),
        revisions_guard: events_guard,
        revisions: events,
    })
}

fn ensure_artifact_overlay_directory(
    store: &JobStore,
    locked: &LockedJob,
    artifact_ref: &ManagedArtifactRefV1,
) -> Result<LockedJob, JobStoreError> {
    if artifact_ref.local_job_id.as_str().is_empty() {
        return Err(invalid_record("artifact overlay owner is empty"));
    }
    let job = store
        .version_root()
        .join(artifact_ref.local_job_id.as_str());
    let overlays = job.join(ARTIFACT_REMOVALS_DIRECTORY);
    let overlays_guard = ensure_private_directory(&overlays)?;
    sync_directory(&overlays, &overlays_guard)?;
    let job_guard = locked.guards.last().ok_or(JobStoreError::MalformedLayout {
        reason: "artifact overlay omitted its retained job-directory guard",
    })?;
    sync_directory(&job, job_guard)?;
    Ok(LockedJob {
        lock: locked.lock.clone(),
        guards: Vec::new(),
        revisions_guard: overlays_guard,
        revisions: overlays,
    })
}

fn read_artifact_overlays(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<BTreeMap<String, ArtifactRemovalOverlayV1>, JobStoreError> {
    let overlays = store
        .version_root()
        .join(local_job_id.as_str())
        .join(ARTIFACT_REMOVALS_DIRECTORY);
    let Some(guard) = open_private_directory_if_present(
        &overlays,
        "artifact removals entry is linked or not a directory",
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let record = store.latest(local_job_id)?;
    let lock = if store.access == JobStoreAccess::ReadOnly {
        store.open_read_only_job(local_job_id)?.lock
    } else {
        store.lock_job(local_job_id, false)?.lock
    };
    let directory = LockedJob {
        lock,
        guards: Vec::new(),
        revisions_guard: guard,
        revisions: overlays,
    };
    latest_artifact_overlays_for_record(
        &record,
        scan_all_artifact_overlays(&directory, local_job_id)?,
    )
}

fn read_artifact_overlays_locked(
    store: &JobStore,
    locked: &LockedJob,
    record: &StoredJobV1,
) -> Result<BTreeMap<String, ArtifactRemovalOverlayV1>, JobStoreError> {
    let overlays = store
        .version_root()
        .join(record.local_job_id.as_str())
        .join(ARTIFACT_REMOVALS_DIRECTORY);
    let Some(guard) = open_private_directory_if_present(
        &overlays,
        "artifact removals entry is linked or not a directory",
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let directory = LockedJob {
        lock: locked.lock.clone(),
        guards: Vec::new(),
        revisions_guard: guard,
        revisions: overlays,
    };
    latest_artifact_overlays_for_record(
        record,
        scan_all_artifact_overlays(&directory, &record.local_job_id)?,
    )
}

fn latest_artifact_overlays_for_record(
    record: &StoredJobV1,
    overlays: Vec<ArtifactRemovalOverlayV1>,
) -> Result<BTreeMap<String, ArtifactRemovalOverlayV1>, JobStoreError> {
    let mut latest = BTreeMap::new();
    let mut grouped = BTreeMap::<String, Vec<ArtifactRemovalOverlayV1>>::new();
    for overlay in overlays {
        grouped
            .entry(overlay.artifact_ref.provider_artifact_id.clone())
            .or_default()
            .push(overlay);
    }
    for (artifact_id, overlays) in grouped {
        let artifact = record
            .artifacts
            .iter()
            .find(|artifact| artifact.record.artifact_id == artifact_id)
            .ok_or_else(|| invalid_record("artifact removal overlay has no owning manifest"))?;
        let mut previous = None;
        for overlay in &overlays {
            validate_artifact_overlay(artifact, overlay, previous)?;
            previous = Some(overlay);
        }
        if let Some(overlay) = overlays.last() {
            latest.insert(artifact_id, overlay.clone());
        }
    }
    Ok(latest)
}

fn scan_artifact_overlays(
    directory: &LockedJob,
    artifact_ref: &ManagedArtifactRefV1,
) -> Result<Vec<ArtifactRemovalOverlayV1>, JobStoreError> {
    let overlays = scan_all_artifact_overlays(directory, &artifact_ref.local_job_id)?
        .into_iter()
        .filter(|overlay| overlay.artifact_ref == *artifact_ref)
        .collect::<Vec<_>>();
    for (index, overlay) in overlays.iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if overlay.revision != expected {
            return Err(JobStoreError::MalformedRevision {
                reason: "artifact removal overlay revisions are non-contiguous",
            });
        }
    }
    Ok(overlays)
}

fn scan_all_artifact_overlays(
    directory: &LockedJob,
    local_job_id: &LocalJobId,
) -> Result<Vec<ArtifactRemovalOverlayV1>, JobStoreError> {
    let mut overlays = Vec::new();
    for entry in fs::read_dir(&directory.revisions)
        .map_err(|source| io_error("read artifact removal overlays", source))?
    {
        if overlays.len() >= MAX_ARTIFACT_REMOVAL_OVERLAYS_PER_JOB {
            return Err(JobStoreError::BoundExceeded {
                kind: "artifact removal overlays",
                maximum: MAX_ARTIFACT_REMOVAL_OVERLAYS_PER_JOB as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read artifact removal entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "artifact removal filename is not UTF-8",
            })?;
        if is_revision_staging_name(&name) {
            return Err(JobStoreError::RecoveryRequired {
                reason: "artifact removal staging requires writable recovery",
            });
        }
        let (artifact_id, revision, sha256) = parse_artifact_overlay_filename(&name)?;
        let bytes = read_private_bounded_file(&entry.path(), 32 * 1024)?;
        if sha256_hex(&bytes) != sha256 {
            return Err(JobStoreError::MalformedRevision {
                reason: "artifact removal overlay differs from its filename digest",
            });
        }
        let overlay: ArtifactRemovalOverlayV1 =
            serde_json::from_slice(&bytes).map_err(|_| JobStoreError::MalformedRevision {
                reason: "artifact removal overlay is not canonical v1 JSON",
            })?;
        let canonical = encode_bounded_json(
            "artifact removal overlay bytes",
            &overlay,
            32 * 1024,
            "encode artifact removal overlay",
        )?;
        if canonical != bytes
            || overlay.revision != revision
            || overlay.artifact_ref.provider_artifact_id != artifact_id
            || overlay.artifact_ref.local_job_id != *local_job_id
        {
            return Err(JobStoreError::MalformedRevision {
                reason: "artifact removal overlay is not canonically filename-bound",
            });
        }
        overlays.push(overlay);
    }
    overlays.sort_by(|left, right| {
        (&left.artifact_ref.provider_artifact_id, left.revision)
            .cmp(&(&right.artifact_ref.provider_artifact_id, right.revision))
    });
    Ok(overlays)
}

fn parse_artifact_overlay_filename(name: &str) -> Result<(String, u64, String), JobStoreError> {
    let stem = name
        .strip_suffix(".json")
        .ok_or(JobStoreError::MalformedLayout {
            reason: "artifact removal filename has an unexpected extension",
        })?;
    let (prefix, sha256) = stem
        .rsplit_once('-')
        .ok_or(JobStoreError::MalformedLayout {
            reason: "artifact removal filename is malformed",
        })?;
    let (artifact_id, revision) =
        prefix
            .rsplit_once('-')
            .ok_or(JobStoreError::MalformedLayout {
                reason: "artifact removal filename is malformed",
            })?;
    validate_identifier("provider_artifact_id", artifact_id)?;
    if revision.len() != REVISION_DIGITS
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || !is_sha256(sha256)
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "artifact removal filename is malformed",
        });
    }
    let revision_text = revision;
    let revision = revision_text
        .parse::<u64>()
        .map_err(|_| JobStoreError::MalformedLayout {
            reason: "artifact removal revision is outside the supported range",
        })?;
    Ok((artifact_id.to_owned(), revision, sha256.to_owned()))
}

fn validate_artifact_overlay(
    artifact: &StoredArtifactV1,
    overlay: &ArtifactRemovalOverlayV1,
    previous: Option<&ArtifactRemovalOverlayV1>,
) -> Result<(), JobStoreError> {
    if overlay.schema_version != 1
        || overlay.revision == 0
        || overlay.artifact_ref.provider_artifact_id != artifact.record.artifact_id
        || Some(overlay.expected_path.as_str()) != artifact.local_path.as_deref()
        || Some(overlay.expected_file_identity.as_str()) != artifact.local_file_identity.as_deref()
        || overlay.expected_sha256 != artifact.record.sha256
        || overlay.expected_size != artifact.record.size
        || overlay.state == ManagedArtifactRemovalState::Available
    {
        return Err(invalid_record(
            "artifact removal overlay differs from immutable artifact provenance",
        ));
    }
    validate_local_artifact_path("artifact_removal.expected_path", &overlay.expected_path)?;
    validate_sha256("artifact_removal.expected_sha256", &overlay.expected_sha256)?;
    let identity = overlay
        .expected_file_identity
        .parse::<RegularFileFilesystemIdentity>()
        .map_err(|_| invalid_record("artifact removal file identity is invalid"))?;
    if identity.to_string() != overlay.expected_file_identity {
        return Err(invalid_record(
            "artifact removal file identity is not canonical",
        ));
    }
    match previous {
        None if overlay.revision == 1 && overlay.state == ManagedArtifactRemovalState::Intent => {}
        Some(previous)
            if overlay.revision == previous.revision.saturating_add(1)
                && overlay.updated_at_ms >= previous.updated_at_ms
                && overlay.artifact_ref == previous.artifact_ref
                && overlay.expected_path == previous.expected_path
                && overlay.expected_file_identity == previous.expected_file_identity
                && overlay.expected_sha256 == previous.expected_sha256
                && overlay.expected_size == previous.expected_size
                && matches!(
                    (previous.state, overlay.state),
                    (
                        ManagedArtifactRemovalState::Intent,
                        ManagedArtifactRemovalState::Removed
                            | ManagedArtifactRemovalState::Uncertain
                    ) | (
                        ManagedArtifactRemovalState::Uncertain,
                        ManagedArtifactRemovalState::Intent
                    )
                ) => {}
        _ => {
            return Err(invalid_record(
                "artifact removal overlay transition is invalid",
            ));
        }
    }
    Ok(())
}

fn publish_artifact_overlay(
    directory: &LockedJob,
    overlay: &ArtifactRemovalOverlayV1,
) -> Result<bool, JobStoreError> {
    let bytes = encode_bounded_json(
        "artifact removal overlay bytes",
        overlay,
        32 * 1024,
        "encode artifact removal overlay",
    )?;
    let sha256 = sha256_hex(&bytes);
    let path = directory.revisions.join(format!(
        "{}-{:0REVISION_DIGITS$}-{sha256}.json",
        overlay.artifact_ref.provider_artifact_id, overlay.revision
    ));
    publish_managed_bytes(directory, &path, &bytes, 32 * 1024)
}

#[cfg(windows)]
fn remove_exact_persisted_artifact(
    intent: &ArtifactRemovalOverlayV1,
) -> ManagedArtifactRemovalState {
    use rustferry_core::{open_regular_file_for_exact_removal, regular_file_identity_from_file};

    let Ok(expected_identity) = intent
        .expected_file_identity
        .parse::<RegularFileFilesystemIdentity>()
    else {
        return ManagedArtifactRemovalState::Uncertain;
    };
    let path = PathBuf::from(&intent.expected_path);
    let removal = match open_regular_file_for_exact_removal(&path) {
        Ok(removal) if removal.identity() == &expected_identity => removal,
        _ => return ManagedArtifactRemovalState::Uncertain,
    };
    let Ok(mut reader) = File::open(&path) else {
        return ManagedArtifactRemovalState::Uncertain;
    };
    if regular_file_identity_from_file(&reader).ok().as_ref() != Some(&expected_identity) {
        return ManagedArtifactRemovalState::Uncertain;
    }
    if reader
        .metadata()
        .ok()
        .is_none_or(|metadata| metadata.len() != intent.expected_size)
    {
        return ManagedArtifactRemovalState::Uncertain;
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return ManagedArtifactRemovalState::Uncertain,
        }
    }
    if lower_hex(digest.finalize()) != intent.expected_sha256 {
        return ManagedArtifactRemovalState::Uncertain;
    }
    drop(reader);
    if removal.remove().is_ok() {
        ManagedArtifactRemovalState::Removed
    } else {
        ManagedArtifactRemovalState::Uncertain
    }
}

#[cfg(unix)]
fn remove_exact_persisted_artifact(
    _intent: &ArtifactRemovalOverlayV1,
) -> ManagedArtifactRemovalState {
    // POSIX has no unlink-by-file-descriptor primitive. A same-UID process can replace a
    // pathname after its identity is checked and before unlink(2), so mutating here could delete
    // an unrelated replacement. The public API rejects this platform before publishing intent;
    // this defensive fallback also leaves the expected path and every overlay untouched.
    ManagedArtifactRemovalState::Uncertain
}

#[cfg(all(not(unix), not(windows)))]
fn remove_exact_persisted_artifact(
    _intent: &ArtifactRemovalOverlayV1,
) -> ManagedArtifactRemovalState {
    ManagedArtifactRemovalState::Uncertain
}

fn scan_managed_event_files(
    managed: &LockedJob,
    local_job_id: &LocalJobId,
) -> Result<Vec<ManagedEventEntry>, JobStoreError> {
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in fs::read_dir(&managed.revisions)
        .map_err(|source| io_error("read managed event directory", source))?
    {
        if entries.len() >= MAX_MANAGED_EVENTS_PER_JOB {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event records",
                maximum: MAX_MANAGED_EVENTS_PER_JOB as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read managed event entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "managed event filename is not UTF-8",
            })?;
        if is_revision_staging_name(&name) {
            return Err(JobStoreError::RecoveryRequired {
                reason: "managed event publication staging requires writable recovery",
            });
        }
        let (sequence, sha256) = parse_managed_event_filename(&name)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect managed event entry", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JobStoreError::MalformedLayout {
                reason: "managed event entry is linked or not a regular file",
            });
        }
        if metadata.len() > MAX_MANAGED_EVENT_BYTES {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event bytes",
                maximum: MAX_MANAGED_EVENT_BYTES,
            });
        }
        total_bytes =
            total_bytes
                .checked_add(metadata.len())
                .ok_or(JobStoreError::BoundExceeded {
                    kind: "managed event bytes",
                    maximum: MAX_MANAGED_EVENT_TOTAL_BYTES,
                })?;
        if total_bytes > MAX_MANAGED_EVENT_TOTAL_BYTES {
            return Err(JobStoreError::BoundExceeded {
                kind: "managed event bytes",
                maximum: MAX_MANAGED_EVENT_TOTAL_BYTES,
            });
        }
        entries.push(ManagedEventEntry {
            sequence,
            sha256,
            path: entry.path(),
            bytes: metadata.len(),
        });
    }
    entries.sort_by_key(|entry| entry.sequence);
    for (index, entry) in entries.iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if entry.sequence != expected {
            return Err(JobStoreError::MalformedLayout {
                reason: "managed event sequences are duplicated or non-contiguous",
            });
        }
        drop(read_managed_event(entry, local_job_id)?);
    }
    Ok(entries)
}

fn read_managed_event(
    entry: &ManagedEventEntry,
    local_job_id: &LocalJobId,
) -> Result<ManagedJobEventV1, JobStoreError> {
    let mut file = open_private_revision_file(&entry.path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MANAGED_EVENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read managed event", source))?;
    verify_open_private_revision_file(&file, &entry.path)?;
    if bytes.len() as u64 > MAX_MANAGED_EVENT_BYTES || sha256_hex(&bytes) != entry.sha256 {
        return Err(JobStoreError::MalformedRevision {
            reason: "managed event bytes differ from the filename digest",
        });
    }
    let event: ManagedJobEventV1 =
        serde_json::from_slice(&bytes).map_err(|_| JobStoreError::MalformedRevision {
            reason: "managed event is not canonical v1 JSON",
        })?;
    let canonical = event.validate_for(local_job_id)?;
    if canonical != bytes || event.sequence != entry.sequence {
        return Err(JobStoreError::MalformedRevision {
            reason: "managed event bytes are not their canonical owner-bound encoding",
        });
    }
    Ok(event)
}

fn managed_event_filename(sequence: u64, sha256: &str) -> String {
    format!("{sequence:0REVISION_DIGITS$}-{sha256}.json")
}

#[cfg(test)]
fn managed_event_publication_checkpoint(final_path: &Path) -> Result<(), JobStoreError> {
    let should_fail = {
        let mut control = MANAGED_EVENT_PUBLICATION_TEST_CONTROL
            .lock()
            .expect("managed-event publication test-control lock is not poisoned");
        control.as_ref().is_some_and(|path| path == final_path) && control.take().is_some()
    };
    if should_fail {
        return Err(JobStoreError::CommitUncertain {
            reason: "injected managed-event batch publication uncertainty",
        });
    }
    Ok(())
}

fn parse_managed_event_filename(name: &str) -> Result<(u64, String), JobStoreError> {
    let stem = name
        .strip_suffix(".json")
        .ok_or(JobStoreError::MalformedLayout {
            reason: "managed event filename has an unexpected extension",
        })?;
    let (sequence, sha256) = stem.split_once('-').ok_or(JobStoreError::MalformedLayout {
        reason: "managed event filename is malformed",
    })?;
    if sequence.len() != REVISION_DIGITS
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || !is_sha256(sha256)
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "managed event filename is malformed",
        });
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| JobStoreError::MalformedLayout {
            reason: "managed event sequence is outside the supported range",
        })?;
    if sequence == 0 {
        return Err(JobStoreError::MalformedLayout {
            reason: "managed event sequence must start at one",
        });
    }
    Ok((sequence, sha256.to_owned()))
}

fn validate_managed_event_message(message: &str) -> Result<(), JobStoreError> {
    validate_safe_text("managed_event.message", message)?;
    if message.is_empty() || message.contains(['\r', '\n']) || message.chars().any(char::is_control)
    {
        return Err(invalid_record(
            "managed event message must be one non-empty printable line",
        ));
    }
    let lowercase = message.to_ascii_lowercase();
    let secret_marker = [
        "authorization:",
        "authorization =",
        "bearer ",
        "basic ",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "-----begin ",
        "password=",
        "password:",
        "client_secret",
        "access_token",
        "refresh_token",
        "private_key",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker));
    let credential_url = lowercase.contains("://")
        && lowercase.split_once("://").is_some_and(|(_, authority)| {
            authority.split('/').next().is_some_and(|v| v.contains('@'))
        });
    if secret_marker || credential_url || path_contains_query_marker(message) {
        return Err(invalid_record(
            "managed event message resembles credentials or an unredacted URL",
        ));
    }
    Ok(())
}

fn encode_bounded_json<T: Serialize>(
    kind: &'static str,
    value: &T,
    maximum: u64,
    operation: &'static str,
) -> Result<Vec<u8>, JobStoreError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|source| JobStoreError::Serialization { operation, source })?;
    bytes.push(b'\n');
    if bytes.len() as u64 > maximum {
        return Err(JobStoreError::BoundExceeded { kind, maximum });
    }
    Ok(bytes)
}

fn publish_managed_bytes(
    directory: &LockedJob,
    final_path: &Path,
    bytes: &[u8],
    maximum: u64,
) -> Result<bool, JobStoreError> {
    match fs::symlink_metadata(final_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum
            {
                return Err(JobStoreError::MalformedLayout {
                    reason: "managed immutable destination is linked or malformed",
                });
            }
            let mut file = open_private_revision_file_for_sync(final_path)?;
            let mut actual = Vec::new();
            (&mut file)
                .take(maximum.saturating_add(1))
                .read_to_end(&mut actual)
                .map_err(|source| io_error("read existing managed immutable file", source))?;
            verify_open_private_revision_file(&file, final_path)?;
            if actual != bytes {
                return Err(JobStoreError::CommitUncertain {
                    reason: "managed immutable destination contains different bytes",
                });
            }
            file.sync_all()
                .map_err(|_| JobStoreError::CommitUncertain {
                    reason: "managed immutable destination could not be flushed",
                })?;
            sync_directory(&directory.revisions, &directory.revisions_guard)?;
            Ok(true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            match publish_create_only(directory, final_path, bytes) {
                Ok(()) => Ok(false),
                Err(failure) => {
                    let original = failure.error;
                    drop(failure.retained_file);
                    if fs::symlink_metadata(final_path).is_ok() {
                        match publish_managed_bytes(directory, final_path, bytes, maximum) {
                            Ok(_) => Ok(true),
                            Err(_) => Err(original),
                        }
                    } else {
                        Err(original)
                    }
                }
            }
        }
        Err(source) => Err(io_error("inspect managed immutable destination", source)),
    }
}

fn recover_managed_staging(directory: &LockedJob) -> Result<(), JobStoreError> {
    let staging = revision_staging_paths(&directory.revisions)?;
    for path in staging {
        recover_one_managed_staging(directory, &path)?;
    }
    sync_directory(&directory.revisions, &directory.revisions_guard)
}

#[cfg(windows)]
fn recover_one_managed_staging(_directory: &LockedJob, path: &Path) -> Result<(), JobStoreError> {
    use rustferry_core::windows_private_directory::{
        open_private_file_for_removal, remove_private_file_handle,
    };

    let file = open_private_file_for_removal(path)
        .map_err(|error| windows_security_error("open managed staging for recovery", &error))?;
    remove_private_file_handle(file)
        .map_err(|error| windows_security_error("remove managed staging by handle", &error))
}

pub(super) fn admin_store_entry_is_reserved(name: &str) -> bool {
    matches!(
        name,
        ADMIN_LOCK_FILE
            | ADMIN_TRANSACTIONS_DIRECTORY
            | TOMBSTONES_DIRECTORY
            | OPERATION_RESERVATIONS_DIRECTORY
    )
}

pub(super) fn validate_admin_store_entry(
    name: &str,
    metadata: &fs::Metadata,
) -> Result<(), JobStoreError> {
    let valid = match name {
        ADMIN_LOCK_FILE => metadata.is_file(),
        ADMIN_TRANSACTIONS_DIRECTORY | TOMBSTONES_DIRECTORY | OPERATION_RESERVATIONS_DIRECTORY => {
            metadata.is_dir()
        }
        _ => false,
    };
    if metadata.file_type().is_symlink() || !valid {
        return Err(JobStoreError::MalformedLayout {
            reason: "administrative store entry is linked or has the wrong type",
        });
    }
    Ok(())
}

fn open_pending_transaction_directory(
    store: &JobStore,
) -> Result<Option<(File, PathBuf)>, JobStoreError> {
    let transactions = store.version_root().join(ADMIN_TRANSACTIONS_DIRECTORY);
    let Some(guard) = open_private_directory_if_present(
        &transactions,
        "admin transactions entry is linked or not a directory",
    )?
    else {
        return Ok(None);
    };
    Ok(Some((guard, transactions)))
}

pub(super) fn reject_pending_admin_transactions(store: &JobStore) -> Result<(), JobStoreError> {
    let Some((_guard, transactions)) = open_pending_transaction_directory(store)? else {
        return Ok(());
    };
    if scan_pending_transaction_paths(&transactions)?.is_empty() {
        Ok(())
    } else {
        Err(JobStoreError::RecoveryRequired {
            reason: "an administrative job-store transaction is incomplete",
        })
    }
}

pub(super) fn reject_pending_transaction_for_job(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), JobStoreError> {
    let Some((_guard, transactions)) = open_pending_transaction_directory(store)? else {
        return Ok(());
    };
    for path in scan_pending_transaction_paths(&transactions)? {
        let (_, transaction) = read_admin_transaction(&path)?;
        let owns_job = match transaction {
            AdminTransactionV1::Retry(transaction) => {
                transaction.parent_next.local_job_id == *local_job_id
                    || transaction.child.local_job_id == *local_job_id
            }
            AdminTransactionV1::PruneRelease(authorization) => authorization
                .plan
                .candidates
                .iter()
                .any(|candidate| candidate.local_job_id == *local_job_id),
            AdminTransactionV1::Prune(transaction) => transaction
                .plan
                .candidates
                .iter()
                .any(|candidate| candidate.local_job_id == *local_job_id),
        };
        if owns_job {
            return Err(JobStoreError::RecoveryRequired {
                reason: "the job participates in an incomplete administrative transaction",
            });
        }
    }
    Ok(())
}

fn reject_active_prune_release_for_job(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), JobStoreError> {
    let Some((_guard, transactions)) = open_pending_transaction_directory(store)? else {
        return Ok(());
    };
    if scan_active_prune_release_authorizations(&transactions)?
        .iter()
        .any(|(_, authorization)| {
            authorization
                .plan
                .candidates
                .iter()
                .any(|candidate| candidate.local_job_id == *local_job_id)
        })
    {
        return Err(JobStoreError::RecoveryRequired {
            reason: "the job belongs to a durable prune release authorization",
        });
    }
    Ok(())
}

pub(super) fn recover_pending_admin_transactions(store: &JobStore) -> Result<(), JobStoreError> {
    if open_pending_transaction_directory(store)?.is_none() {
        return Ok(());
    }
    let layout = ensure_admin_layout(store)?;
    let transaction_directory = admin_transaction_locked_directory(&layout)?;
    recover_managed_staging(&transaction_directory)?;
    for path in scan_pending_transaction_paths(&layout.transactions)? {
        let (sha256, transaction) = read_admin_transaction(&path)?;
        match transaction {
            AdminTransactionV1::Retry(transaction) => {
                finish_retry_transaction(store, &layout, &sha256, &transaction)?;
                publish_admin_completion(&layout, "retry", &sha256)?;
            }
            AdminTransactionV1::PruneRelease(_) => {
                publish_admin_completion(&layout, "release", &sha256)?;
            }
            AdminTransactionV1::Prune(transaction) => {
                finish_prune_transaction(store, &layout, &sha256, &transaction)?;
                publish_admin_completion(&layout, "prune", &sha256)?;
            }
        }
    }
    reconcile_consumed_prune_release_authorizations(store, &layout)?;
    Ok(())
}

fn ensure_admin_layout(store: &JobStore) -> Result<AdminLayout, JobStoreError> {
    store.ensure_writable()?;
    drop(store.ensure_store_layout()?);
    let version_root = store.version_root();
    let transactions = version_root.join(ADMIN_TRANSACTIONS_DIRECTORY);
    let tombstones = version_root.join(TOMBSTONES_DIRECTORY);
    drop(ensure_private_directory(&transactions)?);
    drop(ensure_private_directory(&tombstones)?);
    let lock_path = version_root.join(ADMIN_LOCK_FILE);
    let lock = match open_existing_private_lock(&lock_path)? {
        Some(lock) => lock,
        None => open_or_create_private_lock(&lock_path)?,
    };
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| JobStoreError::RecoveryRequired {
        reason: "another process is recovering or mutating administrative job-store state",
    })?;
    let lock = HeldFileLock::new(lock);
    let store_layout =
        store
            .open_existing_store_layout()?
            .ok_or(JobStoreError::MalformedLayout {
                reason: "administrative store layout disappeared after locking",
            })?;
    verify_private_lock_identity(&lock, &lock_path)?;
    let transactions_guard = open_private_directory_if_present(
        &transactions,
        "admin transactions entry is linked or not a directory",
    )?
    .ok_or(JobStoreError::MalformedLayout {
        reason: "admin transactions directory disappeared after locking",
    })?;
    let tombstones_guard = open_private_directory_if_present(
        &tombstones,
        "admin tombstones entry is linked or not a directory",
    )?
    .ok_or(JobStoreError::MalformedLayout {
        reason: "admin tombstones directory disappeared after locking",
    })?;
    lock.sync_all()
        .map_err(|source| io_error("sync administrative store lock", source))?;
    sync_directory(&transactions, &transactions_guard)?;
    sync_directory(&tombstones, &tombstones_guard)?;
    let version_guard = store_layout
        .guards
        .last()
        .ok_or(JobStoreError::MalformedLayout {
            reason: "administrative store omitted the version-root guard",
        })?;
    sync_directory(&version_root, version_guard)?;
    Ok(AdminLayout {
        _guards: store_layout.guards,
        transactions_guard,
        transactions,
        tombstones_guard,
        tombstones,
        lock,
    })
}

fn admin_transaction_locked_directory(layout: &AdminLayout) -> Result<LockedJob, JobStoreError> {
    Ok(LockedJob {
        lock: layout.lock.clone(),
        guards: Vec::new(),
        revisions_guard: layout
            .transactions_guard
            .try_clone()
            .map_err(|source| io_error("clone transaction directory guard", source))?,
        revisions: layout.transactions.clone(),
    })
}

fn admin_tombstone_locked_directory(layout: &AdminLayout) -> Result<LockedJob, JobStoreError> {
    Ok(LockedJob {
        lock: layout.lock.clone(),
        guards: Vec::new(),
        revisions_guard: layout
            .tombstones_guard
            .try_clone()
            .map_err(|source| io_error("clone tombstone directory guard", source))?,
        revisions: layout.tombstones.clone(),
    })
}

fn consumed_operation_locked_directory(
    store: &JobStore,
    layout: &AdminLayout,
) -> Result<LockedJob, JobStoreError> {
    let reservations = store.version_root().join(OPERATION_RESERVATIONS_DIRECTORY);
    let reservations_guard = ensure_private_directory(&reservations)?;
    Ok(LockedJob {
        lock: layout.lock.clone(),
        guards: Vec::new(),
        revisions_guard: reservations_guard,
        revisions: reservations,
    })
}

fn scan_pending_transaction_paths(directory: &Path) -> Result<Vec<PathBuf>, JobStoreError> {
    let mut pending = BTreeMap::new();
    let mut completed = BTreeSet::new();
    let mut consumed = BTreeSet::new();
    let mut count = 0_usize;
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("read admin transactions", source))?
    {
        count = count.saturating_add(1);
        if count > MAX_ADMIN_TRANSACTION_FILES {
            return Err(JobStoreError::BoundExceeded {
                kind: "administrative transactions",
                maximum: MAX_ADMIN_TRANSACTION_FILES as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read admin transaction entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "administrative transaction filename is not UTF-8",
            })?;
        if is_revision_staging_name(&name) {
            return Err(JobStoreError::RecoveryRequired {
                reason: "administrative transaction staging requires writable recovery",
            });
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect admin transaction entry", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JobStoreError::MalformedLayout {
                reason: "administrative transaction entry is linked or not a regular file",
            });
        }
        if let Some(stem) = name.strip_suffix(".json") {
            let sha256 = parse_transaction_stem(stem)?;
            pending.insert(sha256, entry.path());
        } else if let Some(stem) = name.strip_suffix(".done") {
            let sha256 = parse_transaction_stem(stem)?;
            let bytes = read_private_bounded_file(&entry.path(), SHA256_HEX_BYTES as u64 + 1)?;
            if bytes != format!("{sha256}\n").as_bytes() {
                return Err(JobStoreError::MalformedRevision {
                    reason: "administrative completion receipt is malformed",
                });
            }
            completed.insert(sha256);
        } else if let Some(stem) = name.strip_suffix(".used") {
            let Some(sha256) = stem.strip_prefix("release-") else {
                return Err(JobStoreError::MalformedLayout {
                    reason: "administrative consumption filename is malformed",
                });
            };
            if !is_sha256(sha256) {
                return Err(JobStoreError::MalformedLayout {
                    reason: "administrative consumption filename is malformed",
                });
            }
            let bytes = read_private_bounded_file(&entry.path(), SHA256_HEX_BYTES as u64 + 1)?;
            if bytes != format!("{sha256}\n").as_bytes() {
                return Err(JobStoreError::MalformedRevision {
                    reason: "administrative consumption receipt is malformed",
                });
            }
            consumed.insert(sha256.to_owned());
        } else {
            return Err(JobStoreError::MalformedLayout {
                reason: "administrative transaction filename is malformed",
            });
        }
    }
    for complete in &completed {
        if !pending.contains_key(complete) {
            return Err(JobStoreError::MalformedLayout {
                reason: "administrative completion receipt lacks its immutable transaction",
            });
        }
    }
    for consumed_sha256 in &consumed {
        if !pending.contains_key(consumed_sha256) || !completed.contains(consumed_sha256) {
            return Err(JobStoreError::MalformedLayout {
                reason: "administrative consumption receipt lacks its completed authorization",
            });
        }
    }
    Ok(pending
        .into_iter()
        .filter_map(|(sha256, path)| {
            (!completed.contains(&sha256) && !consumed.contains(&sha256)).then_some(path)
        })
        .collect())
}

fn parse_transaction_stem(stem: &str) -> Result<String, JobStoreError> {
    let Some((kind, sha256)) = stem.split_once('-') else {
        return Err(JobStoreError::MalformedLayout {
            reason: "administrative transaction filename is malformed",
        });
    };
    if !matches!(kind, "retry" | "release" | "prune") || !is_sha256(sha256) {
        return Err(JobStoreError::MalformedLayout {
            reason: "administrative transaction filename is malformed",
        });
    }
    Ok(sha256.to_owned())
}

fn scan_active_prune_release_authorizations(
    transactions: &Path,
) -> Result<Vec<(String, PruneReleaseAuthorizationV1)>, JobStoreError> {
    if !scan_pending_transaction_paths(transactions)?.is_empty() {
        return Err(JobStoreError::RecoveryRequired {
            reason: "an administrative job-store transaction is incomplete",
        });
    }
    let mut authorizations = Vec::new();
    for entry in fs::read_dir(transactions)
        .map_err(|source| io_error("read prune release authorizations", source))?
    {
        let path = entry
            .map_err(|source| io_error("read prune release authorization entry", source))?
            .path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            return Err(JobStoreError::MalformedLayout {
                reason: "prune release authorization filename is not UTF-8",
            });
        };
        if !name.starts_with("release-") || Path::new(name).extension() != Some(OsStr::new("json"))
        {
            continue;
        }
        let (sha256, transaction) = read_admin_transaction(&path)?;
        let AdminTransactionV1::PruneRelease(authorization) = transaction else {
            return Err(JobStoreError::MalformedRevision {
                reason: "release authorization filename contains another transaction kind",
            });
        };
        let used = transactions.join(format!("release-{sha256}.used"));
        match fs::symlink_metadata(&used) {
            Ok(_) => continue,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect prune release consumption", source)),
        }
        authorizations.push((sha256, authorization));
    }
    authorizations.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(authorizations)
}

fn read_admin_transaction(path: &Path) -> Result<(String, AdminTransactionV1), JobStoreError> {
    let name = path
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or(JobStoreError::MalformedLayout {
            reason: "administrative transaction filename is malformed",
        })?;
    let sha256 = parse_transaction_stem(name)?;
    let maximum = MAX_JOB_REVISION_BYTES
        .saturating_mul(2)
        .saturating_add(1024 * 1024);
    let bytes = read_private_bounded_file(path, maximum)?;
    if sha256_hex(&bytes) != sha256 {
        return Err(JobStoreError::MalformedRevision {
            reason: "administrative transaction differs from its filename digest",
        });
    }
    let transaction: AdminTransactionV1 =
        serde_json::from_slice(&bytes).map_err(|_| JobStoreError::MalformedRevision {
            reason: "administrative transaction is not canonical v1 JSON",
        })?;
    let canonical = encode_bounded_json(
        "administrative transaction bytes",
        &transaction,
        maximum,
        "encode administrative transaction",
    )?;
    if canonical != bytes {
        return Err(JobStoreError::MalformedRevision {
            reason: "administrative transaction bytes are not canonical",
        });
    }
    validate_admin_transaction(&transaction)?;
    Ok((sha256, transaction))
}

fn validate_admin_transaction(transaction: &AdminTransactionV1) -> Result<(), JobStoreError> {
    match transaction {
        AdminTransactionV1::Retry(transaction) => {
            if transaction.schema_version != ADMIN_TRANSACTION_SCHEMA_VERSION {
                return Err(invalid_record("retry transaction schema is unsupported"));
            }
            transaction.parent_next.validate()?;
            transaction.child.validate()?;
            validate_retry_transaction_shape(transaction)
        }
        AdminTransactionV1::PruneRelease(authorization) => {
            if authorization.schema_version != ADMIN_TRANSACTION_SCHEMA_VERSION
                || authorization.plan.selection_max_jobs == 0
                || authorization.plan.candidates.is_empty()
            {
                return Err(invalid_record(
                    "prune release authorization shape is invalid",
                ));
            }
            validate_prune_plan_shape(&authorization.plan)
        }
        AdminTransactionV1::Prune(transaction) => {
            if transaction.schema_version != ADMIN_TRANSACTION_SCHEMA_VERSION
                || transaction.plan.candidates.is_empty()
                || transaction.plan.candidates.len() > MAX_PRUNE_JOBS
            {
                return Err(invalid_record("prune transaction shape is invalid"));
            }
            validate_prune_plan_shape(&transaction.plan)
        }
    }
}

fn publish_admin_transaction(
    layout: &AdminLayout,
    transaction: &AdminTransactionV1,
) -> Result<(String, bool), JobStoreError> {
    validate_admin_transaction(transaction)?;
    let maximum = MAX_JOB_REVISION_BYTES
        .saturating_mul(2)
        .saturating_add(1024 * 1024);
    let bytes = encode_bounded_json(
        "administrative transaction bytes",
        transaction,
        maximum,
        "encode administrative transaction",
    )?;
    let sha256 = sha256_hex(&bytes);
    let kind = match transaction {
        AdminTransactionV1::Retry(_) => "retry",
        AdminTransactionV1::PruneRelease(_) => "release",
        AdminTransactionV1::Prune(_) => "prune",
    };
    let path = layout.transactions.join(format!("{kind}-{sha256}.json"));
    ensure_admin_transaction_capacity(layout, &path, 2)?;
    let directory = admin_transaction_locked_directory(layout)?;
    let already_present = publish_managed_bytes(&directory, &path, &bytes, maximum)?;
    Ok((sha256, already_present))
}

fn publish_admin_completion(
    layout: &AdminLayout,
    kind: &str,
    sha256: &str,
) -> Result<bool, JobStoreError> {
    let bytes = format!("{sha256}\n").into_bytes();
    let path = layout.transactions.join(format!("{kind}-{sha256}.done"));
    ensure_admin_transaction_capacity(layout, &path, 1)?;
    let directory = admin_transaction_locked_directory(layout)?;
    publish_managed_bytes(&directory, &path, &bytes, SHA256_HEX_BYTES as u64 + 1)
}

fn publish_prune_release_consumed(
    layout: &AdminLayout,
    authorization_sha256: &str,
) -> Result<bool, JobStoreError> {
    validate_sha256("prune_release.authorization_sha256", authorization_sha256)?;
    let bytes = format!("{authorization_sha256}\n").into_bytes();
    let path = layout
        .transactions
        .join(format!("release-{authorization_sha256}.used"));
    ensure_admin_transaction_capacity(layout, &path, 1)?;
    let directory = admin_transaction_locked_directory(layout)?;
    publish_managed_bytes(&directory, &path, &bytes, SHA256_HEX_BYTES as u64 + 1)
}

fn ensure_admin_transaction_capacity(
    layout: &AdminLayout,
    path: &Path,
    additional_if_absent: usize,
) -> Result<(), JobStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspect administrative publication", source)),
    }
    let mut count = 0_usize;
    for entry in fs::read_dir(&layout.transactions)
        .map_err(|source| io_error("count administrative transactions", source))?
    {
        entry.map_err(|source| io_error("count administrative transaction entry", source))?;
        count = count.saturating_add(1);
        if count.saturating_add(additional_if_absent) > MAX_ADMIN_TRANSACTION_FILES {
            return Err(JobStoreError::BoundExceeded {
                kind: "administrative transactions",
                maximum: MAX_ADMIN_TRANSACTION_FILES as u64,
            });
        }
    }
    Ok(())
}

fn read_private_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, JobStoreError> {
    let mut file = open_private_revision_file(path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read private managed file", source))?;
    verify_open_private_revision_file(&file, path)?;
    if bytes.len() as u64 > maximum {
        return Err(JobStoreError::BoundExceeded {
            kind: "private managed file bytes",
            maximum,
        });
    }
    Ok(bytes)
}

impl JobStore {
    /// Atomically create a retry child and append the reciprocal parent lineage revision.
    ///
    /// A durable transaction precedes either revision. Recovery completes both sides, and every
    /// normal read fails closed while an incomplete transaction names that job.
    ///
    /// # Errors
    ///
    /// Returns a typed eligibility, identity, lock, conflict, publication, or storage error.
    #[allow(
        clippy::too_many_lines,
        reason = "retry validation, durable intent, and reciprocal publication stay under the same ordered job locks"
    )]
    pub fn create_retry_lineage(
        &self,
        parent_job_id: &LocalJobId,
        parent_retry_lease: &JobOperationLease,
        child: &StoredJobV1,
        options: &RetryLineageOptionsV1,
    ) -> Result<RetryLineageReceipt, JobStoreError> {
        let (receipt, operation_lease) = self.create_retry_lineage_inner(
            parent_job_id,
            parent_retry_lease,
            None,
            child,
            options,
        )?;
        debug_assert!(operation_lease.is_none());
        Ok(receipt)
    }

    /// Atomically create retry lineage from a vacant snapshot operation and retain child Build
    /// authority before either job lock or the vacancy is released.
    ///
    /// # Errors
    ///
    /// Returns a typed eligibility, vacancy, identity, lock, conflict, or storage error.
    pub fn create_retry_lineage_with_operation_lease(
        &self,
        parent_job_id: &LocalJobId,
        parent_retry_lease: &JobOperationLease,
        vacancy: VacantSnapshotOperationLease,
        child: &StoredJobV1,
        options: &RetryLineageOptionsV1,
    ) -> Result<LeasedRetryLineageReceipt, JobStoreError> {
        let (lineage, operation_lease) = self.create_retry_lineage_inner(
            parent_job_id,
            parent_retry_lease,
            Some(vacancy),
            child,
            options,
        )?;
        let operation_lease = operation_lease.ok_or_else(|| {
            invalid_record("vacant retry child publication omitted its Build lease")
        })?;
        Ok(LeasedRetryLineageReceipt {
            lineage,
            operation_lease,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one ordered durability protocol keeps lease validation, publication, and recovery auditable"
    )]
    fn create_retry_lineage_inner(
        &self,
        parent_job_id: &LocalJobId,
        parent_retry_lease: &JobOperationLease,
        vacancy: Option<VacantSnapshotOperationLease>,
        child: &StoredJobV1,
        options: &RetryLineageOptionsV1,
    ) -> Result<(RetryLineageReceipt, Option<JobOperationLease>), JobStoreError> {
        self.ensure_writable()?;
        if parent_job_id == &child.local_job_id {
            return Err(invalid_record("retry parent and child must differ"));
        }
        reject_tombstoned_local_job_id(self, &child.local_job_id)?;

        // Prove the caller's live parent authority before creating or recovering any child or
        // administrative layout. The later ordered-lock validation closes the re-lock window.
        reject_pending_transaction_for_job(self, parent_job_id)?;
        let parent_probe = self.lock_job_unchecked(parent_job_id, false)?;
        recover_revision_staging(&parent_probe)?;
        parent_retry_lease.validate_owner(
            self,
            &parent_probe,
            parent_job_id,
            JobOperationKind::Retry,
        )?;
        drop(latest_locked(&parent_probe, parent_job_id)?);
        drop(parent_probe);

        let supplied_vacancy = vacancy.is_some();
        let operation_reservation = match vacancy {
            Some(vacancy) => vacancy,
            None => acquire_snapshot_operation_reservation(self, &child.operation_id)?,
        };
        operation_reservation.validate_owner(self, &child.operation_id)?;
        if let Some((local_job_id, _)) = scan_snapshot_operation_owner(self, &child.operation_id)?
            && (supplied_vacancy || local_job_id != child.local_job_id)
        {
            return Err(invalid_record(
                "retry operation already belongs to another durable job",
            ));
        }
        reject_consumed_snapshot_operation_while_reserved(self, &child.operation_id)?;
        let layout = ensure_admin_layout(self)?;
        recover_pending_transactions_locked(self, &layout)?;

        let mut identifiers = vec![parent_job_id.clone(), child.local_job_id.clone()];
        identifiers.sort();
        identifiers.dedup();
        debug_assert_eq!(identifiers.len(), 2);
        let mut locked = BTreeMap::new();
        for identifier in &identifiers {
            let create_layout = identifier == &child.local_job_id;
            let job = self.lock_job(identifier, create_layout)?;
            recover_revision_staging(&job)?;
            locked.insert(identifier.clone(), job);
        }
        let parent_locked = locked
            .get(parent_job_id)
            .ok_or_else(|| invalid_record("retry parent lock is missing"))?;
        parent_retry_lease.validate_owner(
            self,
            parent_locked,
            parent_job_id,
            JobOperationKind::Retry,
        )?;
        let parent_before = latest_locked(parent_locked, parent_job_id)?;
        let parent_before_entry = scan_revision_files(&parent_locked.revisions)?
            .pop()
            .ok_or_else(|| JobStoreError::JobNotFound {
                local_job_id: parent_job_id.clone(),
            })?;

        let child_locked = locked
            .get(&child.local_job_id)
            .ok_or_else(|| invalid_record("retry child lock is missing"))?;
        let child_revisions = scan_revision_files(&child_locked.revisions)?;
        if let Some(existing_entry) = child_revisions.last() {
            if supplied_vacancy {
                return Err(invalid_record(
                    "vacant snapshot operation unexpectedly has an existing retry child",
                ));
            }
            let existing = read_job_revision(
                &existing_entry.path,
                existing_entry.revision,
                &existing_entry.sha256,
                &child.local_job_id,
            )?;
            let (authorization_sha256, completed) =
                find_retry_transaction_for_child(&layout, parent_job_id, &child.local_job_id)?
                    .ok_or(JobStoreError::RecoveryRequired {
                        reason: "retry lineage exists without its immutable transaction journal",
                    })?;
            let expected_child_sha256 = sha256_hex(&encode_revision_v2(&completed.child, None)?);
            if existing != *child
                || existing_entry.sha256 != expected_child_sha256
                || completed.child != *child
                || completed.options != *options
                || !parent_before
                    .retry_lineage
                    .child_job_ids
                    .contains(&child.local_job_id)
            {
                return Err(JobStoreError::RevisionConflict {
                    expected: existing_entry.revision.saturating_add(1),
                    found: child.revision,
                });
            }
            let expected_parent_bytes = encode_revision_v2(
                &completed.parent_next,
                Some(&completed.parent_before_sha256),
            )?;
            let expected_parent_sha256 = sha256_hex(&expected_parent_bytes);
            let parent_entry = scan_revision_files(&parent_locked.revisions)?
                .into_iter()
                .find(|entry| {
                    entry.revision == completed.parent_next.revision
                        && entry.sha256 == expected_parent_sha256
                })
                .ok_or(JobStoreError::RecoveryRequired {
                    reason: "retry parent journal revision is missing",
                })?;
            return Ok((
                RetryLineageReceipt {
                    parent: RevisionReceipt {
                        local_job_id: parent_job_id.clone(),
                        revision: parent_entry.revision,
                        sha256: parent_entry.sha256,
                        already_present: true,
                    },
                    child: RevisionReceipt {
                        local_job_id: child.local_job_id.clone(),
                        revision: existing_entry.revision,
                        sha256: existing_entry.sha256.clone(),
                        already_present: true,
                    },
                    binding: retry_lineage_binding_from_transaction(
                        &authorization_sha256,
                        &completed,
                    ),
                },
                None,
            ));
        }

        reject_consumed_snapshot_operation_while_reserved(self, &child.operation_id)?;

        let parent_next = build_retry_parent_successor(&parent_before, child, options)?;
        let transaction = RetryTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            parent_before_revision: parent_before.revision,
            parent_before_sha256: parent_before_entry.sha256,
            parent_next,
            child: child.clone(),
            options: options.clone(),
        };
        validate_retry_transaction_against_parent(&parent_before, &transaction)?;
        let transaction_value = AdminTransactionV1::Retry(Box::new(transaction.clone()));
        let (transaction_sha256, _) = publish_admin_transaction(&layout, &transaction_value)?;
        let receipt = finish_retry_transaction_with_locks(
            &layout,
            &transaction_sha256,
            &transaction,
            &locked,
        )?;
        let operation_lease = if supplied_vacancy {
            let child_locked = locked
                .remove(&child.local_job_id)
                .ok_or_else(|| invalid_record("retry child lock is missing after publication"))?;
            Some(acquire_operation_lease_from_locked(
                self,
                &child.local_job_id,
                JobOperationKind::Build,
                child_locked,
            )?)
        } else {
            None
        };
        publish_admin_completion(&layout, "retry", &transaction_sha256)?;
        drop(operation_reservation);
        Ok((receipt, operation_lease))
    }

    /// Recover the immutable authorization and policy for one active retry edge.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found, recovery, lineage, revision, or storage error.
    pub fn retry_lineage_binding(
        &self,
        parent_job_id: &LocalJobId,
        child_job_id: &LocalJobId,
    ) -> Result<RetryLineageBindingV1, JobStoreError> {
        reject_pending_transaction_for_job(self, parent_job_id)?;
        reject_pending_transaction_for_job(self, child_job_id)?;
        let Some((_guard, transactions)) = open_pending_transaction_directory(self)? else {
            return Err(JobStoreError::RecoveryRequired {
                reason: "retry lineage has no immutable transaction journal",
            });
        };
        let (authorization_sha256, transaction) = find_retry_transaction_for_child_in_directory(
            &transactions,
            parent_job_id,
            child_job_id,
        )?
        .ok_or(JobStoreError::RecoveryRequired {
            reason: "retry lineage has no immutable transaction journal",
        })?;
        validate_retry_transaction_shape(&transaction)?;
        let parent_next = self.revision(parent_job_id, transaction.parent_next.revision)?;
        let child_initial = self.revision(child_job_id, transaction.child.revision)?;
        let parent_latest = self.latest(parent_job_id)?;
        let child_latest = self.latest(child_job_id)?;
        if parent_next != transaction.parent_next
            || child_initial != transaction.child
            || !parent_latest
                .retry_lineage
                .child_job_ids
                .contains(child_job_id)
            || child_latest.retry_lineage.parent_job_id.as_ref() != Some(parent_job_id)
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "retry lineage differs from its immutable transaction journal",
            });
        }
        Ok(retry_lineage_binding_from_transaction(
            &authorization_sha256,
            &transaction,
        ))
    }
}

fn find_retry_transaction_for_child(
    layout: &AdminLayout,
    parent_job_id: &LocalJobId,
    child_job_id: &LocalJobId,
) -> Result<Option<(String, RetryTransactionV1)>, JobStoreError> {
    find_retry_transaction_for_child_in_directory(&layout.transactions, parent_job_id, child_job_id)
}

fn find_retry_transaction_for_child_in_directory(
    transactions: &Path,
    parent_job_id: &LocalJobId,
    child_job_id: &LocalJobId,
) -> Result<Option<(String, RetryTransactionV1)>, JobStoreError> {
    let mut found = None;
    for entry in fs::read_dir(transactions)
        .map_err(|source| io_error("read retry transaction journal", source))?
    {
        let path = entry
            .map_err(|source| io_error("read retry transaction entry", source))?
            .path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let (authorization_sha256, transaction) = read_admin_transaction(&path)?;
        let AdminTransactionV1::Retry(transaction) = transaction else {
            continue;
        };
        if transaction.parent_next.local_job_id == *parent_job_id
            && transaction.child.local_job_id == *child_job_id
            && found
                .replace((authorization_sha256, *transaction))
                .is_some()
        {
            return Err(JobStoreError::MalformedLayout {
                reason: "retry child has multiple immutable transaction journals",
            });
        }
    }
    Ok(found)
}

fn retry_lineage_binding_from_transaction(
    authorization_sha256: &str,
    transaction: &RetryTransactionV1,
) -> RetryLineageBindingV1 {
    RetryLineageBindingV1 {
        authorization_sha256: authorization_sha256.to_owned(),
        parent_before_revision: transaction.parent_before_revision,
        parent_next_revision: transaction.parent_next.revision,
        child_job_id: transaction.child.local_job_id.clone(),
        child_operation_id: transaction.child.operation_id.clone(),
        options: transaction.options.clone(),
    }
}

fn build_retry_parent_successor(
    parent: &StoredJobV1,
    child: &StoredJobV1,
    options: &RetryLineageOptionsV1,
) -> Result<StoredJobV1, JobStoreError> {
    validate_retry_child(parent, child, options)?;
    if parent
        .retry_lineage
        .child_job_ids
        .contains(&child.local_job_id)
    {
        return Err(invalid_record("retry child is already named by the parent"));
    }
    let mut next = parent.clone();
    next.revision = parent.revision.saturating_add(1);
    next.updated_at_ms = parent.updated_at_ms.max(child.created_at_ms);
    next.retry_lineage
        .child_job_ids
        .push(child.local_job_id.clone());
    next.validate()?;
    validate_successor(parent, &next)?;
    Ok(next)
}

fn validate_retry_common_identity(
    parent: &StoredJobV1,
    child: &StoredJobV1,
) -> Result<(), JobStoreError> {
    child.validate()?;
    validate_initial_job_revision(child)?;
    let expected_attempt =
        parent.retry_lineage.attempt.checked_add(1).ok_or_else(|| {
            invalid_record("retry attempt cannot advance beyond the supported range")
        })?;
    if child.revision != 1
        || child.retry_lineage.parent_job_id.as_ref() != Some(&parent.local_job_id)
        || child.retry_lineage.attempt != expected_attempt
        || child.retry_lineage.attempt == 0
        || child.project != parent.project
        || child.provider != parent.provider
        || child.target != parent.target
        || child.profile != parent.profile
        || child.signing_mode != parent.signing_mode
        || child.operation_id == parent.operation_id
        || child.created_at_ms < parent.created_at_ms
    {
        return Err(invalid_record(
            "retry child differs from its immutable parent identity",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "retry identity validation intentionally enumerates every immutable request and lineage field"
)]
fn validate_retry_child(
    parent: &StoredJobV1,
    child: &StoredJobV1,
    options: &RetryLineageOptionsV1,
) -> Result<(), JobStoreError> {
    validate_retry_common_identity(parent, child)?;
    match &options.source_policy {
        RetrySourcePolicyV1::Exact => {
            if parent.request.source_mode == SourceMode::GitSnapshot
                || child.request.source_mode == SourceMode::GitSnapshot
            {
                return Err(invalid_record(
                    "Git snapshot retry requires an archive-bound source policy",
                ));
            }
            let mut expected_request = parent.request.clone();
            expected_request
                .operation_id
                .clone_from(&child.operation_id);
            if child.request != expected_request
                || child.semantic_retry_sha256 != parent.semantic_retry_sha256
                || child.source != parent.source
            {
                return Err(invalid_record(
                    "exact retry changed a request field other than its operation",
                ));
            }
        }
        RetrySourcePolicyV1::ExactGitSnapshot {
            source_archive_sha256,
        } => {
            validate_sha256("retry.source_archive_sha256", source_archive_sha256)?;
            let parent_resume = parent.provider_resume.as_ref().ok_or_else(|| {
                invalid_record("exact Git snapshot retry lacks a retained parent checkpoint")
            })?;
            let parent_snapshot = parent_resume.git_snapshot.as_ref().ok_or_else(|| {
                invalid_record("exact Git snapshot retry lacks a retained parent checkpoint")
            })?;
            let mut expected_request = parent.request.clone();
            expected_request
                .operation_id
                .clone_from(&child.operation_id);
            expected_request
                .source_revision
                .clone_from(&child.request.source_revision);
            if parent.request.source_mode != SourceMode::GitSnapshot
                || child.request.source_mode != SourceMode::GitSnapshot
                || parent.cleanup_status != StoredCleanupStatus::Confirmed
                || parent_resume.state != JobState::Cleaned
                || !parent_resume.cleanup_requested
                || parent.provider_job_id.as_deref() != Some(parent.operation_id.as_str())
                || parent_resume.job_id != parent.operation_id
                || !matches!(
                    parent_snapshot.phase,
                    GithubGitSnapshotPhaseV1::SourceDeleted
                        | GithubGitSnapshotPhaseV1::SourceAbsent
                        | GithubGitSnapshotPhaseV1::SourceConflict
                )
                || parent_snapshot
                    .keepalive_release_authorization_sha256
                    .is_some()
                || child.request != expected_request
                || child.request.source_revision == parent.request.source_revision
                || child.request.source_repository != parent.request.source_repository
                || child.request.source != parent.request.source
                || child.source.manifest_sha256 != parent.source.manifest_sha256
                || parent_snapshot.stage.archive.sha256 != *source_archive_sha256
            {
                return Err(invalid_record(
                    "exact Git snapshot retry differs from its retained archive template",
                ));
            }
        }
        RetrySourcePolicyV1::RecapturedGitSnapshot {
            confirmation_sha256,
            snapshot_consent_sha256,
            source_archive_sha256,
        } => {
            validate_sha256("retry.confirmation_sha256", confirmation_sha256)?;
            validate_sha256("retry.snapshot_consent_sha256", snapshot_consent_sha256)?;
            validate_sha256("retry.source_archive_sha256", source_archive_sha256)?;
            let expected = retry_recapture_confirmation_sha256(parent, child)?;
            if *confirmation_sha256 != expected {
                return Err(invalid_record(
                    "recaptured retry confirmation differs from the exact child template",
                ));
            }
        }
    }
    let terminal = matches!(
        parent.state,
        StoredJobState::Failed | StoredJobState::Cancelled | StoredJobState::Expired
    );
    let cleanup_safe = matches!(
        parent.cleanup_status,
        StoredCleanupStatus::NotStarted | StoredCleanupStatus::Confirmed
    );
    let failure_retryable = parent.state != StoredJobState::Failed
        || parent
            .failure
            .as_ref()
            .is_some_and(|failure| failure.retryable);
    let successful_allowed = options.parent_policy == RetryParentPolicyV1::AllowSuccessful
        && parent.state == StoredJobState::Succeeded
        && parent.terminal_outcome == Some(StoredBuildOutcome::Succeeded)
        && parent.cleanup_status == StoredCleanupStatus::Confirmed
        && parent.compile_evidence.is_some()
        && parent.provider_resume.is_some();
    if !(terminal || successful_allowed)
        || parent.terminal_outcome.is_none()
        || !cleanup_safe
        || !failure_retryable
        || parent.cancellation_status == StoredCancellationStatus::Uncertain
    {
        return Err(invalid_record(
            "retry parent is active, uncertain, cleanup-failed, or not retryable",
        ));
    }
    if parent.retry_lineage.child_job_ids.len() >= MAX_RETRY_CHILDREN {
        return Err(JobStoreError::BoundExceeded {
            kind: "retry children",
            maximum: MAX_RETRY_CHILDREN as u64,
        });
    }
    Ok(())
}

fn validate_retry_transaction_shape(transaction: &RetryTransactionV1) -> Result<(), JobStoreError> {
    if transaction.parent_before_revision.saturating_add(1) != transaction.parent_next.revision
        || !is_sha256(&transaction.parent_before_sha256)
        || transaction.child.revision != 1
    {
        return Err(invalid_record(
            "retry transaction revision binding is invalid",
        ));
    }
    let parent_children = &transaction.parent_next.retry_lineage.child_job_ids;
    if parent_children.last() != Some(&transaction.child.local_job_id)
        || transaction.child.retry_lineage.parent_job_id.as_ref()
            != Some(&transaction.parent_next.local_job_id)
    {
        return Err(invalid_record(
            "retry transaction lineage binding is invalid",
        ));
    }
    Ok(())
}

fn validate_retry_transaction_against_parent(
    parent_before: &StoredJobV1,
    transaction: &RetryTransactionV1,
) -> Result<(), JobStoreError> {
    validate_retry_transaction_shape(transaction)?;
    if parent_before.revision != transaction.parent_before_revision
        || transaction.parent_next.local_job_id != parent_before.local_job_id
        || transaction.parent_next.retry_lineage.child_job_ids.len()
            != parent_before
                .retry_lineage
                .child_job_ids
                .len()
                .saturating_add(1)
        || transaction.parent_next.retry_lineage.child_job_ids
            [..parent_before.retry_lineage.child_job_ids.len()]
            != parent_before.retry_lineage.child_job_ids
    {
        return Err(invalid_record(
            "retry transaction differs from the exact parent revision",
        ));
    }
    validate_retry_child(parent_before, &transaction.child, &transaction.options)?;
    validate_successor(parent_before, &transaction.parent_next)
}

fn finish_retry_transaction(
    store: &JobStore,
    layout: &AdminLayout,
    transaction_sha256: &str,
    transaction: &RetryTransactionV1,
) -> Result<RetryLineageReceipt, JobStoreError> {
    let mut identifiers = vec![
        transaction.parent_next.local_job_id.clone(),
        transaction.child.local_job_id.clone(),
    ];
    identifiers.sort();
    let mut locked = BTreeMap::new();
    for identifier in identifiers {
        let job = store.lock_job_unchecked(&identifier, true)?;
        recover_revision_staging(&job)?;
        locked.insert(identifier, job);
    }
    finish_retry_transaction_with_locks(layout, transaction_sha256, transaction, &locked)
}

fn finish_retry_transaction_with_locks(
    _layout: &AdminLayout,
    transaction_sha256: &str,
    transaction: &RetryTransactionV1,
    locked: &BTreeMap<LocalJobId, LockedJob>,
) -> Result<RetryLineageReceipt, JobStoreError> {
    let parent_id = &transaction.parent_next.local_job_id;
    let child_id = &transaction.child.local_job_id;
    let parent_locked = locked
        .get(parent_id)
        .ok_or_else(|| invalid_record("retry recovery omitted its parent lock"))?;
    let child_locked = locked
        .get(child_id)
        .ok_or_else(|| invalid_record("retry recovery omitted its child lock"))?;

    let parent_entries = scan_revision_files(&parent_locked.revisions)?;
    let parent_latest = parent_entries
        .last()
        .ok_or_else(|| JobStoreError::JobNotFound {
            local_job_id: parent_id.clone(),
        })?;
    let parent_record = read_job_revision(
        &parent_latest.path,
        parent_latest.revision,
        &parent_latest.sha256,
        parent_id,
    )?;
    let expected_parent_sha256 = sha256_hex(&encode_revision_v2(
        &transaction.parent_next,
        Some(&transaction.parent_before_sha256),
    )?);
    let parent_complete =
        parent_record == transaction.parent_next && parent_latest.sha256 == expected_parent_sha256;
    if !parent_complete {
        if parent_record.revision != transaction.parent_before_revision
            || parent_latest.sha256 != transaction.parent_before_sha256
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "retry parent changed after its durable transaction intent",
            });
        }
        validate_retry_transaction_against_parent(&parent_record, transaction)?;
    }

    let expected_child_sha256 = sha256_hex(&encode_revision_v2(&transaction.child, None)?);
    let child_entries = scan_revision_files(&child_locked.revisions)?;
    let child_complete = if let Some(child_entry) = child_entries.last() {
        let child_record = read_job_revision(
            &child_entry.path,
            child_entry.revision,
            &child_entry.sha256,
            child_id,
        )?;
        if child_record != transaction.child
            || child_entry.sha256 != expected_child_sha256
            || child_entries.len() != 1
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "retry child differs from its durable transaction intent",
            });
        }
        true
    } else {
        false
    };

    let child_receipt = if child_complete {
        let child_entry = child_entries.last().expect("checked child entry");
        ensure_revision_durable(child_locked, child_entry, &transaction.child)?;
        RevisionReceipt {
            local_job_id: child_id.clone(),
            revision: child_entry.revision,
            sha256: child_entry.sha256.clone(),
            already_present: true,
        }
    } else {
        publish_admin_job_revision(child_locked, &transaction.child, true, None)?
    };

    let parent_receipt = if parent_complete {
        ensure_revision_durable(parent_locked, parent_latest, &transaction.parent_next)?;
        RevisionReceipt {
            local_job_id: parent_id.clone(),
            revision: parent_latest.revision,
            sha256: parent_latest.sha256.clone(),
            already_present: true,
        }
    } else {
        publish_admin_job_revision(
            parent_locked,
            &transaction.parent_next,
            false,
            Some(&transaction.parent_before_sha256),
        )?
    };
    Ok(RetryLineageReceipt {
        parent: parent_receipt,
        child: child_receipt,
        binding: retry_lineage_binding_from_transaction(transaction_sha256, transaction),
    })
}

fn publish_admin_job_revision(
    locked: &LockedJob,
    record: &StoredJobV1,
    initial: bool,
    previous_revision_sha256: Option<&str>,
) -> Result<RevisionReceipt, JobStoreError> {
    record.validate()?;
    if initial {
        validate_initial_job_revision(record)?;
    }
    let bytes = encode_revision_v2(record, previous_revision_sha256)?;
    let sha256 = sha256_hex(&bytes);
    let final_path = locked
        .revisions
        .join(revision_filename(record.revision, &sha256));
    let already_present =
        publish_revision_with_reconciliation(locked, &final_path, record, &bytes, &sha256)?;
    Ok(RevisionReceipt {
        local_job_id: record.local_job_id.clone(),
        revision: record.revision,
        sha256,
        already_present,
    })
}

fn recover_pending_transactions_locked(
    store: &JobStore,
    layout: &AdminLayout,
) -> Result<(), JobStoreError> {
    let transaction_directory = admin_transaction_locked_directory(layout)?;
    recover_managed_staging(&transaction_directory)?;
    for path in scan_pending_transaction_paths(&layout.transactions)? {
        let (sha256, transaction) = read_admin_transaction(&path)?;
        match transaction {
            AdminTransactionV1::Retry(transaction) => {
                finish_retry_transaction(store, layout, &sha256, &transaction)?;
                publish_admin_completion(layout, "retry", &sha256)?;
            }
            AdminTransactionV1::PruneRelease(_) => {
                publish_admin_completion(layout, "release", &sha256)?;
            }
            AdminTransactionV1::Prune(transaction) => {
                finish_prune_transaction(store, layout, &sha256, &transaction)?;
                publish_admin_completion(layout, "prune", &sha256)?;
            }
        }
    }
    reconcile_consumed_prune_release_authorizations(store, layout)?;
    Ok(())
}

impl JobStore {
    /// Build a deterministic, read-only prune plan containing only complete eligible lineages.
    ///
    /// Active, unknown, cleanup-failed, cleanup-uncertain, cancellation-uncertain, incomplete
    /// lineage components, and jobs with local artifacts not durably removed are never selected.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, malformed-lineage, lock, record, or storage error.
    #[allow(
        clippy::too_many_lines,
        reason = "the read-only complete-lineage planner keeps all fail-closed selection checks together"
    )]
    pub fn plan_prune(
        &self,
        terminal_before_ms: u64,
        max_jobs: usize,
    ) -> Result<PrunePlanV1, JobStoreError> {
        if max_jobs == 0 || max_jobs > MAX_PRUNE_JOBS {
            return Err(JobStoreError::BoundExceeded {
                kind: "prune jobs",
                maximum: MAX_PRUNE_JOBS as u64,
            });
        }
        reject_pending_admin_transactions(self)?;
        let records = scan_active_jobs(self)?;
        validate_retry_graph(&records)?;
        let mut artifacts_removed = BTreeMap::new();
        for (local_job_id, (_, record)) in &records {
            let overlays = read_artifact_overlays(self, local_job_id)?;
            artifacts_removed.insert(
                local_job_id.clone(),
                local_artifacts_are_removed(record, &overlays),
            );
        }
        let mut visited = BTreeSet::new();
        let mut components = Vec::new();
        for identifier in records.keys() {
            if visited.contains(identifier) {
                continue;
            }
            let component = lineage_component(identifier, &records)?;
            visited.extend(component.iter().cloned());
            if component.iter().all(|job_id| {
                records
                    .get(job_id)
                    .is_some_and(|(_, record)| prune_record_is_eligible(record, terminal_before_ms))
                    && artifacts_removed.get(job_id) == Some(&true)
            }) {
                let oldest = component
                    .iter()
                    .filter_map(|job_id| records.get(job_id))
                    .map(|(_, record)| record.updated_at_ms)
                    .min()
                    .unwrap_or(u64::MAX);
                let first = component
                    .iter()
                    .next()
                    .cloned()
                    .ok_or_else(|| invalid_record("retry lineage component is empty"))?;
                components.push((oldest, first, component));
            }
        }
        components.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
        let mut selected = BTreeSet::new();
        let mut selected_authorizations = BTreeMap::new();
        for (_, _, component) in components {
            if selected.len().saturating_add(component.len()) > max_jobs {
                continue;
            }
            let authorization =
                complete_lineage_authorization_sha256(terminal_before_ms, &component, &records)?;
            validate_component_snapshot_release_authority(&component, &records, &authorization)?;
            for local_job_id in &component {
                selected_authorizations.insert(local_job_id.clone(), authorization.clone());
            }
            selected.extend(component);
        }
        let mut candidates = selected
            .into_iter()
            .map(|local_job_id| {
                let (entry, record) = records
                    .get(&local_job_id)
                    .ok_or_else(|| invalid_record("selected prune job disappeared"))?;
                Ok(PruneCandidateV1 {
                    complete_lineage_authorization_sha256: selected_authorizations
                        .get(&local_job_id)
                        .cloned()
                        .ok_or_else(|| {
                            invalid_record("selected prune job lacks lineage authorization")
                        })?,
                    has_git_snapshot_keepalive: record
                        .provider_resume
                        .as_ref()
                        .and_then(|resume| resume.git_snapshot.as_ref())
                        .is_some(),
                    local_job_id,
                    operation_id: record.operation_id.clone(),
                    revision: entry.revision,
                    revision_sha256: entry.sha256.clone(),
                    updated_at_ms: record.updated_at_ms,
                    attempt: record.retry_lineage.attempt,
                    parent_job_id: record.retry_lineage.parent_job_id.clone(),
                    child_job_ids: record.retry_lineage.child_job_ids.clone(),
                })
            })
            .collect::<Result<Vec<_>, JobStoreError>>()?;
        candidates.sort_by(|left, right| {
            (&left.updated_at_ms, &left.local_job_id)
                .cmp(&(&right.updated_at_ms, &right.local_job_id))
        });
        let plan = PrunePlanV1 {
            terminal_before_ms,
            selection_max_jobs: max_jobs,
            candidates,
        };
        validate_prune_plan_shape(&plan)?;
        Ok(plan)
    }

    /// Acquire every exact candidate's Prune lease in sorted order and revalidate the full plan.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-plan, busy, identity, recovery, or storage error.
    pub fn acquire_prune_leases(&self, plan: &PrunePlanV1) -> Result<PruneLeaseSet, JobStoreError> {
        self.ensure_writable()?;
        validate_prune_plan_shape(plan)?;
        if plan.selection_max_jobs == 0 {
            return Err(invalid_record(
                "prune lease acquisition requires a replan-capable selection bound",
            ));
        }
        reject_pending_admin_transactions(self)?;
        if let Some((_guard, transactions)) = open_pending_transaction_directory(self)?
            && !scan_active_prune_release_authorizations(&transactions)?.is_empty()
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "a durable prune release authorization must be resumed before planning another prune",
            });
        }
        #[cfg(test)]
        await_prune_release_publication_test_barrier(self);
        let mut identifiers = plan
            .candidates
            .iter()
            .map(|candidate| candidate.local_job_id.clone())
            .collect::<Vec<_>>();
        identifiers.sort();
        let mut leases = BTreeMap::new();
        for identifier in identifiers {
            let lease = self.try_acquire_operation_lease(&identifier, JobOperationKind::Prune)?;
            leases.insert(identifier, lease);
        }
        let mut lease_set = PruneLeaseSet {
            initial_plan: plan.clone(),
            release_authorization_sha256: String::new(),
            leases,
        };
        let observed = self.plan_prune(plan.terminal_before_ms, plan.selection_max_jobs)?;
        if observed != *plan {
            return Err(JobStoreError::RecoveryRequired {
                reason: "prune plan changed while its exact job leases were acquired",
            });
        }
        validate_prune_lease_set_against_plan(self, &lease_set, &observed, false)?;
        if !plan.candidates.is_empty() {
            let layout = ensure_admin_layout(self)?;
            recover_pending_transactions_locked(self, &layout)?;
            if !scan_active_prune_release_authorizations(&layout.transactions)?.is_empty() {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "a durable prune release authorization must be resumed before planning another prune",
                });
            }
            let authorization = PruneReleaseAuthorizationV1 {
                schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
                plan: plan.clone(),
            };
            let value = AdminTransactionV1::PruneRelease(authorization);
            let (authorization_sha256, _) = publish_admin_transaction(&layout, &value)?;
            publish_admin_completion(&layout, "release", &authorization_sha256)?;
            lease_set.release_authorization_sha256 = authorization_sha256;
        }
        Ok(lease_set)
    }

    /// Return the exact durable release plan that must be resumed, regardless of new CLI cutoff.
    ///
    /// This is read-only. It returns current post-checkpoint revisions while retaining the
    /// original cutoff, selection bound, component IDs, edges, and provider authorization digests.
    ///
    /// # Errors
    ///
    /// Returns a typed ambiguity, stale-authority, pending-recovery, or storage error.
    pub fn pending_prune_release_plan(&self) -> Result<Option<PrunePlanV1>, JobStoreError> {
        let Some((_guard, transactions)) = open_pending_transaction_directory(self)? else {
            return Ok(None);
        };
        let authorizations = scan_active_prune_release_authorizations(&transactions)?;
        let Some((_, authorization)) = authorizations.first() else {
            return Ok(None);
        };
        if authorizations.len() != 1 {
            return Err(JobStoreError::RecoveryRequired {
                reason: "multiple durable prune release authorizations require inspection",
            });
        }
        let current = self.plan_prune(
            authorization.plan.terminal_before_ms,
            authorization.plan.selection_max_jobs,
        )?;
        if !prune_plans_share_stable_authority(&authorization.plan, &current) {
            return Err(JobStoreError::RecoveryRequired {
                reason: "durable prune release authorization differs from current lineage",
            });
        }
        Ok(Some(current))
    }

    /// Reacquire every exact lease for the one durable, incomplete prune release authorization.
    ///
    /// # Errors
    ///
    /// Returns a typed ambiguity, busy, stale-authority, recovery, or storage error.
    pub fn resume_prune_release_leases(&self) -> Result<Option<PruneLeaseSet>, JobStoreError> {
        self.ensure_writable()?;
        let layout = ensure_admin_layout(self)?;
        recover_pending_transactions_locked(self, &layout)?;
        let authorizations = scan_active_prune_release_authorizations(&layout.transactions)?;
        drop(layout);
        let Some((authorization_sha256, authorization)) = authorizations.into_iter().next() else {
            return Ok(None);
        };
        let Some((_guard, transactions)) = open_pending_transaction_directory(self)? else {
            return Err(JobStoreError::RecoveryRequired {
                reason: "prune release authorization directory disappeared",
            });
        };
        if scan_active_prune_release_authorizations(&transactions)?.len() != 1 {
            return Err(JobStoreError::RecoveryRequired {
                reason: "multiple durable prune release authorizations require inspection",
            });
        }
        let mut identifiers = authorization
            .plan
            .candidates
            .iter()
            .map(|candidate| candidate.local_job_id.clone())
            .collect::<Vec<_>>();
        identifiers.sort();
        let mut leases = BTreeMap::new();
        for identifier in identifiers {
            let lease = self.try_acquire_operation_lease(&identifier, JobOperationKind::Prune)?;
            leases.insert(identifier, lease);
        }
        let lease_set = PruneLeaseSet {
            initial_plan: authorization.plan,
            release_authorization_sha256: authorization_sha256,
            leases,
        };
        let current = replan_prune_with_stable_authority(self, &lease_set)?;
        validate_prune_lease_set_against_plan(self, &lease_set, &current, false)?;
        Ok(Some(lease_set))
    }

    /// Return every snapshot keepalive release bound to a held complete-lineage lease set.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-plan, lease, checkpoint, identity, recovery, or storage error.
    pub fn snapshot_keepalive_releases(
        &self,
        lease_set: &PruneLeaseSet,
    ) -> Result<Vec<PruneSnapshotReleaseV1>, JobStoreError> {
        let current = replan_prune_with_stable_authority(self, lease_set)?;
        validate_prune_lease_set_against_plan(self, lease_set, &current, false)?;
        let mut releases = Vec::new();
        for candidate in &current.candidates {
            if !candidate.has_git_snapshot_keepalive {
                continue;
            }
            let record = self.latest(&candidate.local_job_id)?;
            let snapshot = record
                .provider_resume
                .as_ref()
                .and_then(|resume| resume.git_snapshot.as_ref())
                .ok_or_else(|| invalid_record("snapshot prune candidate lost its checkpoint"))?;
            let state = match snapshot.phase {
                GithubGitSnapshotPhaseV1::SourceDeleted
                | GithubGitSnapshotPhaseV1::SourceAbsent
                | GithubGitSnapshotPhaseV1::SourceConflict => PruneSnapshotReleaseStateV1::Required,
                GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent => {
                    PruneSnapshotReleaseStateV1::Intent
                }
                GithubGitSnapshotPhaseV1::KeepaliveReleased => {
                    PruneSnapshotReleaseStateV1::Released
                }
                _ => {
                    return Err(invalid_record(
                        "snapshot prune candidate is outside a releasable phase",
                    ));
                }
            };
            releases.push(PruneSnapshotReleaseV1 {
                local_job_id: candidate.local_job_id.clone(),
                operation_id: record.operation_id,
                complete_lineage_authorization_sha256: candidate
                    .complete_lineage_authorization_sha256
                    .clone(),
                state,
            });
        }
        Ok(releases)
    }

    /// Replan under all retained Prune leases and require every snapshot keepalive to be released.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-plan, release-proof, lease, identity, recovery, or storage error.
    pub fn replan_prune_after_keepalive_releases(
        &self,
        lease_set: &PruneLeaseSet,
    ) -> Result<PrunePlanV1, JobStoreError> {
        let current = replan_prune_with_stable_authority(self, lease_set)?;
        validate_prune_lease_set_against_plan(self, lease_set, &current, true)?;
        Ok(current)
    }

    /// Publish one exact post-release prune transaction, then release leases and delete all trees.
    ///
    /// The lease set is consumed only after the immutable transaction is durably published. Crash
    /// recovery therefore performs deletion without a live Windows handle blocking tree removal.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-plan, busy, release-proof, identity, recovery, or storage error.
    pub fn prune(
        &self,
        lease_set: PruneLeaseSet,
        post_release_plan: &PrunePlanV1,
        pruned_at_ms: u64,
    ) -> Result<PruneReceiptV1, JobStoreError> {
        self.ensure_writable()?;
        validate_prune_plan_shape(post_release_plan)?;
        let observed = replan_prune_with_stable_authority(self, &lease_set)?;
        if observed != *post_release_plan {
            return Err(JobStoreError::RecoveryRequired {
                reason: "post-release prune plan changed before transaction publication",
            });
        }
        if post_release_plan.candidates.is_empty() {
            drop(lease_set);
            return Ok(PruneReceiptV1 {
                transaction_sha256: sha256_hex(b"rustferry-empty-prune-v1"),
                pruned_job_ids: Vec::new(),
                already_complete: true,
            });
        }
        let layout = ensure_admin_layout(self)?;
        recover_pending_transactions_locked(self, &layout)?;
        let mut identifiers = post_release_plan
            .candidates
            .iter()
            .map(|candidate| candidate.local_job_id.clone())
            .collect::<Vec<_>>();
        identifiers.sort();
        let locked =
            validate_prune_lease_set_against_plan(self, &lease_set, post_release_plan, true)?;
        await_prune_publication_validation_test_control(&locked);

        let transaction = PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms,
            plan: post_release_plan.clone(),
        };
        let value = AdminTransactionV1::Prune(transaction.clone());
        let (transaction_sha256, already_present) = publish_admin_transaction(&layout, &value)?;
        await_prune_transaction_published_test_control(&locked);
        let release_authorization_sha256 = lease_set.release_authorization_sha256.clone();
        drop(locked);
        #[cfg(test)]
        await_prune_candidate_locks_released_test_control(&identifiers);
        drop(lease_set);
        finish_prune_transaction(self, &layout, &transaction_sha256, &transaction)?;
        let completion_already_present =
            publish_admin_completion(&layout, "prune", &transaction_sha256)?;
        publish_prune_release_consumed(&layout, &release_authorization_sha256)?;
        Ok(PruneReceiptV1 {
            transaction_sha256,
            pruned_job_ids: identifiers,
            already_complete: already_present && completion_already_present,
        })
    }
}

fn replan_prune_with_stable_authority(
    store: &JobStore,
    lease_set: &PruneLeaseSet,
) -> Result<PrunePlanV1, JobStoreError> {
    let initial = &lease_set.initial_plan;
    if initial.selection_max_jobs == 0 {
        return Err(invalid_record(
            "prune lease set lacks its original selection bound",
        ));
    }
    if !initial.candidates.is_empty() {
        validate_sha256(
            "prune_release.authorization_sha256",
            &lease_set.release_authorization_sha256,
        )?;
        let Some((_guard, transactions)) = open_pending_transaction_directory(store)? else {
            return Err(JobStoreError::RecoveryRequired {
                reason: "held prune leases lost their durable release authorization",
            });
        };
        let active = scan_active_prune_release_authorizations(&transactions)?;
        if active.len() != 1
            || active[0].0 != lease_set.release_authorization_sha256
            || !prune_plans_share_stable_authority(&active[0].1.plan, initial)
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "held prune leases differ from their durable release authorization",
            });
        }
    }
    let current = store.plan_prune(initial.terminal_before_ms, initial.selection_max_jobs)?;
    if !prune_plans_share_stable_authority(initial, &current) {
        return Err(JobStoreError::RecoveryRequired {
            reason: "complete-lineage prune authorization changed while leases were held",
        });
    }
    Ok(current)
}

fn prune_plans_share_stable_authority(left: &PrunePlanV1, right: &PrunePlanV1) -> bool {
    if left.terminal_before_ms != right.terminal_before_ms
        || left.selection_max_jobs != right.selection_max_jobs
        || left.candidates.len() != right.candidates.len()
    {
        return false;
    }
    let right_candidates = right
        .candidates
        .iter()
        .map(|candidate| (&candidate.local_job_id, candidate))
        .collect::<BTreeMap<_, _>>();
    left.candidates.iter().all(|candidate| {
        right_candidates
            .get(&candidate.local_job_id)
            .is_some_and(|current| {
                current.attempt == candidate.attempt
                    && current.parent_job_id == candidate.parent_job_id
                    && current.child_job_ids == candidate.child_job_ids
                    && current.complete_lineage_authorization_sha256
                        == candidate.complete_lineage_authorization_sha256
                    && current.has_git_snapshot_keepalive == candidate.has_git_snapshot_keepalive
            })
    })
}

fn validate_prune_lease_set_against_plan(
    store: &JobStore,
    lease_set: &PruneLeaseSet,
    plan: &PrunePlanV1,
    require_keepalive_released: bool,
) -> Result<BTreeMap<LocalJobId, LockedJob>, JobStoreError> {
    let identifiers = plan
        .candidates
        .iter()
        .map(|candidate| candidate.local_job_id.clone())
        .collect::<BTreeSet<_>>();
    if identifiers.len() != lease_set.leases.len()
        || identifiers
            .iter()
            .any(|identifier| !lease_set.leases.contains_key(identifier))
    {
        return Err(invalid_record(
            "prune lease set differs from the exact candidate set",
        ));
    }
    let mut locked = BTreeMap::new();
    for identifier in &identifiers {
        let job = store.lock_job(identifier, false)?;
        recover_revision_staging(&job)?;
        let lease = lease_set
            .leases
            .get(identifier)
            .ok_or_else(|| invalid_record("prune candidate lacks its exact operation lease"))?;
        lease.validate_owner(store, &job, identifier, JobOperationKind::Prune)?;
        locked.insert(identifier.clone(), job);
    }
    validate_prune_plan_against_locked(store, plan, &locked, require_keepalive_released)?;
    Ok(locked)
}

fn scan_active_jobs(
    store: &JobStore,
) -> Result<BTreeMap<LocalJobId, (RevisionEntry, StoredJobV1)>, JobStoreError> {
    let Some(_layout) = store.open_existing_store_layout()? else {
        return Ok(BTreeMap::new());
    };
    let root = store.version_root();
    let mut identifiers = Vec::new();
    for entry in fs::read_dir(&root).map_err(|source| io_error("read jobs for prune", source))? {
        if identifiers.len() >= MAX_STORED_JOBS {
            return Err(JobStoreError::BoundExceeded {
                kind: "stored jobs",
                maximum: MAX_STORED_JOBS as u64,
            });
        }
        let entry = entry.map_err(|source| io_error("read prune job entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JobStoreError::MalformedLayout {
                reason: "job directory name is not UTF-8",
            })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("inspect prune job entry", source))?;
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
    identifiers.sort();
    let mut records = BTreeMap::new();
    for identifier in identifiers {
        let observed = if store.access == JobStoreAccess::ReadOnly {
            let opened = store.open_read_only_job(&identifier)?;
            let entries = scan_revision_files(&opened.revisions)?;
            entries
                .last()
                .map(|entry| {
                    read_job_revision(&entry.path, entry.revision, &entry.sha256, &identifier)
                        .map(|record| (entry.clone_for_admin(), record))
                })
                .transpose()?
        } else {
            let opened = store.lock_job(&identifier, false)?;
            recover_revision_staging(&opened)?;
            let entries = scan_revision_files(&opened.revisions)?;
            entries
                .last()
                .map(|entry| {
                    read_job_revision(&entry.path, entry.revision, &entry.sha256, &identifier)
                        .map(|record| (entry.clone_for_admin(), record))
                })
                .transpose()?
        };
        if let Some(observed) = observed {
            records.insert(identifier, observed);
        }
    }
    Ok(records)
}

impl RevisionEntry {
    fn clone_for_admin(&self) -> Self {
        Self {
            revision: self.revision,
            sha256: self.sha256.clone(),
            path: self.path.clone(),
        }
    }
}

fn validate_retry_graph(
    records: &BTreeMap<LocalJobId, (RevisionEntry, StoredJobV1)>,
) -> Result<(), JobStoreError> {
    for (local_job_id, (_, record)) in records {
        if let Some(parent_id) = &record.retry_lineage.parent_job_id {
            let (_, parent) = records.get(parent_id).ok_or_else(|| {
                invalid_record("active retry lineage references a missing parent")
            })?;
            if !parent.retry_lineage.child_job_ids.contains(local_job_id)
                || record.retry_lineage.attempt != parent.retry_lineage.attempt.saturating_add(1)
            {
                return Err(invalid_record(
                    "active retry lineage lacks an exact reciprocal parent edge",
                ));
            }
        }
        for child_id in &record.retry_lineage.child_job_ids {
            let (_, child) = records
                .get(child_id)
                .ok_or_else(|| invalid_record("active retry lineage references a missing child"))?;
            if child.retry_lineage.parent_job_id.as_ref() != Some(local_job_id)
                || child.retry_lineage.attempt != record.retry_lineage.attempt.saturating_add(1)
            {
                return Err(invalid_record(
                    "active retry lineage lacks an exact reciprocal child edge",
                ));
            }
        }
    }
    Ok(())
}

fn lineage_component(
    start: &LocalJobId,
    records: &BTreeMap<LocalJobId, (RevisionEntry, StoredJobV1)>,
) -> Result<BTreeSet<LocalJobId>, JobStoreError> {
    let mut component = BTreeSet::new();
    let mut pending = VecDeque::from([start.clone()]);
    while let Some(identifier) = pending.pop_front() {
        if !component.insert(identifier.clone()) {
            continue;
        }
        let (_, record) = records
            .get(&identifier)
            .ok_or_else(|| invalid_record("retry lineage component references a missing job"))?;
        if let Some(parent) = &record.retry_lineage.parent_job_id {
            pending.push_back(parent.clone());
        }
        pending.extend(record.retry_lineage.child_job_ids.iter().cloned());
    }
    Ok(component)
}

fn complete_lineage_authorization_sha256(
    terminal_before_ms: u64,
    component: &BTreeSet<LocalJobId>,
    records: &BTreeMap<LocalJobId, (RevisionEntry, StoredJobV1)>,
) -> Result<String, JobStoreError> {
    let mut edges = BTreeSet::new();
    for parent_id in component {
        let (_, parent) = records
            .get(parent_id)
            .ok_or_else(|| invalid_record("prune authorization references a missing job"))?;
        for child_id in &parent.retry_lineage.child_job_ids {
            if !component.contains(child_id) {
                return Err(invalid_record(
                    "prune authorization splits a retry lineage edge",
                ));
            }
            edges.insert((parent_id.clone(), child_id.clone()));
        }
    }
    Ok(stable_lineage_authorization_sha256(
        terminal_before_ms,
        component,
        &edges,
    ))
}

fn stable_lineage_authorization_sha256(
    terminal_before_ms: u64,
    identifiers: &BTreeSet<LocalJobId>,
    edges: &BTreeSet<(LocalJobId, LocalJobId)>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rustferry-prune-complete-lineage-v1\0");
    digest.update(terminal_before_ms.to_be_bytes());
    digest.update(
        u64::try_from(identifiers.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for identifier in identifiers {
        update_length_prefixed_digest(&mut digest, identifier.as_str());
    }
    digest.update(u64::try_from(edges.len()).unwrap_or(u64::MAX).to_be_bytes());
    for (parent, child) in edges {
        update_length_prefixed_digest(&mut digest, parent.as_str());
        update_length_prefixed_digest(&mut digest, child.as_str());
    }
    lower_hex(digest.finalize())
}

fn update_length_prefixed_digest(digest: &mut Sha256, value: &str) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

fn validate_component_snapshot_release_authority(
    component: &BTreeSet<LocalJobId>,
    records: &BTreeMap<LocalJobId, (RevisionEntry, StoredJobV1)>,
    authorization_sha256: &str,
) -> Result<(), JobStoreError> {
    for local_job_id in component {
        let (_, record) = records
            .get(local_job_id)
            .ok_or_else(|| invalid_record("snapshot release references a missing prune job"))?;
        let Some(resume) = record.provider_resume.as_ref() else {
            continue;
        };
        let Some(snapshot) = resume.git_snapshot.as_ref() else {
            continue;
        };
        if record.provider_job_id.as_deref() != Some(record.operation_id.as_str())
            || resume.job_id != record.operation_id
            || resume.state != JobState::Cleaned
            || !resume.cleanup_requested
        {
            return Err(invalid_record(
                "snapshot prune job lacks exact cleaned provider identity",
            ));
        }
        match snapshot.phase {
            GithubGitSnapshotPhaseV1::SourceDeleted
            | GithubGitSnapshotPhaseV1::SourceAbsent
            | GithubGitSnapshotPhaseV1::SourceConflict => {
                if snapshot.keepalive_release_authorization_sha256.is_some() {
                    return Err(invalid_record(
                        "snapshot prune source-clean phase contains release authority",
                    ));
                }
            }
            GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent
            | GithubGitSnapshotPhaseV1::KeepaliveReleased => {
                if snapshot.keepalive_release_authorization_sha256.as_deref()
                    != Some(authorization_sha256)
                {
                    return Err(JobStoreError::RecoveryRequired {
                        reason: "snapshot keepalive release belongs to a different prune cutoff or lineage",
                    });
                }
            }
            _ => {
                return Err(invalid_record(
                    "snapshot prune source cleanup is incomplete",
                ));
            }
        }
    }
    Ok(())
}

fn prune_record_is_eligible(record: &StoredJobV1, terminal_before_ms: u64) -> bool {
    let terminal = matches!(
        record.state,
        StoredJobState::Succeeded
            | StoredJobState::Failed
            | StoredJobState::Cancelled
            | StoredJobState::Expired
    ) && record.terminal_outcome.is_some();
    let cleanup_safe = record.cleanup_status == StoredCleanupStatus::Confirmed
        || (record.cleanup_status == StoredCleanupStatus::NotStarted
            && record.provider_job_id.is_none()
            && record.provider_resume.is_none());
    terminal
        && cleanup_safe
        && record.cancellation_status != StoredCancellationStatus::Uncertain
        && record.updated_at_ms < terminal_before_ms
        && record
            .provider_resume
            .as_ref()
            .and_then(|resume| resume.git_snapshot.as_ref())
            .is_none_or(|snapshot| {
                matches!(
                    snapshot.phase,
                    GithubGitSnapshotPhaseV1::SourceDeleted
                        | GithubGitSnapshotPhaseV1::SourceAbsent
                        | GithubGitSnapshotPhaseV1::SourceConflict
                        | GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent
                        | GithubGitSnapshotPhaseV1::KeepaliveReleased
                )
            })
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if callbacks receive references"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if callbacks receive references"
)]
const fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

fn local_artifacts_are_removed(
    record: &StoredJobV1,
    overlays: &BTreeMap<String, ArtifactRemovalOverlayV1>,
) -> bool {
    record.artifacts.iter().all(|artifact| {
        if artifact.local_path.is_none() && artifact.local_file_identity.is_none() {
            return true;
        }
        overlays
            .get(&artifact.record.artifact_id)
            .is_some_and(|overlay| overlay.state == ManagedArtifactRemovalState::Removed)
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the signed prune-plan validator explicitly checks every authorization-bound field"
)]
fn validate_prune_plan_shape(plan: &PrunePlanV1) -> Result<(), JobStoreError> {
    if plan.candidates.len() > MAX_PRUNE_JOBS
        || plan.selection_max_jobs > MAX_PRUNE_JOBS
        || (plan.selection_max_jobs != 0 && plan.candidates.len() > plan.selection_max_jobs)
    {
        return Err(JobStoreError::BoundExceeded {
            kind: "prune jobs",
            maximum: MAX_PRUNE_JOBS as u64,
        });
    }
    let mut identifiers = BTreeSet::new();
    let mut operation_ids = BTreeSet::new();
    for candidate in &plan.candidates {
        if candidate.revision == 0
            || candidate.operation_id.is_empty()
            || !is_sha256(&candidate.revision_sha256)
            || (!candidate.complete_lineage_authorization_sha256.is_empty()
                && !is_sha256(&candidate.complete_lineage_authorization_sha256))
            || (candidate.has_git_snapshot_keepalive
                && candidate.complete_lineage_authorization_sha256.is_empty())
            || candidate.updated_at_ms >= plan.terminal_before_ms
            || !identifiers.insert(candidate.local_job_id.clone())
        {
            return Err(invalid_record(
                "prune plan candidate is malformed or duplicated",
            ));
        }
        validate_identifier("prune.operation_id", &candidate.operation_id)?;
        if !operation_ids.insert(candidate.operation_id.clone()) {
            return Err(invalid_record("prune plan duplicates a provider operation"));
        }
    }
    let candidates = plan
        .candidates
        .iter()
        .map(|candidate| (candidate.local_job_id.clone(), candidate))
        .collect::<BTreeMap<_, _>>();
    for candidate in &plan.candidates {
        let mut children = BTreeSet::new();
        if let Some(parent_id) = &candidate.parent_job_id {
            let parent = candidates
                .get(parent_id)
                .ok_or_else(|| invalid_record("prune plan splits a retry lineage parent"))?;
            if !parent.child_job_ids.contains(&candidate.local_job_id)
                || candidate.attempt != parent.attempt.saturating_add(1)
            {
                return Err(invalid_record(
                    "prune plan has a non-reciprocal parent edge",
                ));
            }
        }
        for child_id in &candidate.child_job_ids {
            if !children.insert(child_id) {
                return Err(invalid_record("prune plan duplicates a retry child"));
            }
            let child = candidates
                .get(child_id)
                .ok_or_else(|| invalid_record("prune plan splits a retry lineage child"))?;
            if child.parent_job_id.as_ref() != Some(&candidate.local_job_id)
                || child.attempt != candidate.attempt.saturating_add(1)
            {
                return Err(invalid_record("prune plan has a non-reciprocal child edge"));
            }
        }
    }

    let mut visited = BTreeSet::new();
    for start in &identifiers {
        if visited.contains(start) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut pending = VecDeque::from([start.clone()]);
        while let Some(local_job_id) = pending.pop_front() {
            if !component.insert(local_job_id.clone()) {
                continue;
            }
            let candidate = candidates
                .get(&local_job_id)
                .ok_or_else(|| invalid_record("prune component candidate is missing"))?;
            if let Some(parent) = &candidate.parent_job_id {
                pending.push_back(parent.clone());
            }
            pending.extend(candidate.child_job_ids.iter().cloned());
        }
        visited.extend(component.iter().cloned());
        let mut edges = BTreeSet::new();
        for parent_id in &component {
            let parent = candidates
                .get(parent_id)
                .ok_or_else(|| invalid_record("prune component parent is missing"))?;
            for child_id in &parent.child_job_ids {
                edges.insert((parent_id.clone(), child_id.clone()));
            }
        }
        let expected =
            stable_lineage_authorization_sha256(plan.terminal_before_ms, &component, &edges);
        let legacy = component.iter().all(|local_job_id| {
            candidates.get(local_job_id).is_some_and(|candidate| {
                candidate.complete_lineage_authorization_sha256.is_empty()
                    && !candidate.has_git_snapshot_keepalive
            })
        });
        if !legacy
            && component.iter().any(|local_job_id| {
                candidates.get(local_job_id).is_none_or(|candidate| {
                    candidate.complete_lineage_authorization_sha256 != expected
                })
            })
        {
            return Err(invalid_record(
                "prune component authorization differs from its stable lineage digest",
            ));
        }
    }
    Ok(())
}

fn validate_prune_plan_against_locked(
    store: &JobStore,
    plan: &PrunePlanV1,
    locked: &BTreeMap<LocalJobId, LockedJob>,
    require_keepalive_released: bool,
) -> Result<(), JobStoreError> {
    for candidate in &plan.candidates {
        let job = locked
            .get(&candidate.local_job_id)
            .ok_or_else(|| invalid_record("prune plan omitted its exact job lock"))?;
        validate_prune_candidate_against_locked(
            store,
            candidate,
            plan.terminal_before_ms,
            job,
            require_keepalive_released,
        )?;
    }
    Ok(())
}

fn validate_prune_candidate_against_locked(
    store: &JobStore,
    candidate: &PruneCandidateV1,
    terminal_before_ms: u64,
    job: &LockedJob,
    require_keepalive_released: bool,
) -> Result<(), JobStoreError> {
    let entries = scan_revision_files(&job.revisions)?;
    let entry = entries.last().ok_or_else(|| JobStoreError::JobNotFound {
        local_job_id: candidate.local_job_id.clone(),
    })?;
    let record = read_job_revision(
        &entry.path,
        entry.revision,
        &entry.sha256,
        &candidate.local_job_id,
    )?;
    let artifact_overlays = read_artifact_overlays_locked(store, job, &record)?;
    if entry.revision != candidate.revision
        || entry.sha256 != candidate.revision_sha256
        || (!candidate.operation_id.is_empty() && record.operation_id != candidate.operation_id)
        || record.updated_at_ms != candidate.updated_at_ms
        || record.retry_lineage.attempt != candidate.attempt
        || record.retry_lineage.parent_job_id != candidate.parent_job_id
        || record.retry_lineage.child_job_ids != candidate.child_job_ids
        || !prune_record_is_eligible(&record, terminal_before_ms)
        || !local_artifacts_are_removed(&record, &artifact_overlays)
        || !snapshot_prune_candidate_is_bound(&record, candidate, require_keepalive_released)
    {
        return Err(JobStoreError::RevisionConflict {
            expected: candidate.revision,
            found: entry.revision,
        });
    }
    Ok(())
}

fn snapshot_prune_candidate_is_bound(
    record: &StoredJobV1,
    candidate: &PruneCandidateV1,
    require_keepalive_released: bool,
) -> bool {
    let snapshot = record
        .provider_resume
        .as_ref()
        .and_then(|resume| resume.git_snapshot.as_ref());
    if snapshot.is_some() != candidate.has_git_snapshot_keepalive {
        return false;
    }
    let Some(snapshot) = snapshot else {
        return !candidate.complete_lineage_authorization_sha256.is_empty()
            || !candidate.has_git_snapshot_keepalive;
    };
    let Some(resume) = record.provider_resume.as_ref() else {
        return false;
    };
    if candidate.complete_lineage_authorization_sha256.is_empty()
        || record.provider_job_id.as_deref() != Some(record.operation_id.as_str())
        || resume.job_id != record.operation_id
        || resume.state != JobState::Cleaned
        || !resume.cleanup_requested
    {
        return false;
    }
    if require_keepalive_released {
        return snapshot.phase == GithubGitSnapshotPhaseV1::KeepaliveReleased
            && snapshot.keepalive_release_authorization_sha256.as_deref()
                == Some(candidate.complete_lineage_authorization_sha256.as_str());
    }
    match snapshot.phase {
        GithubGitSnapshotPhaseV1::SourceDeleted
        | GithubGitSnapshotPhaseV1::SourceAbsent
        | GithubGitSnapshotPhaseV1::SourceConflict => {
            snapshot.keepalive_release_authorization_sha256.is_none()
        }
        GithubGitSnapshotPhaseV1::KeepaliveReleaseIntent
        | GithubGitSnapshotPhaseV1::KeepaliveReleased => {
            snapshot.keepalive_release_authorization_sha256.as_deref()
                == Some(candidate.complete_lineage_authorization_sha256.as_str())
        }
        _ => false,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one recovery-replayable transaction publishes consumed markers before exact tree deletion"
)]
fn finish_prune_transaction(
    store: &JobStore,
    layout: &AdminLayout,
    transaction_sha256: &str,
    transaction: &PruneTransactionV1,
) -> Result<(), JobStoreError> {
    validate_prune_plan_shape(&transaction.plan)?;
    let tombstone_directory = admin_tombstone_locked_directory(layout)?;
    let consumed_operation_directory = consumed_operation_locked_directory(store, layout)?;
    let mut tombstones = Vec::with_capacity(transaction.plan.candidates.len());
    let mut consumed_operations = Vec::with_capacity(transaction.plan.candidates.len());
    let mut removals = Vec::with_capacity(transaction.plan.candidates.len());
    for candidate in &transaction.plan.candidates {
        if !candidate.operation_id.is_empty() {
            let marker = ConsumedOperationV1 {
                schema_version: CONSUMED_OPERATION_SCHEMA_VERSION,
                operation_id: candidate.operation_id.clone(),
                local_job_id: candidate.local_job_id.clone(),
            };
            let bytes = encode_bounded_json(
                "consumed operation marker bytes",
                &marker,
                8 * 1024,
                "encode consumed operation marker",
            )?;
            consumed_operations.push((
                consumed_operation_path(store, &candidate.operation_id),
                bytes,
            ));
        }
        let tombstone = PruneTombstoneV1 {
            schema_version: PRUNE_TOMBSTONE_SCHEMA_VERSION,
            pruned_at_ms: transaction.pruned_at_ms,
            transaction_sha256: transaction_sha256.to_owned(),
            candidate: candidate.clone(),
        };
        let bytes = encode_bounded_json(
            "prune tombstone bytes",
            &tombstone,
            64 * 1024,
            "encode prune tombstone",
        )?;
        let path = layout.tombstones.join(format!(
            "{}-{:0REVISION_DIGITS$}-{}.json",
            candidate.local_job_id.as_str(),
            candidate.revision,
            candidate.revision_sha256
        ));
        let job_path = store.version_root().join(candidate.local_job_id.as_str());
        match fs::symlink_metadata(&job_path) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                verify_exact_prune_tombstone(&path, &bytes)?;
                tombstones.push((path, bytes));
                continue;
            }
            Err(source) => return Err(io_error("inspect prune job directory", source)),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(JobStoreError::MalformedLayout {
                    reason: "prune target is linked or not a directory",
                });
            }
            Ok(_) => {}
        }
        let locked = store.lock_job_unchecked(&candidate.local_job_id, false)?;
        recover_revision_staging(&locked)?;
        validate_prune_candidate_against_locked(
            store,
            candidate,
            transaction.plan.terminal_before_ms,
            &locked,
            true,
        )?;
        let expected_identity =
            DirectoryFilesystemIdentity::capture(&job_path).map_err(|error| {
                retained_directory_error("capture exact job tree for prune", &error)
            })?;
        drop(locked);
        let removal = prepare_owned_job_tree_removal(&job_path, &expected_identity)?;
        tombstones.push((path, bytes));
        removals.push((candidate.local_job_id.clone(), job_path, removal));
    }

    // No tree is touched until every candidate, artifact closure, release proof, identity, and
    // already-absent tombstone has passed exact preflight. Operation consumption is published
    // first, so a crash between removals can never make a one-use provider operation vacant.
    for (path, bytes) in &consumed_operations {
        publish_managed_bytes(&consumed_operation_directory, path, bytes, 8 * 1024)?;
    }
    for (path, bytes) in &tombstones {
        publish_managed_bytes(&tombstone_directory, path, bytes, 64 * 1024)?;
    }
    for (_, _, removal) in removals {
        remove_owned_job_tree(removal)?;
    }
    for candidate in &transaction.plan.candidates {
        let job_path = store.version_root().join(candidate.local_job_id.as_str());
        match fs::symlink_metadata(&job_path) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("confirm pruned job absence", source)),
            Ok(_) => {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "prune job tree remains after exact removal",
                });
            }
        }
    }
    let version_guard = open_private_directory_if_present(
        &store.version_root(),
        "prune store-version root is linked or not a directory",
    )?
    .ok_or(JobStoreError::MalformedLayout {
        reason: "prune store-version root disappeared before final sync",
    })?;
    sync_directory(&store.version_root(), &version_guard)?;
    Ok(())
}

fn verify_exact_prune_tombstone(path: &Path, expected: &[u8]) -> Result<(), JobStoreError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(JobStoreError::RecoveryRequired {
                reason: "pruned job is absent without its exact immutable tombstone",
            });
        }
        Err(source) => return Err(io_error("inspect prune tombstone", source)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(JobStoreError::MalformedLayout {
                reason: "prune tombstone is linked or not a regular file",
            });
        }
        Ok(_) => {}
    }
    let actual = read_private_bounded_file(path, 64 * 1024)?;
    if actual != expected {
        return Err(JobStoreError::RecoveryRequired {
            reason: "pruned job tombstone differs from its exact transaction",
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "authorization recovery verifies the complete journal-to-tombstone state machine"
)]
fn reconcile_consumed_prune_release_authorizations(
    store: &JobStore,
    layout: &AdminLayout,
) -> Result<(), JobStoreError> {
    for (authorization_sha256, authorization) in
        scan_active_prune_release_authorizations(&layout.transactions)?
    {
        let mut all_absent = true;
        for candidate in &authorization.plan.candidates {
            let job_path = store.version_root().join(candidate.local_job_id.as_str());
            match fs::symlink_metadata(job_path) {
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(io_error("inspect released prune job", source)),
                Ok(_) => {
                    all_absent = false;
                    break;
                }
            }
        }
        if !all_absent {
            continue;
        }
        let mut transaction_sha256 = None;
        let mut tombstones = BTreeMap::new();
        for candidate in &authorization.plan.candidates {
            let path = layout.tombstones.join(format!(
                "{}-{:0REVISION_DIGITS$}-{}.json",
                candidate.local_job_id.as_str(),
                candidate.revision,
                candidate.revision_sha256
            ));
            // Release checkpoints advance snapshot revisions, so locate the exact tombstone by
            // durable job ID when the authorization's initial revision is no longer final.
            let path = if path.exists() {
                path
            } else {
                find_single_prune_tombstone(&layout.tombstones, &candidate.local_job_id)?
            };
            let bytes = read_private_bounded_file(&path, 64 * 1024)?;
            let tombstone: PruneTombstoneV1 =
                serde_json::from_slice(&bytes).map_err(|source| JobStoreError::Serialization {
                    operation: "decode prune tombstone",
                    source,
                })?;
            let canonical = encode_bounded_json(
                "prune tombstone bytes",
                &tombstone,
                64 * 1024,
                "encode prune tombstone",
            )?;
            if canonical != bytes
                || tombstone.schema_version != PRUNE_TOMBSTONE_SCHEMA_VERSION
                || tombstone.candidate.local_job_id != candidate.local_job_id
                || tombstone.candidate.complete_lineage_authorization_sha256
                    != candidate.complete_lineage_authorization_sha256
                || tombstone.candidate.parent_job_id != candidate.parent_job_id
                || tombstone.candidate.child_job_ids != candidate.child_job_ids
                || tombstone.candidate.attempt != candidate.attempt
            {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "prune release authorization lacks its exact lineage tombstone",
                });
            }
            if transaction_sha256
                .replace(tombstone.transaction_sha256.clone())
                .is_some_and(|previous| previous != tombstone.transaction_sha256)
            {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "prune release authorization spans multiple deletion transactions",
                });
            }
            tombstones.insert(tombstone.candidate.local_job_id.clone(), tombstone);
        }
        let transaction_sha256 = transaction_sha256.ok_or_else(|| {
            invalid_record("prune release authorization contains no candidate tombstones")
        })?;
        let transaction_path = layout
            .transactions
            .join(format!("prune-{transaction_sha256}.json"));
        let (_, transaction) = read_admin_transaction(&transaction_path)?;
        let AdminTransactionV1::Prune(transaction) = transaction else {
            return Err(JobStoreError::RecoveryRequired {
                reason: "prune release tombstone names another transaction kind",
            });
        };
        let completion = layout
            .transactions
            .join(format!("prune-{transaction_sha256}.done"));
        let completion_bytes = read_private_bounded_file(&completion, SHA256_HEX_BYTES as u64 + 1)?;
        if completion_bytes != format!("{transaction_sha256}\n").as_bytes()
            || !prune_plans_share_stable_authority(&authorization.plan, &transaction.plan)
            || transaction.plan.candidates.len() != tombstones.len()
            || transaction.plan.candidates.iter().any(|candidate| {
                tombstones
                    .get(&candidate.local_job_id)
                    .is_none_or(|tombstone| tombstone.candidate != *candidate)
            })
        {
            return Err(JobStoreError::RecoveryRequired {
                reason: "completed prune differs from its durable release authorization",
            });
        }
        publish_prune_release_consumed(layout, &authorization_sha256)?;
    }
    Ok(())
}

fn parse_prune_tombstone_filename(path: &Path) -> Result<(LocalJobId, u64, String), JobStoreError> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(JobStoreError::MalformedLayout {
            reason: "prune tombstone filename is not UTF-8",
        })?;
    let body = name
        .strip_suffix(".json")
        .ok_or(JobStoreError::MalformedLayout {
            reason: "prune tombstone filename is malformed",
        })?;
    let (owner_and_revision, revision_sha256) =
        body.rsplit_once('-')
            .ok_or(JobStoreError::MalformedLayout {
                reason: "prune tombstone filename is malformed",
            })?;
    let (local_job_id, revision_text) =
        owner_and_revision
            .rsplit_once('-')
            .ok_or(JobStoreError::MalformedLayout {
                reason: "prune tombstone filename is malformed",
            })?;
    if revision_text.len() != REVISION_DIGITS
        || !revision_text.bytes().all(|byte| byte.is_ascii_digit())
        || !is_sha256(revision_sha256)
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "prune tombstone filename is malformed",
        });
    }
    let revision = revision_text
        .parse::<u64>()
        .map_err(|_| JobStoreError::MalformedLayout {
            reason: "prune tombstone filename is malformed",
        })?;
    if revision == 0 || format!("{revision:0REVISION_DIGITS$}") != revision_text {
        return Err(JobStoreError::MalformedLayout {
            reason: "prune tombstone filename is malformed",
        });
    }
    let local_job_id =
        LocalJobId::new(local_job_id.to_owned()).map_err(|_| JobStoreError::MalformedLayout {
            reason: "prune tombstone filename has an invalid local job identifier",
        })?;
    Ok((local_job_id, revision, revision_sha256.to_owned()))
}

fn read_validated_prune_tombstone(path: &Path) -> Result<PruneTombstoneV1, JobStoreError> {
    let (filename_job_id, filename_revision, filename_sha256) =
        parse_prune_tombstone_filename(path)?;
    inspect_private_revision_file(path, 64 * 1024)?;
    let bytes = read_private_bounded_file(path, 64 * 1024)?;
    let tombstone: PruneTombstoneV1 =
        serde_json::from_slice(&bytes).map_err(|source| JobStoreError::Serialization {
            operation: "decode prune tombstone",
            source,
        })?;
    let canonical = encode_bounded_json(
        "prune tombstone bytes",
        &tombstone,
        64 * 1024,
        "encode prune tombstone",
    )?;
    let candidate = &tombstone.candidate;
    let children = candidate.child_job_ids.iter().collect::<BTreeSet<_>>();
    if canonical != bytes
        || tombstone.schema_version != PRUNE_TOMBSTONE_SCHEMA_VERSION
        || !is_sha256(&tombstone.transaction_sha256)
        || candidate.local_job_id != filename_job_id
        || candidate.revision != filename_revision
        || candidate.revision_sha256 != filename_sha256
        || candidate.operation_id.is_empty()
        || !is_sha256(&candidate.revision_sha256)
        || (!candidate.complete_lineage_authorization_sha256.is_empty()
            && !is_sha256(&candidate.complete_lineage_authorization_sha256))
        || (candidate.has_git_snapshot_keepalive
            && candidate.complete_lineage_authorization_sha256.is_empty())
        || candidate.parent_job_id.as_ref() == Some(&candidate.local_job_id)
        || candidate
            .child_job_ids
            .iter()
            .any(|child| child == &candidate.local_job_id)
        || children.len() != candidate.child_job_ids.len()
    {
        return Err(JobStoreError::MalformedLayout {
            reason: "prune tombstone identity or canonical shape is invalid",
        });
    }
    validate_identifier("prune.operation_id", &candidate.operation_id)?;
    Ok(tombstone)
}

pub(super) fn reject_tombstoned_local_job_id(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), JobStoreError> {
    let tombstones = store.version_root().join(TOMBSTONES_DIRECTORY);
    let Some(_guard) = open_private_directory_if_present(
        &tombstones,
        "admin tombstones entry is linked or not a directory",
    )?
    else {
        return Ok(());
    };
    let mut matching = 0_usize;
    let mut entries = 0_usize;
    for entry in fs::read_dir(&tombstones)
        .map_err(|source| io_error("read prune tombstones for job creation", source))?
    {
        entries = entries.saturating_add(1);
        if entries > MAX_ADMIN_TRANSACTION_FILES {
            return Err(JobStoreError::BoundExceeded {
                kind: "prune tombstones",
                maximum: MAX_ADMIN_TRANSACTION_FILES as u64,
            });
        }
        let path = entry
            .map_err(|source| io_error("read prune tombstone creation entry", source))?
            .path();
        let (owner, _, _) = parse_prune_tombstone_filename(&path)?;
        if owner != *local_job_id {
            continue;
        }
        drop(read_validated_prune_tombstone(&path)?);
        matching = matching.saturating_add(1);
    }
    if matching > 1 {
        return Err(JobStoreError::RecoveryRequired {
            reason: "multiple prune tombstones match one local job identifier",
        });
    }
    if matching == 1 {
        return Err(invalid_record(
            "local job identifier was permanently consumed by a pruned job",
        ));
    }
    Ok(())
}

fn find_single_prune_tombstone(
    tombstones: &Path,
    local_job_id: &LocalJobId,
) -> Result<PathBuf, JobStoreError> {
    let mut found = None;
    for entry in fs::read_dir(tombstones)
        .map_err(|source| io_error("read prune tombstones for release recovery", source))?
    {
        let path = entry
            .map_err(|source| io_error("read prune tombstone recovery entry", source))?
            .path();
        let (owner, _, _) = parse_prune_tombstone_filename(&path)?;
        if owner == *local_job_id && found.replace(path).is_some() {
            return Err(JobStoreError::RecoveryRequired {
                reason: "multiple prune tombstones match one released job",
            });
        }
    }
    found.ok_or(JobStoreError::RecoveryRequired {
        reason: "released prune job is absent without a tombstone",
    })
}

#[cfg(windows)]
struct OwnedJobTreeRemoval {
    directory: File,
}

#[cfg(windows)]
fn prepare_owned_job_tree_removal(
    path: &Path,
    expected_identity: &DirectoryFilesystemIdentity,
) -> Result<OwnedJobTreeRemoval, JobStoreError> {
    use rustferry_core::{
        directory_identity_from_file, windows_private_directory::open_private_directory,
    };

    let directory = open_private_directory(path)
        .map_err(|error| windows_security_error("retain exact job tree for prune", &error))?;
    let retained_identity = directory_identity_from_file(&directory).map_err(|error| {
        retained_directory_error("identify retained exact job tree for prune", &error)
    })?;
    if &retained_identity != expected_identity {
        return Err(JobStoreError::RecoveryRequired {
            reason: "prune job tree changed during its lock-to-removal transition",
        });
    }
    Ok(OwnedJobTreeRemoval { directory })
}

#[cfg(windows)]
fn remove_owned_job_tree(removal: OwnedJobTreeRemoval) -> Result<(), JobStoreError> {
    use rustferry_core::windows_private_directory::remove_private_directory_tree_handle;

    remove_private_directory_tree_handle(removal.directory)
        .map_err(|error| windows_security_error("remove exact owned job tree", &error))
}

#[cfg(unix)]
struct OwnedJobTreeRemoval {
    path: PathBuf,
    retained: RetainedDirectoryIdentity,
}

#[cfg(unix)]
fn prepare_owned_job_tree_removal(
    path: &Path,
    expected_identity: &DirectoryFilesystemIdentity,
) -> Result<OwnedJobTreeRemoval, JobStoreError> {
    let retained = RetainedDirectoryIdentity::open(path)
        .map_err(|error| retained_directory_error("retain exact job tree for prune", &error))?;
    if retained.identity() != expected_identity {
        return Err(JobStoreError::RecoveryRequired {
            reason: "prune job tree changed during its lock-to-removal transition",
        });
    }
    retained
        .verify_path(path)
        .map_err(|error| retained_directory_error("verify exact job tree for prune", &error))?;
    Ok(OwnedJobTreeRemoval {
        path: path.to_path_buf(),
        retained,
    })
}

#[cfg(unix)]
fn remove_owned_job_tree(removal: OwnedJobTreeRemoval) -> Result<(), JobStoreError> {
    let OwnedJobTreeRemoval { path, retained } = removal;
    let parent = path.parent().ok_or(JobStoreError::MalformedLayout {
        reason: "prune job directory has no parent",
    })?;
    let name = path.file_name().ok_or(JobStoreError::MalformedLayout {
        reason: "prune job directory has no filename",
    })?;
    let parent_dir = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .map_err(|source| io_error("open capability prune parent", source))?;
    retained
        .verify_path(&path)
        .map_err(|error| retained_directory_error("reverify exact job tree for prune", &error))?;
    parent_dir
        .remove_dir_all(name)
        .map_err(|source| io_error("remove capability-bound owned job tree", source))
}

#[cfg(all(not(unix), not(windows)))]
struct OwnedJobTreeRemoval;

#[cfg(all(not(unix), not(windows)))]
fn prepare_owned_job_tree_removal(
    _path: &Path,
    _expected_identity: &DirectoryFilesystemIdentity,
) -> Result<OwnedJobTreeRemoval, JobStoreError> {
    Err(JobStoreError::RecoveryRequired {
        reason: "secure job-tree pruning is unsupported on this platform",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn remove_owned_job_tree(_removal: OwnedJobTreeRemoval) -> Result<(), JobStoreError> {
    Err(JobStoreError::RecoveryRequired {
        reason: "secure job-tree pruning is unsupported on this platform",
    })
}

#[cfg(unix)]
fn recover_one_managed_staging(directory: &LockedJob, path: &Path) -> Result<(), JobStoreError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let staging = options
        .open(path)
        .map_err(|source| io_error("open managed staging for recovery", source))?;
    let metadata = staging
        .metadata()
        .map_err(|source| io_error("inspect managed staging for recovery", source))?;
    match metadata.nlink() {
        1 => remove_owned_unix_staging(&staging, path),
        2 => {
            verify_unix_private_file(&staging, path, 2)?;
            let mut matched = false;
            for entry in fs::read_dir(&directory.revisions)
                .map_err(|source| io_error("scan managed publication pair", source))?
            {
                let candidate = entry
                    .map_err(|source| io_error("read managed publication pair", source))?
                    .path();
                if candidate == path
                    || is_revision_staging_name(
                        &candidate.file_name().unwrap_or_default().to_string_lossy(),
                    )
                {
                    continue;
                }
                let final_file = options
                    .open(&candidate)
                    .map_err(|source| io_error("open managed publication final", source))?;
                if verify_file_identity(&staging, &candidate).is_ok()
                    && verify_unix_private_file(&final_file, &candidate, 2).is_ok()
                {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(JobStoreError::RecoveryRequired {
                    reason: "managed staging publication pair has no exact final link",
                });
            }
            fs::remove_file(path)
                .map_err(|source| io_error("remove managed staging publication link", source))
        }
        _ => Err(JobStoreError::RecoveryRequired {
            reason: "managed staging has an unsupported hard-link count",
        }),
    }
}

#[cfg(all(not(unix), not(windows)))]
fn recover_one_managed_staging(_directory: &LockedJob, _path: &Path) -> Result<(), JobStoreError> {
    Err(JobStoreError::RecoveryRequired {
        reason: "managed staging recovery is unsupported on this platform",
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::super::tests::{
        StoreFixture, advance_through_local_validation, checkpoint_through_github_success,
        github_cleaned_resume, persist_providerless_artifact_ready,
    };
    use super::*;

    enum SingleAttemptJobLockProbe {
        Acquired(LockedJob),
        Busy,
        Error(JobStoreError),
    }

    fn probe_job_lock_once(
        store: &JobStore,
        local_job_id: &LocalJobId,
    ) -> SingleAttemptJobLockProbe {
        match store.lock_job_unchecked(local_job_id, false) {
            Ok(locked) => SingleAttemptJobLockProbe::Acquired(locked),
            Err(JobStoreError::JobBusy { .. }) => SingleAttemptJobLockProbe::Busy,
            Err(error) => SingleAttemptJobLockProbe::Error(error),
        }
    }

    fn expect_busy_lock_probe(probe: SingleAttemptJobLockProbe) {
        match probe {
            SingleAttemptJobLockProbe::Busy => {}
            SingleAttemptJobLockProbe::Acquired(_) => {
                panic!("single-attempt candidate lock probe unexpectedly acquired the lock")
            }
            SingleAttemptJobLockProbe::Error(error) => {
                panic!("single-attempt candidate lock probe failed: {error:?}")
            }
        }
    }

    fn expect_acquired_lock_probe(probe: SingleAttemptJobLockProbe) -> LockedJob {
        match probe {
            SingleAttemptJobLockProbe::Acquired(locked) => locked,
            SingleAttemptJobLockProbe::Busy => {
                panic!("single-attempt candidate lock probe remained busy after release")
            }
            SingleAttemptJobLockProbe::Error(error) => {
                panic!("single-attempt candidate lock probe failed after release: {error:?}")
            }
        }
    }

    struct PrunePublicationTestControlReset;

    impl Drop for PrunePublicationTestControlReset {
        fn drop(&mut self) {
            *PRUNE_PUBLICATION_LOCK_TEST_CONTROL
                .lock()
                .expect("prune-publication test-control lock is not poisoned") = None;
        }
    }

    fn persist_failed_parent(fixture: &StoreFixture, local_job_id: &str) -> StoredJobV1 {
        let first = fixture.record(local_job_id, 100);
        fixture.store.create(&first).unwrap();
        mark_job_failed(fixture, &first.local_job_id)
    }

    fn mark_job_failed(fixture: &StoreFixture, local_job_id: &LocalJobId) -> StoredJobV1 {
        fixture
            .store
            .update(local_job_id, |previous| {
                let mut failed = previous.clone();
                failed.revision += 1;
                failed.updated_at_ms += 1;
                failed.state = StoredJobState::Failed;
                failed.last_confirmed_state = Some(StoredJobState::Failed);
                failed.terminal_outcome = Some(StoredBuildOutcome::Failed);
                failed.failure = Some(StoredFailureV1 {
                    code: "controller.failed".to_owned(),
                    retryable: true,
                });
                Ok(failed)
            })
            .unwrap();
        fixture.store.latest(local_job_id).unwrap()
    }

    fn retry_child(
        fixture: &StoreFixture,
        parent: &StoredJobV1,
        local_job_id: &str,
        operation_id: &str,
    ) -> StoredJobV1 {
        let mut child = fixture.record(local_job_id, parent.updated_at_ms + 1);
        child.created_at_ms = parent.updated_at_ms + 1;
        child.updated_at_ms = child.created_at_ms;
        child.operation_id = operation_id.to_owned();
        child.request.operation_id = operation_id.to_owned();
        child.request_sha256 = canonical_request_sha256(&child.request).unwrap();
        child.semantic_retry_sha256 = canonical_retry_template_sha256_v1(&child.request).unwrap();
        child.retry_lineage.attempt = parent.retry_lineage.attempt + 1;
        child.retry_lineage.parent_job_id = Some(parent.local_job_id.clone());
        child
    }

    fn event(
        source: ManagedEventSource,
        source_sequence: u64,
        code: &str,
    ) -> ManagedJobEventInputV1 {
        ManagedJobEventInputV1 {
            source,
            source_sequence: Some(source_sequence),
            source_event_sha256: Some(match source {
                ManagedEventSource::Controller => "a".repeat(64),
                ManagedEventSource::Provider => "b".repeat(64),
                ManagedEventSource::Worker => "c".repeat(64),
            }),
            occurred_at_ms: 101,
            phase: Some("compile".to_owned()),
            level: ManagedEventLevel::Info,
            code: code.to_owned(),
            message: Some("sanitized lifecycle event".to_owned()),
        }
    }

    fn assigned_event(
        local_job_id: &LocalJobId,
        sequence: u64,
        input: &ManagedJobEventInputV1,
    ) -> ManagedJobEventV1 {
        ManagedJobEventV1 {
            schema_version: MANAGED_EVENT_SCHEMA_VERSION,
            local_job_id: local_job_id.clone(),
            sequence,
            occurred_at_ms: input.occurred_at_ms,
            phase: input.phase.clone(),
            source: input.source,
            source_sequence: input.source_sequence,
            source_event_sha256: input.source_event_sha256.clone(),
            level: input.level,
            code: input.code.clone(),
            message: input.message.clone(),
        }
    }

    fn fail_managed_event_publication_at(path: PathBuf) {
        let mut installed = MANAGED_EVENT_PUBLICATION_TEST_CONTROL
            .lock()
            .expect("managed-event publication test-control lock is not poisoned");
        assert!(installed.replace(path).is_none());
    }

    fn persist_local_artifact(
        fixture: &StoreFixture,
        local_job_id: &str,
        bytes: &[u8],
    ) -> (ManagedArtifactRefV1, StoredArtifactV1, PathBuf) {
        let path = PathBuf::from(fixture.local_artifact_path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        let identity = RegularFileFilesystemIdentity::capture(&path)
            .unwrap()
            .to_string();
        let mut artifact = fixture.artifact(false);
        artifact.record.size = bytes.len() as u64;
        artifact.record.sha256 = sha256_hex(bytes);
        let ready = persist_providerless_artifact_ready(fixture, local_job_id, vec![artifact]);
        let mut downloading = ready.clone();
        downloading.revision += 1;
        downloading.updated_at_ms += 1;
        downloading.state = StoredJobState::Downloading;
        downloading.artifacts[0].download_destination = Some(path.to_string_lossy().into_owned());
        downloading.artifacts[0].download_parent_identity =
            Some(fixture.local_artifact_parent_identity());
        fixture.store.append(&downloading).unwrap();
        let mut published = downloading;
        published.revision += 1;
        published.updated_at_ms += 1;
        published.artifacts[0].local_path = Some(path.to_string_lossy().into_owned());
        published.artifacts[0].local_file_identity = Some(identity);
        fixture.store.append(&published).unwrap();
        let stored = published.artifacts[0].clone();
        (
            ManagedArtifactRefV1 {
                local_job_id: published.local_job_id,
                provider_artifact_id: stored.record.artifact_id.clone(),
            },
            stored,
            path,
        )
    }

    fn publish_legacy_job_revision(fixture: &StoreFixture, record: &StoredJobV1) -> String {
        let locked = fixture
            .store
            .lock_job_unchecked(&record.local_job_id, true)
            .unwrap();
        let bytes = encode_legacy_revision(record).unwrap();
        let sha256 = sha256_hex(&bytes);
        let path = locked
            .revisions
            .join(revision_filename(record.revision, &sha256));
        publish_managed_bytes(&locked, &path, &bytes, MAX_JOB_REVISION_BYTES).unwrap();
        sha256
    }

    #[test]
    fn operation_lease_conflicts_cross_kind_and_releases_logs_before_cancel() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-operation-lease", 100);
        fixture.store.create(&record).unwrap();

        let lease = fixture
            .store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build)
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel),
            Err(JobStoreError::JobBusy { .. })
        ));
        assert!(matches!(
            fixture
                .store
                .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Logs),
            Err(JobStoreError::JobBusy { .. })
        ));
        drop(lease);
        let logs = fixture
            .store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Logs)
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Retry),
            Err(JobStoreError::JobBusy { .. })
        ));
        // Follow mode releases after each bounded poll, before sleeping, so cancellation wins.
        drop(logs);
        fixture
            .store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel)
            .unwrap();
    }

    #[test]
    fn operation_lease_is_bound_to_its_originating_store() {
        let left = StoreFixture::new();
        let right = StoreFixture::new();
        let left_record = left.record("job-operation-store-owner", 100);
        let right_record = right.record("job-operation-store-owner", 100);
        left.store.create(&left_record).unwrap();
        right.store.create(&right_record).unwrap();
        let lease = left
            .store
            .try_acquire_operation_lease(
                &left_record.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let left_locked = left
            .store
            .lock_job(&left_record.local_job_id, false)
            .unwrap();
        let right_locked = right
            .store
            .lock_job(&right_record.local_job_id, false)
            .unwrap();

        lease
            .validate_owner(
                &left.store,
                &left_locked,
                &left_record.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        assert!(matches!(
            lease.validate_owner(
                &right.store,
                &right_locked,
                &right_record.local_job_id,
                JobOperationKind::ArtifactRemoval,
            ),
            Err(JobStoreError::InvalidRecord { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn operation_lease_rejects_a_reopened_replacement_store() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-operation-replaced-store", 100);
        fixture.store.create(&record).unwrap();
        let lease = fixture
            .store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Retry)
            .unwrap();
        let root = fixture.store.root().to_path_buf();
        let moved = root.with_extension("retained-by-stale-lease");
        fs::rename(&root, &moved).unwrap();
        let replacement = JobStore::open_at(&root).unwrap();
        let replacement_record = fixture.record("job-operation-replaced-store", 100);
        replacement.create(&replacement_record).unwrap();
        let replacement_locked = replacement
            .lock_job(&replacement_record.local_job_id, false)
            .unwrap();

        assert!(matches!(
            lease.validate_owner(
                &replacement,
                &replacement_locked,
                &replacement_record.local_job_id,
                JobOperationKind::Retry,
            ),
            Err(JobStoreError::InvalidRecord { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn foreign_store_lease_cannot_remove_artifact_while_owner_store_is_busy() {
        let left = StoreFixture::new();
        let right = StoreFixture::new();
        let (left_ref, _, _) =
            persist_local_artifact(&left, "job-artifact-foreign-lease", b"left artifact");
        let (right_ref, _, right_path) =
            persist_local_artifact(&right, "job-artifact-foreign-lease", b"right artifact");
        let foreign_lease = left
            .store
            .try_acquire_operation_lease(&left_ref.local_job_id, JobOperationKind::ArtifactRemoval)
            .unwrap();
        let _owner_busy = right
            .store
            .try_acquire_operation_lease(&right_ref.local_job_id, JobOperationKind::Build)
            .unwrap();

        assert!(matches!(
            right
                .store
                .remove_managed_artifact(&foreign_lease, &right_ref, 200),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        assert_eq!(fs::read(&right_path).unwrap(), b"right artifact");
        assert_eq!(
            right
                .store
                .resolve_managed_artifact(
                    &right_ref.provider_artifact_id,
                    Some(&right_ref.local_job_id),
                )
                .unwrap()
                .removal_state,
            ManagedArtifactRemovalState::Available
        );
    }

    #[cfg(windows)]
    #[test]
    fn prune_removal_handle_must_match_the_locked_job_identity() {
        let expected = StoreFixture::new();
        let target = StoreFixture::new();
        let expected_record = expected.record("job-prune-handle-owner", 100);
        let target_record = target.record("job-prune-handle-owner", 100);
        expected.store.create(&expected_record).unwrap();
        target.store.create(&target_record).unwrap();
        let expected_path = expected
            .store
            .version_root()
            .join(expected_record.local_job_id.as_str());
        let target_path = target
            .store
            .version_root()
            .join(target_record.local_job_id.as_str());
        let expected_identity = DirectoryFilesystemIdentity::capture(&expected_path).unwrap();

        assert!(matches!(
            prepare_owned_job_tree_removal(&target_path, &expected_identity),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert_eq!(
            target
                .store
                .latest(&target_record.local_job_id)
                .unwrap()
                .local_job_id,
            target_record.local_job_id
        );
    }

    #[test]
    fn managed_events_assign_one_global_sequence_across_concurrent_sources() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-events", 100);
        fixture.store.create(&record).unwrap();
        let store = Arc::new(fixture.store.clone());
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |input: ManagedJobEventInputV1| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let local_job_id = record.local_job_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.append_managed_events(&local_job_id, 101, &[input])
            })
        };
        let controller = event(ManagedEventSource::Controller, 1, "controller.started");
        let provider = event(ManagedEventSource::Provider, 1, "provider.queued");
        let left = spawn(controller.clone());
        let right = spawn(provider.clone());
        barrier.wait();
        left.join().unwrap().unwrap();
        right.join().unwrap().unwrap();

        let page = store
            .read_managed_events(&record.local_job_id, 0, 10)
            .unwrap();
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.source)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([ManagedEventSource::Controller, ManagedEventSource::Provider])
        );
        assert!(
            page.events
                .iter()
                .all(|event| event.phase.as_deref() == Some("compile"))
        );

        let replay = store
            .append_managed_events(&record.local_job_id, 102, std::slice::from_ref(&provider))
            .unwrap();
        assert_eq!(replay.appended, 0);
        assert_eq!(replay.already_present, 1);
        assert_eq!(
            store
                .read_managed_events(&record.local_job_id, 0, 10)
                .unwrap()
                .events
                .len(),
            2
        );
        let mut conflicting = provider;
        conflicting.message = Some("different sanitized payload".to_owned());
        assert!(matches!(
            store.append_managed_events(&record.local_job_id, 103, &[conflicting]),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let mut secret = controller;
        secret.source_sequence = Some(2);
        secret.message = Some("Authorization: Bearer raw-secret".to_owned());
        assert!(matches!(
            store.append_managed_events(&record.local_job_id, 104, &[secret]),
            Err(JobStoreError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn managed_event_batch_preflight_rejects_late_conflict_without_a_prefix() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-preflight", 100);
        fixture.store.create(&record).unwrap();
        let provider = event(ManagedEventSource::Provider, 1, "provider.queued");
        fixture
            .store
            .append_managed_events(&record.local_job_id, 101, std::slice::from_ref(&provider))
            .unwrap();
        let before = fixture.store.latest(&record.local_job_id).unwrap();
        let controller = event(ManagedEventSource::Controller, 1, "controller.started");
        let mut conflicting = provider;
        conflicting.message = Some("different sanitized payload".to_owned());

        assert!(matches!(
            fixture.store.append_managed_events(
                &record.local_job_id,
                102,
                &[controller, conflicting],
            ),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let after = fixture.store.latest(&record.local_job_id).unwrap();
        assert_eq!(after.revision, before.revision);
        let page = fixture
            .store
            .read_managed_events(&record.local_job_id, 0, 10)
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].source, ManagedEventSource::Provider);
    }

    #[test]
    fn managed_event_batch_rejects_internal_conflict_before_binding_location() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-internal-conflict", 100);
        fixture.store.create(&record).unwrap();
        let first = event(ManagedEventSource::Provider, 1, "provider.queued");
        let mut conflicting = first.clone();
        conflicting.message = Some("different sanitized payload".to_owned());

        assert!(matches!(
            fixture
                .store
                .append_managed_events(&record.local_job_id, 101, &[first, conflicting],),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let latest = fixture.store.latest(&record.local_job_id).unwrap();
        assert_eq!(latest.revision, record.revision);
        assert_eq!(latest.log_location, None);
        assert!(
            !fixture
                .store
                .version_root()
                .join(record.local_job_id.as_str())
                .join(EVENTS_DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn managed_event_batch_requires_replay_identity_before_binding_location() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-batch-identity", 100);
        fixture.store.create(&record).unwrap();
        let first = event(ManagedEventSource::Controller, 1, "controller.started");
        let mut unsequenced = event(ManagedEventSource::Worker, 1, "worker.compiling");
        unsequenced.source_sequence = None;
        unsequenced.source_event_sha256 = None;

        assert!(matches!(
            fixture
                .store
                .append_managed_events(&record.local_job_id, 101, &[first, unsequenced],),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let latest = fixture.store.latest(&record.local_job_id).unwrap();
        assert_eq!(latest.revision, record.revision);
        assert_eq!(latest.log_location, None);
        assert!(
            !fixture
                .store
                .version_root()
                .join(record.local_job_id.as_str())
                .join(EVENTS_DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn managed_event_batch_rejects_malformed_source_identity_without_writes() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-malformed-identity", 100);
        fixture.store.create(&record).unwrap();
        let first = event(ManagedEventSource::Controller, 1, "controller.started");
        let mut malformed = event(ManagedEventSource::Worker, 1, "worker.compiling");
        malformed.source_event_sha256 = None;

        assert!(matches!(
            fixture
                .store
                .append_managed_events(&record.local_job_id, 101, &[first, malformed],),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let latest = fixture.store.latest(&record.local_job_id).unwrap();
        assert_eq!(latest.revision, record.revision);
        assert_eq!(latest.log_location, None);
        assert!(
            !fixture
                .store
                .version_root()
                .join(record.local_job_id.as_str())
                .join(EVENTS_DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn managed_event_batch_bound_fails_before_binding_location() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-batch-bound", 100);
        fixture.store.create(&record).unwrap();
        let events = (1..=MAX_MANAGED_EVENT_BATCH + 1)
            .map(|sequence| {
                event(
                    ManagedEventSource::Controller,
                    u64::try_from(sequence).unwrap(),
                    "controller.progress",
                )
            })
            .collect::<Vec<_>>();

        assert!(matches!(
            fixture
                .store
                .append_managed_events(&record.local_job_id, 101, &events),
            Err(JobStoreError::BoundExceeded {
                kind: "managed event append batch",
                ..
            })
        ));
        let latest = fixture.store.latest(&record.local_job_id).unwrap();
        assert_eq!(latest.revision, record.revision);
        assert_eq!(latest.log_location, None);
    }

    #[test]
    fn managed_event_batch_replay_recovers_an_injected_durable_prefix() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication tests serialize without poisoning");
        let fixture = StoreFixture::new();
        let record = fixture.record("job-managed-event-prefix-replay", 100);
        fixture.store.create(&record).unwrap();
        let first = event(ManagedEventSource::Controller, 1, "controller.started");
        let second = event(ManagedEventSource::Provider, 1, "provider.queued");
        let second_record = assigned_event(&record.local_job_id, 2, &second);
        let second_bytes = second_record.validate_for(&record.local_job_id).unwrap();
        let second_path = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str())
            .join(EVENTS_DIRECTORY)
            .join(managed_event_filename(2, &sha256_hex(&second_bytes)));
        fail_managed_event_publication_at(second_path);

        assert!(matches!(
            fixture.store.append_managed_events(
                &record.local_job_id,
                101,
                &[first.clone(), second.clone()],
            ),
            Err(JobStoreError::CommitUncertain { .. })
        ));
        let prefix = fixture
            .store
            .read_managed_events(&record.local_job_id, 0, 10)
            .unwrap();
        assert_eq!(prefix.events.len(), 1);
        assert_eq!(prefix.events[0].as_input(), first);

        let recovered = fixture
            .store
            .append_managed_events(&record.local_job_id, 102, &[first, second])
            .unwrap();
        assert_eq!(recovered.appended, 1);
        assert_eq!(recovered.already_present, 1);
        assert_eq!(
            recovered
                .assigned
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let page = fixture
            .store
            .read_managed_events(&record.local_job_id, 0, 10)
            .unwrap();
        assert_eq!(page.events.len(), 2);
    }

    #[test]
    fn retry_lineage_is_reciprocal_idempotent_and_mode_bound() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-retry-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-retry-child",
            "operation-retry-child",
        );
        let options = RetryLineageOptionsV1::default();
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        let receipt = fixture
            .store
            .create_retry_lineage(&parent.local_job_id, &retry_lease, &child, &options)
            .unwrap();
        assert_eq!(receipt.child.revision, 1);
        assert_eq!(
            fixture
                .store
                .latest(&parent.local_job_id)
                .unwrap()
                .retry_lineage
                .child_job_ids,
            vec![child.local_job_id.clone()]
        );
        assert_eq!(
            fixture
                .store
                .latest(&child.local_job_id)
                .unwrap()
                .retry_lineage
                .parent_job_id,
            Some(parent.local_job_id.clone())
        );
        let replay = fixture
            .store
            .create_retry_lineage(&parent.local_job_id, &retry_lease, &child, &options)
            .unwrap();
        assert!(replay.parent.already_present && replay.child.already_present);

        let mismatched = RetryLineageOptionsV1 {
            parent_policy: RetryParentPolicyV1::RequireUnsuccessful,
            source_policy: RetrySourcePolicyV1::RecapturedGitSnapshot {
                confirmation_sha256: "d".repeat(64),
                snapshot_consent_sha256: "e".repeat(64),
                source_archive_sha256: "f".repeat(64),
            },
        };
        assert!(matches!(
            fixture.store.create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &mismatched,
            ),
            Err(JobStoreError::RevisionConflict { .. })
        ));
    }

    #[test]
    fn retry_attempt_overflow_fails_closed() {
        let fixture = StoreFixture::new();
        let mut parent = persist_failed_parent(&fixture, "job-retry-overflow-parent");
        let mut child = retry_child(
            &fixture,
            &parent,
            "job-retry-overflow-child",
            "operation-retry-overflow",
        );
        parent.retry_lineage.attempt = u32::MAX;
        parent.retry_lineage.parent_job_id = Some(LocalJobId::new("job-earlier-parent").unwrap());
        child.retry_lineage.attempt = u32::MAX;

        assert!(matches!(
            validate_retry_child(&parent, &child, &RetryLineageOptionsV1::default()),
            Err(JobStoreError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn retry_lease_is_validated_before_child_or_admin_layout_creation() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-retry-lease-first-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-retry-lease-first-child",
            "operation-retry-lease-first-child",
        );
        let wrong_kind = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Build)
            .unwrap();
        let child_path = fixture
            .store
            .version_root()
            .join(child.local_job_id.as_str());
        let transactions = fixture
            .store
            .version_root()
            .join(ADMIN_TRANSACTIONS_DIRECTORY);
        assert!(!child_path.exists());
        assert!(!transactions.exists());

        assert!(matches!(
            fixture.store.create_retry_lineage(
                &parent.local_job_id,
                &wrong_kind,
                &child,
                &RetryLineageOptionsV1::default(),
            ),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        assert!(!child_path.exists());
        assert!(!transactions.exists());
    }

    #[test]
    fn vacant_operation_blocks_competing_initial_create_across_store_handles() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-vacant-operation-owner", 100);
        let vacancy = match fixture
            .store
            .try_acquire_vacant_snapshot_operation_lease(&record.operation_id)
            .unwrap()
        {
            SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
            SnapshotOperationVacancyV1::Owned(_) => panic!("operation unexpectedly owned"),
        };
        let competing_store = JobStore::open_at(fixture.store.root()).unwrap();
        let mut competing = record.clone();
        competing.local_job_id = LocalJobId::new("job-vacant-operation-competitor").unwrap();
        let competing_result = competing_store.create(&competing);
        assert!(
            matches!(
                competing_result,
                Err(JobStoreError::RecoveryRequired { .. } | JobStoreError::Security { .. })
            ),
            "unexpected competing create result: {competing_result:?}"
        );
        let created = fixture
            .store
            .create_with_operation_lease(vacancy, &record)
            .unwrap();
        assert_eq!(created.operation_lease.kind(), JobOperationKind::Build);
        let owner = fixture
            .store
            .snapshot_operation_owner(&record.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(owner.local_job_id, record.local_job_id);
        assert!(competing_store.create(&competing).is_err());
    }

    #[test]
    fn append_cannot_claim_an_empty_job_chain_or_duplicate_an_operation_owner() {
        let fixture = StoreFixture::new();
        let owner = fixture.record("job-empty-chain-operation-owner", 100);
        fixture.store.create(&owner).unwrap();
        let mut competing = owner.clone();
        competing.local_job_id = LocalJobId::new("job-empty-chain-competitor").unwrap();
        let locked = fixture
            .store
            .lock_job_unchecked(&competing.local_job_id, true)
            .unwrap();
        let revisions = locked.revisions.clone();
        drop(locked);

        assert!(matches!(
            fixture.store.append(&competing),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        assert!(scan_revision_files(&revisions).unwrap().is_empty());
        let durable_owner = fixture
            .store
            .snapshot_operation_owner(&owner.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(durable_owner.local_job_id, owner.local_job_id);
    }

    #[test]
    fn snapshot_operation_owner_rejects_staging_without_recovery_writes() {
        let fixture = StoreFixture::new();
        let record = fixture.record("job-owner-read-only-staging", 100);
        fixture.store.create(&record).unwrap();
        let revisions = fixture
            .store
            .version_root()
            .join(record.local_job_id.as_str())
            .join(REVISIONS_DIRECTORY);
        let staging = revisions.join(".revision-11111111111111111111111111111111.tmp");
        let residue = b"incomplete immutable revision";
        fs::write(&staging, residue).unwrap();

        assert!(matches!(
            fixture.store.snapshot_operation_owner(&record.operation_id),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert_eq!(fs::read(&staging).unwrap(), residue);
    }

    #[test]
    fn retry_transaction_recovers_both_sides_after_intent_only_crash() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-retry-crash-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-retry-crash-child",
            "operation-retry-crash",
        );
        let options = RetryLineageOptionsV1::default();
        let parent_next = build_retry_parent_successor(&parent, &child, &options).unwrap();
        let mut entries = {
            let locked = fixture.store.lock_job(&parent.local_job_id, false).unwrap();
            scan_revision_files(&locked.revisions).unwrap()
        };
        let parent_entry = entries.pop().unwrap();
        let transaction = AdminTransactionV1::Retry(Box::new(RetryTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            parent_before_revision: parent.revision,
            parent_before_sha256: parent_entry.sha256,
            parent_next,
            child: child.clone(),
            options,
        }));
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        publish_admin_transaction(&layout, &transaction).unwrap();
        drop(layout);

        assert!(matches!(
            fixture.store.latest(&parent.local_job_id),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        let reopened = JobStore::open_at(fixture.store.root()).unwrap();
        assert_eq!(
            reopened
                .latest(&parent.local_job_id)
                .unwrap()
                .retry_lineage
                .child_job_ids,
            vec![child.local_job_id.clone()]
        );
        assert_eq!(
            reopened
                .latest(&child.local_job_id)
                .unwrap()
                .retry_lineage
                .parent_job_id,
            Some(parent.local_job_id)
        );
    }

    #[test]
    fn retry_recovery_rejects_a_logical_child_with_legacy_envelope_bytes() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-retry-legacy-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-retry-legacy-child",
            "operation-retry-legacy",
        );
        let options = RetryLineageOptionsV1::default();
        let parent_next = build_retry_parent_successor(&parent, &child, &options).unwrap();
        let parent_entry = {
            let locked = fixture.store.lock_job(&parent.local_job_id, false).unwrap();
            scan_revision_files(&locked.revisions)
                .unwrap()
                .pop()
                .unwrap()
        };
        let transaction = AdminTransactionV1::Retry(Box::new(RetryTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            parent_before_revision: parent.revision,
            parent_before_sha256: parent_entry.sha256,
            parent_next,
            child: child.clone(),
            options,
        }));
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        let (transaction_sha256, _) = publish_admin_transaction(&layout, &transaction).unwrap();
        let completion_path = layout
            .transactions
            .join(format!("retry-{transaction_sha256}.done"));
        drop(layout);
        let legacy_child_sha256 = publish_legacy_job_revision(&fixture, &child);

        assert!(matches!(
            JobStore::open_at(fixture.store.root()),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert!(!completion_path.exists());
        let child_locked = fixture
            .store
            .lock_job_unchecked(&child.local_job_id, false)
            .unwrap();
        let child_entries = scan_revision_files(&child_locked.revisions).unwrap();
        assert_eq!(child_entries.len(), 1);
        assert_eq!(child_entries[0].sha256, legacy_child_sha256);
        let parent_locked = fixture
            .store
            .lock_job_unchecked(&parent.local_job_id, false)
            .unwrap();
        assert_eq!(
            latest_locked(&parent_locked, &parent.local_job_id)
                .unwrap()
                .revision,
            parent.revision
        );
    }

    #[test]
    fn retry_recovery_rejects_a_logical_parent_with_legacy_envelope_bytes() {
        let fixture = StoreFixture::new();
        let initial = fixture.record("job-retry-legacy-chain-parent", 100);
        publish_legacy_job_revision(&fixture, &initial);
        let mut parent = initial;
        parent.revision += 1;
        parent.updated_at_ms += 1;
        parent.state = StoredJobState::Failed;
        parent.last_confirmed_state = Some(StoredJobState::Failed);
        parent.terminal_outcome = Some(StoredBuildOutcome::Failed);
        parent.failure = Some(StoredFailureV1 {
            code: "controller.failed".to_owned(),
            retryable: true,
        });
        let parent_before_sha256 = publish_legacy_job_revision(&fixture, &parent);
        let child = retry_child(
            &fixture,
            &parent,
            "job-retry-legacy-chain-child",
            "operation-retry-legacy-chain",
        );
        let options = RetryLineageOptionsV1::default();
        let parent_next = build_retry_parent_successor(&parent, &child, &options).unwrap();
        let transaction = AdminTransactionV1::Retry(Box::new(RetryTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            parent_before_revision: parent.revision,
            parent_before_sha256,
            parent_next: parent_next.clone(),
            child,
            options,
        }));
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        let (transaction_sha256, _) = publish_admin_transaction(&layout, &transaction).unwrap();
        let completion_path = layout
            .transactions
            .join(format!("retry-{transaction_sha256}.done"));
        drop(layout);
        let legacy_parent_next_sha256 = publish_legacy_job_revision(&fixture, &parent_next);

        assert!(matches!(
            JobStore::open_at(fixture.store.root()),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert!(!completion_path.exists());
        let parent_locked = fixture
            .store
            .lock_job_unchecked(&parent.local_job_id, false)
            .unwrap();
        let parent_entries = scan_revision_files(&parent_locked.revisions).unwrap();
        assert_eq!(parent_entries.len(), 3);
        assert_eq!(
            parent_entries.last().unwrap().sha256,
            legacy_parent_next_sha256
        );
    }

    #[test]
    fn recaptured_snapshot_retry_requires_exact_confirmation() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-recapture-parent");
        let mut child = retry_child(
            &fixture,
            &parent,
            "job-recapture-child",
            "operation-recapture-child",
        );
        child.request.source_mode = rustferry_remote::SourceMode::GitSnapshot;
        child.request.source_revision = Some("f".repeat(40));
        child
            .source
            .revision
            .clone_from(&child.request.source_revision);
        child.request_sha256 = canonical_request_sha256(&child.request).unwrap();
        child.semantic_retry_sha256 = canonical_retry_template_sha256_v1(&child.request).unwrap();
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();

        assert!(matches!(
            fixture.store.create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &RetryLineageOptionsV1::default()
            ),
            Err(JobStoreError::InvalidRecord { .. })
        ));
        let confirmation = retry_recapture_confirmation_sha256(&parent, &child).unwrap();
        let options = RetryLineageOptionsV1 {
            parent_policy: RetryParentPolicyV1::RequireUnsuccessful,
            source_policy: RetrySourcePolicyV1::RecapturedGitSnapshot {
                confirmation_sha256: confirmation,
                snapshot_consent_sha256: "d".repeat(64),
                source_archive_sha256: "e".repeat(64),
            },
        };
        fixture
            .store
            .create_retry_lineage(&parent.local_job_id, &retry_lease, &child, &options)
            .unwrap();
    }

    #[test]
    fn successful_parent_retry_requires_explicit_force_and_verified_cleanup() {
        let fixture = StoreFixture::new();
        let (first, success) =
            checkpoint_through_github_success(&fixture, "job-success-retry-parent");
        advance_through_local_validation(&fixture, &first.local_job_id);
        let cleaned = github_cleaned_resume(success, 108);
        fixture
            .store
            .checkpoint_github_resume(&first.local_job_id, &cleaned)
            .unwrap();
        let parent = fixture.store.latest(&first.local_job_id).unwrap();
        assert_eq!(parent.state, StoredJobState::Succeeded);
        let child = retry_child(
            &fixture,
            &parent,
            "job-success-retry-child",
            "operation-success-retry",
        );
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        assert!(
            fixture
                .store
                .create_retry_lineage(
                    &parent.local_job_id,
                    &retry_lease,
                    &child,
                    &RetryLineageOptionsV1::default()
                )
                .is_err()
        );
        let forced = RetryLineageOptionsV1 {
            parent_policy: RetryParentPolicyV1::AllowSuccessful,
            source_policy: RetrySourcePolicyV1::Exact,
        };
        fixture
            .store
            .create_retry_lineage(&parent.local_job_id, &retry_lease, &child, &forced)
            .unwrap();
    }

    #[test]
    fn prune_selects_complete_terminal_lineages_and_respects_live_lease() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-prune-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-prune-child",
            "operation-prune-child",
        );
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        fixture
            .store
            .create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &RetryLineageOptionsV1::default(),
            )
            .unwrap();
        drop(retry_lease);
        assert!(
            fixture
                .store
                .plan_prune(1_000, 10)
                .unwrap()
                .candidates
                .is_empty()
        );
        fixture
            .store
            .update(&child.local_job_id, |previous| {
                let mut failed = previous.clone();
                failed.revision += 1;
                failed.updated_at_ms += 1;
                failed.state = StoredJobState::Failed;
                failed.last_confirmed_state = Some(StoredJobState::Failed);
                failed.terminal_outcome = Some(StoredBuildOutcome::Failed);
                failed.failure = Some(StoredFailureV1 {
                    code: "controller.failed".to_owned(),
                    retryable: true,
                });
                Ok(failed)
            })
            .unwrap();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        assert_eq!(plan.candidates.len(), 2);
        let lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Build)
            .unwrap();
        assert!(matches!(
            fixture.store.acquire_prune_leases(&plan),
            Err(JobStoreError::JobBusy { .. })
        ));
        drop(lease);
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        let receipt = fixture.store.prune(leases, &post_release, 1_001).unwrap();
        assert_eq!(receipt.pruned_job_ids.len(), 2);
        assert!(matches!(
            fixture.store.latest(&parent.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(matches!(
            fixture.store.latest(&child.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
    }

    #[test]
    fn prune_permanently_consumes_operations_before_job_absence() {
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-prune-consumed-operation");
        let consumed_operation_id = pruned.operation_id.clone();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        assert_eq!(plan.candidates[0].operation_id, consumed_operation_id);
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        fixture.store.prune(leases, &post_release, 1_001).unwrap();

        let reopened = JobStore::open_at(fixture.store.root()).unwrap();
        assert!(matches!(
            reopened.snapshot_operation_owner(&consumed_operation_id),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));
        assert!(matches!(
            reopened.try_acquire_vacant_snapshot_operation_lease(&consumed_operation_id),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));

        let mut ordinary = fixture.record("job-reuse-consumed-operation", 1_100);
        ordinary.operation_id.clone_from(&consumed_operation_id);
        ordinary
            .request
            .operation_id
            .clone_from(&consumed_operation_id);
        ordinary.request_sha256 = canonical_request_sha256(&ordinary.request).unwrap();
        ordinary.semantic_retry_sha256 =
            canonical_retry_template_sha256_v1(&ordinary.request).unwrap();
        assert!(matches!(
            reopened.create(&ordinary),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));

        let mut parent = fixture.record("job-consumed-operation-retry-parent", 1_200);
        parent.operation_id = "operation-consumed-marker-new-parent".to_owned();
        parent.request.operation_id.clone_from(&parent.operation_id);
        parent.request_sha256 = canonical_request_sha256(&parent.request).unwrap();
        parent.semantic_retry_sha256 = canonical_retry_template_sha256_v1(&parent.request).unwrap();
        fixture.store.create(&parent).unwrap();
        let parent = mark_job_failed(&fixture, &parent.local_job_id);
        let child = retry_child(
            &fixture,
            &parent,
            "job-consumed-operation-retry-child",
            &consumed_operation_id,
        );
        let retry_lease = reopened
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        assert!(matches!(
            reopened.create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &RetryLineageOptionsV1::default(),
            ),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));
        assert!(matches!(
            reopened.latest(&child.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
    }

    #[test]
    fn held_operation_reservation_cannot_republish_after_concurrent_prune() {
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-prune-held-operation");
        let reservation =
            acquire_snapshot_operation_reservation(&fixture.store, &pruned.operation_id).unwrap();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        fixture.store.prune(leases, &post_release, 1_001).unwrap();

        let mut replacement = fixture.record("job-prune-held-operation-reuse", 1_100);
        replacement.operation_id.clone_from(&pruned.operation_id);
        replacement
            .request
            .operation_id
            .clone_from(&pruned.operation_id);
        replacement.request_sha256 = canonical_request_sha256(&replacement.request).unwrap();
        replacement.semantic_retry_sha256 =
            canonical_retry_template_sha256_v1(&replacement.request).unwrap();
        assert!(matches!(
            fixture
                .store
                .create_with_operation_lease(reservation, &replacement),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));
        assert!(matches!(
            fixture.store.latest(&replacement.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
    }

    #[test]
    fn idempotent_initial_create_cannot_resurrect_a_concurrently_pruned_operation() {
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-prune-idempotent-create");
        let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        *INITIAL_CREATE_OWNER_TEST_CONTROL.lock().unwrap() = Some(InitialCreateOwnerTestControl {
            operation_id: pruned.operation_id.clone(),
            arrived: std::sync::Arc::clone(&arrived),
            release: std::sync::Arc::clone(&release),
        });
        let writer = fixture.store.clone();
        let replay = fixture
            .store
            .revision(&pruned.local_job_id, 1)
            .expect("initial create bytes");
        let create = std::thread::spawn(move || writer.create(&replay));
        arrived.wait();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        let prune = fixture.store.prune(leases, &post_release, 1_001);
        release.wait();
        let create = create.join().expect("idempotent create thread");
        *INITIAL_CREATE_OWNER_TEST_CONTROL.lock().unwrap() = None;

        prune.expect("concurrent prune");
        assert!(matches!(
            create,
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));
        assert!(matches!(
            fixture.store.latest(&pruned.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(
            read_consumed_snapshot_operation(&fixture.store, &pruned.operation_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn tombstoned_local_job_id_cannot_be_recreated_across_the_prune_race() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-tombstone-race-long");
        let mut replacement = fixture.record(pruned.local_job_id.as_str(), 1_100);
        replacement.operation_id = "operation-tombstone-race-replacement".to_owned();
        replacement
            .request
            .operation_id
            .clone_from(&replacement.operation_id);
        replacement.request_sha256 = canonical_request_sha256(&replacement.request).unwrap();
        replacement.semantic_retry_sha256 =
            canonical_retry_template_sha256_v1(&replacement.request).unwrap();
        let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() =
            Some(PendingTransactionLockTestControl {
                local_job_id: pruned.local_job_id.clone(),
                mode: PendingTransactionLockTestMode::ExclusiveCreating,
                arrived: std::sync::Arc::clone(&arrived),
                release: std::sync::Arc::clone(&release),
            });
        let writer = fixture.store.clone();
        let raced_replacement = replacement.clone();
        let create = std::thread::spawn(move || writer.create(&raced_replacement));
        arrived.wait();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        let prune = fixture.store.prune(leases, &post_release, 1_001);
        release.wait();
        let create = create.join().expect("tombstoned create thread");
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() = None;

        prune.expect("concurrent prune");
        assert!(matches!(
            create,
            Err(JobStoreError::InvalidRecord {
                reason: "local job identifier was permanently consumed by a pruned job"
            })
        ));
        assert!(
            !fixture
                .store
                .version_root()
                .join(pruned.local_job_id.as_str())
                .exists(),
            "rejected tombstoned identifier must leave no empty owner tree"
        );
        assert!(
            fixture
                .store
                .pending_prune_release_plan()
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            fixture.store.create(&replacement),
            Err(JobStoreError::InvalidRecord {
                reason: "local job identifier was permanently consumed by a pruned job"
            })
        ));

        let prefix = fixture.record("job-tombstone-race", 1_200);
        fixture
            .store
            .create(&prefix)
            .expect("hyphen-prefix job ID is distinct from the tombstone owner");
    }

    #[test]
    fn completed_prune_release_fails_closed_on_multiple_exact_job_tombstones() {
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-prune-tombstone-ambiguity");
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let authorization_sha256 = leases.release_authorization_sha256.clone();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        fixture.store.prune(leases, &post_release, 1_001).unwrap();

        let layout = ensure_admin_layout(&fixture.store).unwrap();
        let original_candidate = &post_release.candidates[0];
        let original_path = layout.tombstones.join(format!(
            "{}-{:0REVISION_DIGITS$}-{}.json",
            original_candidate.local_job_id.as_str(),
            original_candidate.revision,
            original_candidate.revision_sha256
        ));
        let original = read_validated_prune_tombstone(&original_path).unwrap();
        fs::remove_file(&original_path).unwrap();
        let directory = admin_tombstone_locked_directory(&layout).unwrap();
        for delta in [1_u64, 2] {
            let mut duplicate = original.clone();
            duplicate.candidate.revision += delta;
            duplicate.candidate.revision_sha256 =
                sha256_hex(format!("replacement tombstone {delta}").as_bytes());
            let bytes = encode_bounded_json(
                "ambiguous prune tombstone bytes",
                &duplicate,
                64 * 1024,
                "encode ambiguous prune tombstone",
            )
            .unwrap();
            let path = layout.tombstones.join(format!(
                "{}-{:0REVISION_DIGITS$}-{}.json",
                duplicate.candidate.local_job_id.as_str(),
                duplicate.candidate.revision,
                duplicate.candidate.revision_sha256
            ));
            publish_managed_bytes(&directory, &path, &bytes, 64 * 1024).unwrap();
        }
        drop(directory);
        fs::remove_file(
            layout
                .transactions
                .join(format!("release-{authorization_sha256}.used")),
        )
        .unwrap();
        drop(layout);

        let reopen = JobStore::open_at(fixture.store.root());
        assert!(matches!(
            reopen,
            Err(JobStoreError::RecoveryRequired {
                reason: "multiple prune tombstones match one released job"
            })
        ));
        assert!(matches!(
            reject_tombstoned_local_job_id(&fixture.store, &pruned.local_job_id),
            Err(JobStoreError::RecoveryRequired {
                reason: "multiple prune tombstones match one local job identifier"
            })
        ));
    }

    #[test]
    fn checked_job_locks_recheck_a_prune_transaction_after_acquisition() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let pruned = persist_failed_parent(&fixture, "job-prune-checked-writer-race");
        let original_revision = pruned.revision;
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() =
            Some(PendingTransactionLockTestControl {
                local_job_id: pruned.local_job_id.clone(),
                mode: PendingTransactionLockTestMode::ExclusiveExisting,
                arrived: std::sync::Arc::clone(&arrived),
                release: std::sync::Arc::clone(&release),
            });
        let writer = fixture.store.clone();
        let writer_job_id = pruned.local_job_id.clone();
        let event_timestamp = pruned.updated_at_ms + 1;
        let writer = std::thread::spawn(move || {
            let mut input = event(ManagedEventSource::Controller, 1, "controller.raced");
            input.occurred_at_ms = event_timestamp;
            writer.append_managed_events(&writer_job_id, event_timestamp, &[input])
        });
        arrived.wait();
        let transaction = AdminTransactionV1::Prune(PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms: 1_001,
            plan,
        });
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        publish_admin_transaction(&layout, &transaction).unwrap();
        drop(layout);
        release.wait();
        let writer = writer.join().expect("checked writer thread");
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() = None;
        assert!(matches!(
            writer,
            Err(JobStoreError::RecoveryRequired {
                reason: "the job participates in an incomplete administrative transaction"
            })
        ));
        let locked = fixture
            .store
            .lock_job_unchecked(&pruned.local_job_id, false)
            .unwrap();
        assert_eq!(
            scan_revision_files(&locked.revisions)
                .unwrap()
                .last()
                .unwrap()
                .revision,
            original_revision
        );
        drop(locked);

        let read_fixture = StoreFixture::new();
        let read_pruned = persist_failed_parent(&read_fixture, "job-prune-checked-reader-race");
        let read_plan = read_fixture.store.plan_prune(1_000, 10).unwrap();
        let reader = JobStore::open_at_read_only(read_fixture.store.root()).unwrap();
        let arrived = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() =
            Some(PendingTransactionLockTestControl {
                local_job_id: read_pruned.local_job_id.clone(),
                mode: PendingTransactionLockTestMode::Shared,
                arrived: std::sync::Arc::clone(&arrived),
                release: std::sync::Arc::clone(&release),
            });
        let reader_job_id = read_pruned.local_job_id.clone();
        let reader = std::thread::spawn(move || reader.latest(&reader_job_id));
        arrived.wait();
        let transaction = AdminTransactionV1::Prune(PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms: 1_001,
            plan: read_plan,
        });
        let layout = ensure_admin_layout(&read_fixture.store).unwrap();
        publish_admin_transaction(&layout, &transaction).unwrap();
        drop(layout);
        release.wait();
        let reader = reader.join().expect("checked reader thread");
        *PENDING_TRANSACTION_LOCK_TEST_CONTROL.lock().unwrap() = None;
        assert!(matches!(
            reader,
            Err(JobStoreError::RecoveryRequired {
                reason: "the job participates in an incomplete administrative transaction"
            })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn prune_retains_candidate_locks_through_transaction_publication() {
        let _serial = PUBLICATION_TEST_SERIAL
            .lock()
            .expect("publication test serial lock is not poisoned");
        let fixture = StoreFixture::new();
        let failed = persist_failed_parent(&fixture, "job-prune-publication-lock");
        let mut first = event(ManagedEventSource::Controller, 1, "controller.first");
        first.occurred_at_ms = failed.updated_at_ms + 1;
        fixture
            .store
            .append_managed_events(&failed.local_job_id, first.occurred_at_ms, &[first])
            .expect("bind managed log before prune planning");
        let pruned = fixture.store.latest(&failed.local_job_id).unwrap();
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        let post_release = fixture
            .store
            .replan_prune_after_keepalive_releases(&leases)
            .unwrap();
        let expected_transaction = PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms: 1_001,
            plan: post_release.clone(),
        };
        let expected_value = AdminTransactionV1::Prune(expected_transaction.clone());
        let maximum = MAX_JOB_REVISION_BYTES
            .saturating_mul(2)
            .saturating_add(1024 * 1024);
        let expected_bytes = encode_bounded_json(
            "administrative transaction bytes",
            &expected_value,
            maximum,
            "encode administrative transaction",
        )
        .unwrap();
        let expected_transaction_sha256 = sha256_hex(&expected_bytes);
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        let expected_transaction_path = layout
            .transactions
            .join(format!("prune-{expected_transaction_sha256}.json"));
        drop(layout);
        let candidate_paths = post_release
            .candidates
            .iter()
            .map(|candidate| {
                fixture
                    .store
                    .version_root()
                    .join(candidate.local_job_id.as_str())
            })
            .collect::<Vec<_>>();
        let event_path = fixture
            .store
            .version_root()
            .join(pruned.local_job_id.as_str())
            .join(EVENTS_DIRECTORY);
        let initial_event_count = fs::read_dir(&event_path).unwrap().count();
        let (candidate_locks_held, candidate_locks_held_rx) = std::sync::mpsc::channel();
        let (allow_publication, allow_publication_rx) = std::sync::mpsc::channel();
        let (transaction_published, transaction_published_rx) = std::sync::mpsc::channel();
        let (allow_lock_release, allow_lock_release_rx) = std::sync::mpsc::channel();
        let (candidate_locks_released, candidate_locks_released_rx) = std::sync::mpsc::channel();
        let (allow_finish, allow_finish_rx) = std::sync::mpsc::channel();
        let (worker_completed, worker_completed_rx) = std::sync::mpsc::channel();
        *PRUNE_PUBLICATION_LOCK_TEST_CONTROL.lock().unwrap() =
            Some(PrunePublicationLockTestControl {
                local_job_id: pruned.local_job_id.clone(),
                candidate_locks_held,
                allow_publication: std::sync::Arc::new(std::sync::Mutex::new(allow_publication_rx)),
                transaction_published,
                allow_lock_release: std::sync::Arc::new(std::sync::Mutex::new(
                    allow_lock_release_rx,
                )),
                candidate_locks_released,
                allow_finish: std::sync::Arc::new(std::sync::Mutex::new(allow_finish_rx)),
            });
        let _control_reset = PrunePublicationTestControlReset;
        let prune_store = fixture.store.clone();
        let prune_plan = post_release.clone();
        let prune = std::thread::spawn(move || {
            let result = prune_store.prune(leases, &prune_plan, 1_001);
            worker_completed
                .send(())
                .expect("waiting_for_worker_completion: test receiver dropped");
            result
        });
        candidate_locks_held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiting_for_candidate_locks");
        for candidate in &post_release.candidates {
            expect_busy_lock_probe(probe_job_lock_once(&fixture.store, &candidate.local_job_id));
        }
        assert!(!expected_transaction_path.exists());
        assert!(candidate_paths.iter().all(|path| path.is_dir()));
        assert_eq!(
            fs::read_dir(&event_path).unwrap().count(),
            initial_event_count
        );

        allow_publication.send(()).unwrap();
        transaction_published_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiting_for_publication");
        let (_, published_transaction) =
            read_admin_transaction(&expected_transaction_path).unwrap();
        assert_eq!(published_transaction, expected_value);
        assert!(candidate_paths.iter().all(|path| path.is_dir()));
        assert_eq!(
            fs::read_dir(&event_path).unwrap().count(),
            initial_event_count
        );
        for candidate in &post_release.candidates {
            expect_busy_lock_probe(probe_job_lock_once(&fixture.store, &candidate.local_job_id));
        }

        allow_lock_release.send(()).unwrap();
        candidate_locks_released_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiting_for_worker_completion");
        for candidate in &post_release.candidates {
            drop(expect_acquired_lock_probe(probe_job_lock_once(
                &fixture.store,
                &candidate.local_job_id,
            )));
        }
        allow_finish.send(()).unwrap();
        worker_completed_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiting_for_worker_completion");
        let prune = prune.join().expect("prune publication thread");
        let receipt = prune.expect("prune after locked publication");
        assert_eq!(receipt.transaction_sha256, expected_transaction_sha256);
        assert_eq!(receipt.pruned_job_ids, vec![pruned.local_job_id.clone()]);
        assert!(matches!(
            fixture.store.latest(&pruned.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(candidate_paths.iter().all(|path| !path.exists()));
        assert!(!event_path.exists());
    }

    #[test]
    fn concurrent_disjoint_prune_plans_publish_only_one_release_authorization() {
        let fixture = StoreFixture::new();
        let parent = persist_failed_parent(&fixture, "job-prune-component-parent");
        let child = retry_child(
            &fixture,
            &parent,
            "job-prune-component-child",
            "operation-prune-component-child",
        );
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        fixture
            .store
            .create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &RetryLineageOptionsV1::default(),
            )
            .unwrap();
        drop(retry_lease);
        mark_job_failed(&fixture, &child.local_job_id);

        let singleton = fixture.record("job-prune-newer-singleton", 200);
        fixture.store.create(&singleton).unwrap();
        mark_job_failed(&fixture, &singleton.local_job_id);
        let component_plan = fixture.store.plan_prune(1_000, 2).unwrap();
        let singleton_plan = fixture.store.plan_prune(1_000, 1).unwrap();
        assert_eq!(component_plan.candidates.len(), 2);
        assert_eq!(singleton_plan.candidates.len(), 1);

        let barrier = Arc::new(Barrier::new(2));
        PRUNE_RELEASE_PUBLICATION_TEST_CONTROL
            .lock()
            .unwrap()
            .replace(PruneReleasePublicationTestControl {
                version_root: fixture.store.version_root(),
                barrier: Arc::clone(&barrier),
            });
        let component_store = fixture.store.clone();
        let component = std::thread::spawn(move || {
            component_store
                .acquire_prune_leases(&component_plan)
                .map(drop)
        });
        let singleton_store = fixture.store.clone();
        let singleton = std::thread::spawn(move || {
            singleton_store
                .acquire_prune_leases(&singleton_plan)
                .map(drop)
        });
        let results = [component.join().unwrap(), singleton.join().unwrap()];
        PRUNE_RELEASE_PUBLICATION_TEST_CONTROL
            .lock()
            .unwrap()
            .take();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let (_, transactions) = open_pending_transaction_directory(&fixture.store)
            .unwrap()
            .expect("one prune authorization directory");
        assert_eq!(
            scan_active_prune_release_authorizations(&transactions)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn prune_release_authorization_resumes_original_future_cutoff_and_blocks_other_operations() {
        let fixture = StoreFixture::new();
        let record = persist_failed_parent(&fixture, "job-prune-release-restart");
        let original_cutoff = u64::MAX - 1;
        let plan = fixture.store.plan_prune(original_cutoff, 10).unwrap();
        let leases = fixture.store.acquire_prune_leases(&plan).unwrap();
        drop(leases);

        let reopened = JobStore::open_at(fixture.store.root()).unwrap();
        let different = reopened.plan_prune(1_000, 10).unwrap();
        assert_ne!(
            different.candidates[0].complete_lineage_authorization_sha256,
            plan.candidates[0].complete_lineage_authorization_sha256
        );
        let pending = reopened.pending_prune_release_plan().unwrap().unwrap();
        assert_eq!(pending.terminal_before_ms, original_cutoff);
        assert_eq!(pending.selection_max_jobs, 10);
        assert!(matches!(
            reopened.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build,),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            reopened.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel,),
            Err(JobStoreError::RecoveryRequired { .. })
        ));

        let resumed = reopened.resume_prune_release_leases().unwrap().unwrap();
        let post_release = reopened
            .replan_prune_after_keepalive_releases(&resumed)
            .unwrap();
        let receipt = reopened.prune(resumed, &post_release, 1_000).unwrap();
        assert_eq!(receipt.pruned_job_ids, vec![record.local_job_id.clone()]);
        assert!(reopened.pending_prune_release_plan().unwrap().is_none());
    }

    #[test]
    fn prune_refuses_terminal_job_with_available_local_artifact() {
        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) =
            persist_local_artifact(&fixture, "job-prune-local-artifact", b"retained bytes");
        mark_job_failed(&fixture, &artifact_ref.local_job_id);

        assert!(
            fixture
                .store
                .plan_prune(1_000, 10)
                .unwrap()
                .candidates
                .is_empty()
        );
        assert_eq!(fs::read(path).unwrap(), b"retained bytes");
    }

    #[test]
    fn prune_refuses_whole_lineage_when_one_job_has_a_local_artifact() {
        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) = persist_local_artifact(
            &fixture,
            "job-prune-artifact-parent",
            b"lineage retained bytes",
        );
        let parent = mark_job_failed(&fixture, &artifact_ref.local_job_id);
        let child = retry_child(
            &fixture,
            &parent,
            "job-prune-artifact-child",
            "operation-prune-artifact-child",
        );
        let retry_lease = fixture
            .store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .unwrap();
        fixture
            .store
            .create_retry_lineage(
                &parent.local_job_id,
                &retry_lease,
                &child,
                &RetryLineageOptionsV1::default(),
            )
            .unwrap();
        drop(retry_lease);
        mark_job_failed(&fixture, &child.local_job_id);

        assert!(
            fixture
                .store
                .plan_prune(1_000, 10)
                .unwrap()
                .candidates
                .is_empty()
        );
        assert_eq!(fs::read(path).unwrap(), b"lineage retained bytes");
    }

    #[test]
    fn prune_intent_is_recovered_on_writable_reopen() {
        let fixture = StoreFixture::new();
        let record = persist_failed_parent(&fixture, "job-prune-crash");
        let plan = fixture.store.plan_prune(1_000, 10).unwrap();
        assert_eq!(plan.candidates.len(), 1);
        let transaction = AdminTransactionV1::Prune(PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms: 1_001,
            plan,
        });
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        publish_admin_transaction(&layout, &transaction).unwrap();
        drop(layout);
        assert!(matches!(
            fixture.store.latest(&record.local_job_id),
            Err(JobStoreError::RecoveryRequired { .. })
        ));
        let reopened = JobStore::open_at(fixture.store.root()).unwrap();
        assert!(matches!(
            reopened.latest(&record.local_job_id),
            Err(JobStoreError::JobNotFound { .. })
        ));
        assert!(matches!(
            reopened.try_acquire_vacant_snapshot_operation_lease(&record.operation_id),
            Err(JobStoreError::InvalidRecord {
                reason: "provider operation was permanently consumed by a pruned job"
            })
        ));
    }

    #[test]
    fn legacy_prune_intent_without_operation_id_never_deletes_its_owner() {
        let fixture = StoreFixture::new();
        let record = persist_failed_parent(&fixture, "job-prune-legacy-operation");
        let mut plan = fixture.store.plan_prune(1_000, 10).unwrap();
        plan.candidates[0].operation_id.clear();
        let transaction = AdminTransactionV1::Prune(PruneTransactionV1 {
            schema_version: ADMIN_TRANSACTION_SCHEMA_VERSION,
            pruned_at_ms: 1_001,
            plan,
        });
        let layout = ensure_admin_layout(&fixture.store).unwrap();
        let maximum = MAX_JOB_REVISION_BYTES
            .saturating_mul(2)
            .saturating_add(1024 * 1024);
        let bytes = encode_bounded_json(
            "legacy administrative transaction bytes",
            &transaction,
            maximum,
            "encode legacy administrative transaction",
        )
        .unwrap();
        let sha256 = sha256_hex(&bytes);
        let path = layout.transactions.join(format!("prune-{sha256}.json"));
        ensure_admin_transaction_capacity(&layout, &path, 2).unwrap();
        let directory = admin_transaction_locked_directory(&layout).unwrap();
        publish_managed_bytes(&directory, &path, &bytes, maximum).unwrap();
        drop(directory);
        drop(layout);

        let reopen = JobStore::open_at(fixture.store.root());
        assert!(
            matches!(
                reopen,
                Err(JobStoreError::InvalidRecord {
                    reason: "prune plan candidate is malformed or duplicated"
                })
            ),
            "unexpected legacy prune recovery result: {reopen:?}"
        );
        assert!(
            fixture
                .store
                .version_root()
                .join(record.local_job_id.as_str())
                .is_dir(),
            "malformed legacy prune intent must leave the exact job tree intact"
        );
        assert!(
            read_consumed_snapshot_operation(&fixture.store, &record.operation_id)
                .unwrap()
                .is_none(),
            "malformed legacy prune intent must not publish a consumed marker"
        );
    }

    #[test]
    fn bare_artifact_reference_refuses_cross_job_ambiguity() {
        let fixture = StoreFixture::new();
        persist_providerless_artifact_ready(
            &fixture,
            "job-artifact-ambiguous-a",
            vec![fixture.artifact(false)],
        );
        persist_providerless_artifact_ready(
            &fixture,
            "job-artifact-ambiguous-b",
            vec![fixture.artifact(false)],
        );
        assert!(matches!(
            fixture.store.resolve_managed_artifact("artifact-1", None),
            Err(JobStoreError::ArtifactReferenceAmbiguous { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn artifact_removal_preserves_provenance_and_recovers_intent() {
        let fixture = StoreFixture::new();
        let (artifact_ref, stored, path) =
            persist_local_artifact(&fixture, "job-artifact-remove", b"exact managed artifact");
        let locked = fixture
            .store
            .lock_job(&artifact_ref.local_job_id, false)
            .unwrap();
        let directory =
            ensure_artifact_overlay_directory(&fixture.store, &locked, &artifact_ref).unwrap();
        let intent = ArtifactRemovalOverlayV1 {
            schema_version: 1,
            revision: 1,
            artifact_ref: artifact_ref.clone(),
            expected_path: stored.local_path.clone().unwrap(),
            expected_file_identity: stored.local_file_identity.clone().unwrap(),
            expected_sha256: stored.record.sha256.clone(),
            expected_size: stored.record.size,
            state: ManagedArtifactRemovalState::Intent,
            updated_at_ms: 200,
        };
        validate_artifact_overlay(&stored, &intent, None).unwrap();
        publish_artifact_overlay(&directory, &intent).unwrap();
        drop(directory);
        drop(locked);

        let lease = fixture
            .store
            .try_acquire_operation_lease(
                &artifact_ref.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let removed = fixture
            .store
            .remove_managed_artifact(&lease, &artifact_ref, 201)
            .unwrap();
        assert_eq!(removed.state, ManagedArtifactRemovalState::Removed);
        assert!(!path.exists());
        let view = fixture
            .store
            .resolve_managed_artifact(
                &artifact_ref.provider_artifact_id,
                Some(&artifact_ref.local_job_id),
            )
            .unwrap();
        assert_eq!(view.removal_state, ManagedArtifactRemovalState::Removed);
        assert_eq!(view.local_path, stored.local_path);
    }

    #[cfg(windows)]
    #[test]
    fn artifact_removal_marks_replacement_uncertain_without_deleting_it() {
        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) =
            persist_local_artifact(&fixture, "job-artifact-replaced", b"expected bytes");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement must survive").unwrap();
        let lease = fixture
            .store
            .try_acquire_operation_lease(
                &artifact_ref.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let receipt = fixture
            .store
            .remove_managed_artifact(&lease, &artifact_ref, 200)
            .unwrap();
        assert_eq!(receipt.state, ManagedArtifactRemovalState::Uncertain);
        assert_eq!(fs::read(path).unwrap(), b"replacement must survive");
    }

    #[cfg(unix)]
    #[test]
    fn unix_artifact_removal_is_fail_closed_without_mutation() {
        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) =
            persist_local_artifact(&fixture, "job-artifact-unix", b"expected bytes");
        let parent = path.parent().unwrap();
        let before = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        let lease = fixture
            .store
            .try_acquire_operation_lease(
                &artifact_ref.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let result = fixture
            .store
            .remove_managed_artifact(&lease, &artifact_ref, 200);
        let after = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();

        assert!(matches!(
            result,
            Err(JobStoreError::ArtifactRemovalUnsupported)
        ));
        assert_eq!(fs::read(path).unwrap(), b"expected bytes");
        assert_eq!(after, before);
        assert_eq!(
            fixture
                .store
                .resolve_managed_artifact(
                    &artifact_ref.provider_artifact_id,
                    Some(&artifact_ref.local_job_id),
                )
                .unwrap()
                .removal_state,
            ManagedArtifactRemovalState::Available
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_artifact_removal_refuses_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) =
            persist_local_artifact(&fixture, "job-artifact-unix-symlink", b"expected bytes");
        fs::remove_file(&path).unwrap();
        let target = path.with_file_name("safe-target.bin");
        fs::write(&target, b"safe target").unwrap();
        symlink(&target, &path).unwrap();
        let lease = fixture
            .store
            .try_acquire_operation_lease(
                &artifact_ref.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let result = fixture
            .store
            .remove_managed_artifact(&lease, &artifact_ref, 200);
        assert!(matches!(
            result,
            Err(JobStoreError::ArtifactRemovalUnsupported)
        ));
        assert_eq!(fs::read(target).unwrap(), b"safe target");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }

    #[cfg(windows)]
    #[test]
    fn artifact_removal_refuses_reparse_point_without_touching_target() {
        use std::os::windows::fs::symlink_file;

        let fixture = StoreFixture::new();
        let (artifact_ref, _, path) =
            persist_local_artifact(&fixture, "job-artifact-reparse", b"expected bytes");
        fs::remove_file(&path).unwrap();
        let target = path.with_file_name("safe-target.bin");
        fs::write(&target, b"safe target").unwrap();
        if symlink_file(&target, &path).is_err() {
            return;
        }
        let lease = fixture
            .store
            .try_acquire_operation_lease(
                &artifact_ref.local_job_id,
                JobOperationKind::ArtifactRemoval,
            )
            .unwrap();
        let receipt = fixture
            .store
            .remove_managed_artifact(&lease, &artifact_ref, 200)
            .unwrap();
        assert_eq!(receipt.state, ManagedArtifactRemovalState::Uncertain);
        assert_eq!(fs::read(target).unwrap(), b"safe target");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
}
