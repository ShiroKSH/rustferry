use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use cargo_ferry::job_store::{
    JobStore, LocalJobId, MAX_MANAGED_EVENT_PAGE, ManagedEventLevel, ManagedEventSource,
    ManagedJobEventV1, PruneCandidateV1, RetryLineageBindingV1, RetryLineageOptionsV1,
    RetryParentPolicyV1, RetrySourcePolicyV1, StoredArtifactV1, StoredBuildOutcome,
    StoredCancellationStatus, StoredCleanupStatus, StoredJobState, StoredJobV1,
    StoredRetryLineageV1,
};
use rustferry_github::{
    git_endpoint::GithubGitEndpoint,
    job_logs::{
        GithubDurableRunAttemptLogIdentity, MAX_WORKER_LOG_EVENTS, WORKER_LOG_LINE_CODE,
        WORKER_LOG_PHASE, WORKER_LOGS_COMPLETE_CODE,
    },
    provider::{
        GithubGitSnapshotKeepaliveReleaseAuthorizationV1, GithubPrincipalIdentityV1,
        GithubRunStatusV1,
    },
    transport::{CommitSha, RunId, WorkflowId},
};
use rustferry_remote::{
    ArtifactKind, BuildProfile, CancellationToken, IosDeviceBuildRequest, JobState, SigningMode,
    SourceMode, canonical_request_sha256, canonical_retry_template_sha256_v1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cli::{
    JobsArgs, JobsCommand, JobsJobArgs, JobsListArgs, JobsLogsArgs, JobsPruneArgs, JobsRetryArgs,
};
use crate::commands::remote::{
    BoundGithubJobSession, BoundGithubRetrySession, CurrentSnapshotRetryPreviewV1,
    DurableGithubCancellationSession, GithubCancellationSessionReceipt,
    GithubRetryChildDisposition, GithubRetryChildSession, GithubRetryCompletionReceipt,
    PreparedGithubJobSession, PreparedGithubRetrySession, ingest_github_job_logs_once,
    ingest_github_job_logs_once_in_store, prepare_current_snapshot_retry_in_store,
};
use crate::error::CliError;
use crate::output::Reporter;

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobsListOutputV1 {
    dry_run: bool,
    limit: usize,
    returned: usize,
    jobs: Vec<JobListItemV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobListItemV1 {
    local_job_id: String,
    revision: u64,
    provider: String,
    provider_job_id: Option<String>,
    provider_run_id: Option<String>,
    operation_id: String,
    app_label: String,
    application_identifier: String,
    target: String,
    profile: &'static str,
    signing_mode: &'static str,
    created_at_ms: u64,
    submitted_at_ms: Option<u64>,
    updated_at_ms: u64,
    state: &'static str,
    last_confirmed_state: Option<&'static str>,
    terminal_outcome: Option<&'static str>,
    cleanup_status: &'static str,
    cancellation_status: &'static str,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobShowOutputV1 {
    dry_run: bool,
    local_job_id: String,
    revision: u64,
    provider: JobProviderIdentityV1,
    provider_job_id: Option<String>,
    provider_run_id: Option<String>,
    operation_id: String,
    request_sha256: String,
    semantic_retry_sha256: String,
    application_identifier: String,
    source_revision: Option<String>,
    source_manifest_sha256: String,
    target: String,
    profile: &'static str,
    signing_mode: &'static str,
    created_at_ms: u64,
    submitted_at_ms: Option<u64>,
    updated_at_ms: u64,
    state: &'static str,
    last_confirmed_state: Option<&'static str>,
    terminal_outcome: Option<&'static str>,
    cleanup_status: &'static str,
    cancellation_status: &'static str,
    retry: JobRetryLineageV1,
    failure: Option<JobFailureV1>,
    artifact_count: usize,
    event_journal_bound: bool,
    provider_resume_available: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobProviderIdentityV1 {
    name: String,
    config_sha256: String,
    principal: JobPrincipalIdentityV1,
    execution_repository_id: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JobPrincipalIdentityV1 {
    User { id: u64, login: String },
    RepositoryCredential,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobRetryLineageV1 {
    attempt: u32,
    parent_job_id: Option<String>,
    child_job_ids: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobFailureV1 {
    code: String,
    retryable: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobArtifactsOutputV1 {
    dry_run: bool,
    local_job_id: String,
    revision: u64,
    artifacts: Vec<JobArtifactV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobArtifactV1 {
    artifact_id: String,
    kind: &'static str,
    file_name: String,
    size: u64,
    sha256: String,
    media_type: Option<String>,
    download_destination: Option<String>,
    download_parent_identity: Option<String>,
    local_path: Option<String>,
    local_file_identity: Option<String>,
    locally_validated: bool,
    current_status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct JobLogEventV1 {
    schema_version: u32,
    event: &'static str,
    record_kind: &'static str,
    local_job_id: String,
    sequence: u64,
    occurred_at_ms: u64,
    source: &'static str,
    source_sequence: Option<u64>,
    source_event_sha256: Option<String>,
    phase: Option<String>,
    level: &'static str,
    code: String,
    message: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the stable log snapshot reports independent requested, completed, and terminal facts"
)]
struct JobLogsOutputV1 {
    dry_run: bool,
    local_job_id: String,
    log_scope: &'static str,
    provider_full_logs: bool,
    follow_requested: bool,
    followed: bool,
    since_ms: u64,
    phase: Option<String>,
    returned: usize,
    next_sequence: u64,
    has_more: bool,
    terminal: bool,
    output_requested: bool,
    output_written: bool,
    events: Vec<JobLogEventV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the terminal stream record keeps independent execution facts machine-readable"
)]
struct JobLogStreamFinishedV1 {
    schema_version: u32,
    event: &'static str,
    local_job_id: String,
    log_scope: &'static str,
    provider_full_logs: bool,
    dry_run: bool,
    followed: bool,
    returned: usize,
    next_sequence: u64,
    terminal: bool,
    output_written: bool,
    reason: &'static str,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobLogStreamErrorV1 {
    schema_version: u32,
    event: &'static str,
    status: &'static str,
    error: JobStreamErrorBodyV1,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobStreamErrorBodyV1 {
    code: &'static str,
    message: String,
    help: Option<String>,
    details: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the preflight DTO explicitly distinguishes intent, resume, and network effects"
)]
struct JobCancelOutputV1 {
    dry_run: bool,
    local_job_id: String,
    revision: u64,
    state: &'static str,
    cancellation_status: &'static str,
    exact_resume_available: bool,
    durable_intent_before_network: bool,
    maximum_provider_cancel_requests: u8,
    provider_cancel_requests_made: u8,
    intent_written: bool,
    get_only_reconciliation: bool,
    provider_state: Option<&'static str>,
    terminal_outcome: Option<&'static str>,
    cleanup_status: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancelPreflightAction {
    PersistIntentThenDispatch,
    ReconcileWithoutDispatch,
}

trait PreparedCancellationSession {
    type Durable: DurableCancellationSession;

    fn persist_intent(self) -> Result<Self::Durable, CliError>;
}

trait DurableCancellationSession {
    type Bound: BoundCancellationSession;

    fn bind_live(self, cancellation: &CancellationToken) -> Result<Self::Bound, CliError>;
}

trait BoundCancellationSession {
    type Receipt;

    fn finish_cancel(
        self,
        reason: &str,
        cancellation: CancellationToken,
    ) -> Result<Self::Receipt, CliError>;
}

impl PreparedCancellationSession for PreparedGithubJobSession {
    type Durable = DurableGithubCancellationSession;

    fn persist_intent(self) -> Result<Self::Durable, CliError> {
        self.persist_cancellation_requested()
    }
}

impl DurableCancellationSession for DurableGithubCancellationSession {
    type Bound = BoundGithubJobSession;

    fn bind_live(self, cancellation: &CancellationToken) -> Result<Self::Bound, CliError> {
        self.bind_live(cancellation)
    }
}

impl BoundCancellationSession for BoundGithubJobSession {
    type Receipt = GithubCancellationSessionReceipt;

    fn finish_cancel(
        self,
        reason: &str,
        cancellation: CancellationToken,
    ) -> Result<Self::Receipt, CliError> {
        self.cancel_or_reconcile_once(reason, cancellation)
    }
}

trait PreparedRetrySession {
    type Bound: BoundRetrySession;

    fn validate_parent(
        self,
        validate: impl FnOnce(&StoredJobV1) -> Result<(), CliError>,
    ) -> Result<Self, CliError>
    where
        Self: Sized;

    fn bind_parent(self, cancellation: &CancellationToken) -> Result<Self::Bound, CliError>;
}

trait BoundRetrySession {
    type Child: RetryChildSession;

    fn create_or_resume_child<F>(
        self,
        options: &RetryLineageOptionsV1,
        make_child: F,
    ) -> Result<Self::Child, CliError>
    where
        F: FnOnce(&StoredJobV1) -> Result<StoredJobV1, CliError>;
}

trait RetryChildSession {
    type Receipt;

    fn complete(
        self,
        cancellation: CancellationToken,
        reporter: &Reporter,
    ) -> Result<Self::Receipt, CliError>;
}

impl PreparedRetrySession for PreparedGithubRetrySession {
    type Bound = BoundGithubRetrySession;

    fn validate_parent(
        self,
        validate: impl FnOnce(&StoredJobV1) -> Result<(), CliError>,
    ) -> Result<Self, CliError> {
        self.validate_leased_parent(validate)
    }

    fn bind_parent(self, cancellation: &CancellationToken) -> Result<Self::Bound, CliError> {
        self.bind_live_parent(cancellation)
    }
}

impl BoundRetrySession for BoundGithubRetrySession {
    type Child = GithubRetryChildSession;

    fn create_or_resume_child<F>(
        self,
        options: &RetryLineageOptionsV1,
        make_child: F,
    ) -> Result<Self::Child, CliError>
    where
        F: FnOnce(&StoredJobV1) -> Result<StoredJobV1, CliError>,
    {
        self.create_or_resume_child(options, make_child)
    }
}

impl RetryChildSession for GithubRetryChildSession {
    type Receipt = GithubRetryCompletionReceipt;

    fn complete(
        self,
        cancellation: CancellationToken,
        reporter: &Reporter,
    ) -> Result<Self::Receipt, CliError> {
        self.complete(cancellation, reporter)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the preflight DTO explicitly distinguishes retry policy and side effects"
)]
struct JobRetryOutputV1 {
    dry_run: bool,
    parent_job_id: String,
    parent_revision: u64,
    parent_state: &'static str,
    parent_outcome: &'static str,
    force: bool,
    source_policy: &'static str,
    source_revision: Option<String>,
    source_manifest_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_source_preview: Option<CurrentSnapshotRetryPreviewV1>,
    atomic_lineage_required: bool,
    child_created: bool,
    resumed_existing_child: bool,
    child_local_job_id: Option<String>,
    child_revision: Option<u64>,
    child_state: Option<&'static str>,
    child_operation_id: Option<String>,
    child_request_sha256: Option<String>,
    child_semantic_retry_sha256: Option<String>,
    child_terminal_outcome: Option<&'static str>,
    cleanup_status: Option<&'static str>,
    provider_job_id: Option<String>,
    provider_run_id: Option<String>,
    submission_confirmed: bool,
    completion_confirmed: bool,
    validated_artifact_count: usize,
    artifacts: Vec<JobRetryArtifactV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobRetryArtifactV1 {
    artifact_id: String,
    sha256: String,
    local_path: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobPruneOutputV1 {
    dry_run: bool,
    terminal_before_ms: u64,
    max_jobs: usize,
    confirmation_provided: bool,
    planned: usize,
    executed: bool,
    transaction_sha256: Option<String>,
    already_complete: Option<bool>,
    pruned_job_ids: Vec<String>,
    candidates: Vec<JobPruneCandidateV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct JobPruneCandidateV1 {
    local_job_id: String,
    operation_id: String,
    revision: u64,
    revision_sha256: String,
    updated_at_ms: u64,
    attempt: u32,
    parent_job_id: Option<String>,
    child_job_ids: Vec<String>,
    complete_lineage_authorization_sha256: String,
    has_git_snapshot_keepalive: bool,
}

/// Secret-free project-filtered job-list data shared with the IDE protocol.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobsListV1 {
    pub limit: usize,
    pub returned: usize,
    pub jobs: Vec<IdeJobListItemV1>,
}

/// One secret-free job summary shared with editor integrations.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobListItemV1 {
    pub local_job_id: String,
    pub revision: u64,
    pub provider: String,
    pub provider_job_id: Option<String>,
    pub provider_run_id: Option<String>,
    pub operation_id: String,
    pub app_label: String,
    pub application_identifier: String,
    pub target: String,
    pub profile: String,
    pub signing_mode: String,
    pub created_at_ms: u64,
    pub submitted_at_ms: Option<u64>,
    pub updated_at_ms: u64,
    pub state: String,
    pub last_confirmed_state: Option<String>,
    pub terminal_outcome: Option<String>,
    pub cleanup_status: String,
    pub cancellation_status: String,
}

/// Secret-free details for one project-filtered job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobDetailsV1 {
    pub local_job_id: String,
    pub revision: u64,
    pub provider: IdeJobProviderIdentityV1,
    pub provider_job_id: Option<String>,
    pub provider_run_id: Option<String>,
    pub operation_id: String,
    pub request_sha256: String,
    pub semantic_retry_sha256: String,
    pub application_identifier: String,
    pub source_revision: Option<String>,
    pub source_manifest_sha256: String,
    pub target: String,
    pub profile: String,
    pub signing_mode: String,
    pub created_at_ms: u64,
    pub submitted_at_ms: Option<u64>,
    pub updated_at_ms: u64,
    pub state: String,
    pub last_confirmed_state: Option<String>,
    pub terminal_outcome: Option<String>,
    pub cleanup_status: String,
    pub cancellation_status: String,
    pub retry: IdeJobRetryLineageV1,
    pub failure: Option<IdeJobFailureV1>,
    pub artifact_count: usize,
    pub event_journal_bound: bool,
    pub provider_resume_available: bool,
}

/// Public provider identity without endpoints or resume state.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobProviderIdentityV1 {
    pub name: String,
    pub config_sha256: String,
    pub principal: IdeJobPrincipalIdentityV1,
    pub execution_repository_id: u64,
}

/// Public provider principal identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdeJobPrincipalIdentityV1 {
    User { id: u64, login: String },
    RepositoryCredential,
}

/// Public retry lineage.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobRetryLineageV1 {
    pub attempt: u32,
    pub parent_job_id: Option<String>,
    pub child_job_ids: Vec<String>,
}

/// Public terminal failure metadata.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobFailureV1 {
    pub code: String,
    pub retryable: bool,
}

/// Secret-free artifact data for one project-filtered job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobArtifactsV1 {
    pub local_job_id: String,
    pub revision: u64,
    pub artifacts: Vec<IdeJobArtifactV1>,
}

/// One recorded artifact without credentials or provider URLs.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobArtifactV1 {
    pub artifact_id: String,
    pub kind: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub media_type: Option<String>,
    pub download_destination: Option<String>,
    pub download_parent_identity: Option<String>,
    pub local_path: Option<String>,
    pub local_file_identity: Option<String>,
    pub locally_validated: bool,
    pub current_status: String,
}

/// Secret-free project-filtered lifecycle-event snapshot.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobLogsV1 {
    pub local_job_id: String,
    pub log_scope: String,
    pub provider_full_logs: bool,
    pub since_ms: u64,
    pub phase: Option<String>,
    pub returned: usize,
    pub next_sequence: u64,
    pub terminal: bool,
    pub events: Vec<IdeJobLogEventV1>,
}

/// Exact logical action eligibility for one workspace-bound durable job revision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobEligibilityV1 {
    pub local_job_id: String,
    pub revision: u64,
    pub can_cancel: bool,
    pub cancel_reason_code: Option<String>,
    pub can_retry: bool,
    pub retry_reason_code: Option<String>,
}

/// One bounded cursor page, optionally after one provider refresh and one local wait.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the wire DTO exposes independent proof flags required by the IDE protocol"
)]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobLogsPageV1 {
    pub local_job_id: String,
    pub log_scope: String,
    pub provider_full_logs: bool,
    pub after_sequence: u64,
    pub phase: Option<String>,
    pub limit: usize,
    pub returned: usize,
    pub next_after_sequence: u64,
    pub has_more: bool,
    pub terminal: bool,
    pub provider_refresh_performed: bool,
    pub waited: bool,
    pub events: Vec<IdeJobLogEventV1>,
}

/// Workspace-bound durable cancellation result without renderer or stdout coupling.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobCancellationV1 {
    pub parent: ProjectJobDetailsV1,
    pub durable: bool,
    pub intent_written: bool,
    pub provider_cancel_requests: u8,
    pub get_only_reconciliation: bool,
}

/// Workspace-bound exact retry lineage and completed child evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProjectJobRetryV1 {
    pub parent: ProjectJobDetailsV1,
    pub child: ProjectJobDetailsV1,
    pub parent_revision: u64,
    pub child_revision: u64,
    pub child_created: bool,
    pub resumed_existing_child: bool,
    pub durable: bool,
}

/// One sanitized lifecycle event; never a provider payload or complete log line.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IdeJobLogEventV1 {
    pub record_kind: String,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub phase: Option<String>,
    pub source: String,
    pub source_sequence: Option<u64>,
    pub source_event_sha256: Option<String>,
    pub level: String,
    pub code: String,
    pub message: Option<String>,
}

pub fn run(
    arguments: &JobsArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    match &arguments.command {
        JobsCommand::List(arguments) => list(
            &JobStore::open_default_read_only()?,
            arguments,
            dry_run,
            reporter,
        ),
        JobsCommand::Show(arguments) => show(
            &JobStore::open_default_read_only()?,
            arguments,
            dry_run,
            reporter,
        ),
        JobsCommand::Artifacts(arguments) => artifacts(
            &JobStore::open_default_read_only()?,
            arguments,
            dry_run,
            reporter,
        ),
        JobsCommand::Logs(arguments) => logs(arguments, dry_run, json_stream, reporter),
        JobsCommand::Cancel(arguments) => cancel(arguments, dry_run, reporter),
        JobsCommand::Retry(arguments) => retry(arguments, dry_run, reporter),
        JobsCommand::Prune(arguments) => prune(arguments, dry_run, reporter),
    }
}

fn list(
    store: &JobStore,
    arguments: &JobsListArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let output = list_output(store, arguments.limit, dry_run)?;
    reporter.success("jobs-list", &output, || render_job_list(&output), &[]);
    Ok(())
}

fn show(
    store: &JobStore,
    arguments: &JobsJobArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let output = show_output(store, &arguments.local_job_id, dry_run)?;
    reporter.success("jobs-show", &output, || render_job_show(&output), &[]);
    Ok(())
}

fn artifacts(
    store: &JobStore,
    arguments: &JobsJobArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let output = artifacts_output(store, &arguments.local_job_id, dry_run)?;
    reporter.success(
        "jobs-artifacts",
        &output,
        || render_job_artifacts(&output),
        &[],
    );
    Ok(())
}

const JOB_LOG_SCOPE: &str = "durable_sanitized_job_events";
const JOB_LOG_WARNING: &str = "This journal contains sanitized lifecycle events and bounded sanitized worker output; raw provider payloads and raw worker bytes are never stored.";
const MAX_POST_TERMINAL_LOG_FETCHES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProviderLogIngestStatus {
    provider_fetch_performed: bool,
    revision: Option<u64>,
    durable_records_observed: usize,
}

trait ProviderLogIngestor {
    /// Perform at most one bounded exact-attempt fetch and durable append.
    /// Implementations must release their `Logs` operation lease before returning.
    fn ingest_once(
        &mut self,
        local_job_id: &LocalJobId,
    ) -> Result<ProviderLogIngestStatus, CliError>;
}

struct GithubProviderLogIngestor;

impl ProviderLogIngestor for GithubProviderLogIngestor {
    fn ingest_once(
        &mut self,
        local_job_id: &LocalJobId,
    ) -> Result<ProviderLogIngestStatus, CliError> {
        // One provider poll has fixed request/deadline bounds; interrupts are sampled at every
        // poll boundary without leaving a watcher thread alive beyond the command.
        let cancellation =
            log_poll_cancellation_token(rustferry_core::process_control::interrupt_requested());
        let receipt = ingest_github_job_logs_once(local_job_id, &cancellation)?;
        if receipt.local_job_id != *local_job_id {
            return Err(jobs_lifecycle_error(
                "provider_log_receipt_identity_mismatch",
                "the bounded provider-log receipt belongs to a different local job",
                "Preserve the journal and retry only through the exact job-bound Logs session.",
                local_job_id,
            ));
        }
        let durable_records_observed = receipt
            .appended
            .checked_add(receipt.already_present)
            .ok_or_else(|| {
                jobs_lifecycle_error(
                    "provider_log_receipt_invalid",
                    "the bounded provider-log receipt count overflowed",
                    "Preserve the journal and inspect its bounded managed-event records.",
                    local_job_id,
                )
            })?;
        Ok(ProviderLogIngestStatus {
            provider_fetch_performed: receipt.provider_fetch_performed,
            revision: Some(receipt.revision),
            durable_records_observed,
        })
    }
}

fn log_poll_cancellation_token(interrupt_requested: bool) -> CancellationToken {
    let cancellation = CancellationToken::new();
    if interrupt_requested {
        cancellation.cancel();
    }
    cancellation
}

fn logs(
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let result = logs_inner(arguments, dry_run, json_stream, reporter);
    if !json_stream {
        return result;
    }
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.is_already_reported() => Err(error),
        Err(error) => {
            let exit_code = error.exit_code();
            let payload = JobLogStreamErrorV1 {
                schema_version: 1,
                event: "job_logs_error",
                status: "error",
                error: JobStreamErrorBodyV1 {
                    code: error.code(),
                    message: error.to_string(),
                    help: error.help(),
                    details: error.details(),
                },
            };
            write_stdout_json_line(&payload)?;
            Err(CliError::AlreadyReported { exit_code })
        }
    }
}

fn logs_inner(
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let mut ingestor = GithubProviderLogIngestor;
    logs_inner_with_ingestor(arguments, dry_run, json_stream, reporter, &mut ingestor)
}

fn logs_inner_with_ingestor(
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
    ingestor: &mut impl ProviderLogIngestor,
) -> Result<(), CliError> {
    let store = JobStore::open_default_read_only()?;
    if json_stream || (arguments.follow && !dry_run) {
        return stream_logs(&store, arguments, dry_run, json_stream, ingestor);
    }
    let (ingest, mut refresh_error) = if dry_run {
        (ProviderLogIngestStatus::default(), None)
    } else {
        match ingestor.ingest_once(&arguments.local_job_id) {
            Ok(status) => (status, None),
            Err(error) => (ProviderLogIngestStatus::default(), Some(error)),
        }
    };
    let initial_record = store.latest(&arguments.local_job_id)?;
    let durable_log_identity = durable_worker_log_identity(&initial_record);
    let mut proof = WorkerLogJournalProof::default();
    let mut cursor = 0_u64;
    let mut events = Vec::new();
    loop {
        let page =
            store.read_managed_events(&arguments.local_job_id, cursor, MAX_MANAGED_EVENT_PAGE)?;
        for event in &page.events {
            if let Some(identity) = durable_log_identity.as_ref() {
                proof.observe(event, &arguments.local_job_id, identity);
            }
            if event_matches_filters(event, arguments.since, arguments.phase.as_deref()) {
                events.push(JobLogEventV1::from(event));
            }
        }
        cursor = page.next_after_sequence;
        if !page.has_more {
            break;
        }
    }
    let record = store.latest(&arguments.local_job_id)?;
    let current_log_identity = durable_worker_log_identity(&record);
    let provider_full_logs = current_log_identity.as_ref() == durable_log_identity.as_ref()
        && current_log_identity
            .as_ref()
            .is_some_and(|identity| proof.is_complete(identity));
    let terminal = job_lifecycle_is_settled(&record);
    if refresh_error.is_none()
        && !dry_run
        && let Err(error) = validate_log_ingest_status(&record, &ingest)
    {
        refresh_error = Some(error);
    }
    let output_written = if let Some(path) = arguments.output.as_deref()
        && !dry_run
    {
        let mut sink = LogFileSink::open(path, false)?;
        for event in &events {
            sink.write_event(event)?;
        }
        sink.finish()?;
        true
    } else {
        false
    };
    let output = JobLogsOutputV1 {
        dry_run,
        local_job_id: arguments.local_job_id.as_str().to_owned(),
        log_scope: JOB_LOG_SCOPE,
        provider_full_logs,
        follow_requested: arguments.follow,
        followed: false,
        since_ms: arguments.since,
        phase: arguments.phase.clone(),
        returned: events.len(),
        next_sequence: cursor,
        has_more: false,
        terminal,
        output_requested: arguments.output.is_some(),
        output_written,
        events,
    };
    if let Some(error) = refresh_error {
        let exit_code = error.exit_code();
        reporter.failure_with_data("jobs-logs", &output, &error, || render_job_logs(&output));
        return Err(CliError::AlreadyReported { exit_code });
    }
    if terminal
        && (provider_logs_are_expected(&record) || ingest.provider_fetch_performed)
        && !provider_full_logs
    {
        let error = provider_logs_incomplete_error(&arguments.local_job_id);
        let exit_code = error.exit_code();
        reporter.failure_with_data("jobs-logs", &output, &error, || render_job_logs(&output));
        return Err(CliError::AlreadyReported { exit_code });
    }
    reporter.success(
        "jobs-logs",
        &output,
        || render_job_logs(&output),
        &[JOB_LOG_WARNING.to_owned()],
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkerLogCompletionMarker {
    occurred_at_ms: u64,
    source_sequence: u64,
    source_event_sha256: String,
    message: String,
}

#[derive(Debug, Default)]
struct WorkerLogJournalProof {
    events: Vec<(u64, String)>,
    marker: Option<WorkerLogCompletionMarker>,
    invalid: bool,
}

impl WorkerLogJournalProof {
    fn observe(
        &mut self,
        event: &ManagedJobEventV1,
        local_job_id: &LocalJobId,
        identity: &GithubDurableRunAttemptLogIdentity,
    ) {
        if event.local_job_id != *local_job_id || event.source != ManagedEventSource::Worker {
            return;
        }
        let Some(source_sequence) = event.source_sequence else {
            self.invalid |= matches!(
                event.code.as_str(),
                WORKER_LOG_LINE_CODE | WORKER_LOGS_COMPLETE_CODE
            );
            return;
        };
        let attempt = identity.expected_completion_source_sequence() >> 32;
        if source_sequence >> 32 != attempt {
            return;
        }
        match event.code.as_str() {
            WORKER_LOG_LINE_CODE => self.observe_line(event, source_sequence),
            WORKER_LOGS_COMPLETE_CODE => self.observe_marker(event, source_sequence),
            _ => self.invalid = true,
        }
    }

    fn observe_line(&mut self, event: &ManagedJobEventV1, source_sequence: u64) {
        let Some(digest) = event.source_event_sha256.as_deref() else {
            self.invalid = true;
            return;
        };
        if self.marker.is_some()
            || self.events.len() >= MAX_WORKER_LOG_EVENTS
            || event.phase.as_deref() != Some(WORKER_LOG_PHASE)
            || event.level != ManagedEventLevel::Info
            || event.occurred_at_ms == 0
            || event.message.is_none()
        {
            self.invalid = true;
            return;
        }
        self.events.push((source_sequence, digest.to_owned()));
    }

    fn observe_marker(&mut self, event: &ManagedJobEventV1, source_sequence: u64) {
        let marker = event
            .source_event_sha256
            .as_deref()
            .zip(event.message.as_deref());
        if self.marker.is_some()
            || event.phase.as_deref() != Some(WORKER_LOG_PHASE)
            || event.level != ManagedEventLevel::Info
            || event.occurred_at_ms == 0
            || marker.is_none()
        {
            self.invalid = true;
            return;
        }
        let (digest, message) = marker.expect("checked completion marker fields");
        self.marker = Some(WorkerLogCompletionMarker {
            occurred_at_ms: event.occurred_at_ms,
            source_sequence,
            source_event_sha256: digest.to_owned(),
            message: message.to_owned(),
        });
    }

    fn is_complete(&self, identity: &GithubDurableRunAttemptLogIdentity) -> bool {
        if self.invalid {
            return false;
        }
        self.marker.as_ref().is_some_and(|marker| {
            identity
                .validate_durable_completion_marker(
                    self.events
                        .iter()
                        .map(|(sequence, digest)| (*sequence, digest.as_str())),
                    marker.occurred_at_ms,
                    marker.source_sequence,
                    &marker.source_event_sha256,
                    &marker.message,
                )
                .is_ok()
        })
    }
}

struct LogStreamState {
    sink: Option<LogFileSink>,
    cursor: u64,
    returned: usize,
    proof_identity: Option<GithubDurableRunAttemptLogIdentity>,
    proof: WorkerLogJournalProof,
    provider_full_logs: bool,
}

impl LogStreamState {
    fn drain_event_pages(
        &mut self,
        store: &JobStore,
        arguments: &JobsLogsArgs,
        json_stream: bool,
        event_page_limit: usize,
        durable_log_identity: Option<&GithubDurableRunAttemptLogIdentity>,
    ) -> Result<(), CliError> {
        if self.proof_identity.as_ref() != durable_log_identity {
            self.proof_identity = durable_log_identity.cloned();
            self.proof = WorkerLogJournalProof::default();
        }
        loop {
            let page = store.read_managed_events(
                &arguments.local_job_id,
                self.cursor,
                event_page_limit,
            )?;
            for event in &page.events {
                if let Some(identity) = durable_log_identity {
                    self.proof.observe(event, &arguments.local_job_id, identity);
                }
                if !event_matches_filters(event, arguments.since, arguments.phase.as_deref()) {
                    continue;
                }
                let output = JobLogEventV1::from(event);
                if json_stream {
                    write_stdout_json_line(&output)?;
                } else {
                    write_stdout_text(&format!("{}\n", render_job_log_event(&output)))?;
                }
                if let Some(sink) = self.sink.as_mut() {
                    sink.write_event(&output)?;
                }
                self.returned = self.returned.saturating_add(1);
            }
            self.cursor = page.next_after_sequence;
            if !page.has_more {
                self.provider_full_logs = self.proof_identity.as_ref() == durable_log_identity
                    && durable_log_identity
                        .is_some_and(|identity| self.proof.is_complete(identity));
                return Ok(());
            }
        }
    }
}

fn stream_logs(
    store: &JobStore,
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    ingestor: &mut impl ProviderLogIngestor,
) -> Result<(), CliError> {
    stream_logs_with_wait(
        store,
        arguments,
        dry_run,
        json_stream,
        ingestor,
        &mut thread::sleep,
    )
}

fn stream_logs_with_wait(
    store: &JobStore,
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    ingestor: &mut impl ProviderLogIngestor,
    wait_between_polls: &mut impl FnMut(Duration),
) -> Result<(), CliError> {
    stream_logs_with_wait_and_page_limit(
        store,
        arguments,
        dry_run,
        json_stream,
        ingestor,
        wait_between_polls,
        MAX_MANAGED_EVENT_PAGE,
    )
}

fn stream_logs_with_wait_and_page_limit(
    store: &JobStore,
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    ingestor: &mut impl ProviderLogIngestor,
    wait_between_polls: &mut impl FnMut(Duration),
    event_page_limit: usize,
) -> Result<(), CliError> {
    let mut state = Box::new(LogStreamState {
        sink: if let Some(path) = arguments.output.as_deref()
            && !dry_run
        {
            Some(LogFileSink::open(path, json_stream)?)
        } else {
            None
        },
        cursor: 0,
        returned: 0,
        proof_identity: None,
        proof: WorkerLogJournalProof::default(),
        provider_full_logs: false,
    });
    if !json_stream {
        write_stdout_text(&format!("{JOB_LOG_WARNING}\n"))?;
    }
    let mut post_terminal_log_fetches = 0_usize;
    let exit = loop {
        let refresh = refresh_provider_logs(dry_run, ingestor, &arguments.local_job_id);
        if let Some(exit) = process_log_stream_iteration(
            store,
            arguments,
            dry_run,
            json_stream,
            event_page_limit,
            &mut state,
            &mut post_terminal_log_fetches,
            refresh,
        )? {
            break exit;
        }
        wait_between_polls(Duration::from_millis(500));
    };
    finish_log_stream(
        *state,
        arguments,
        dry_run,
        json_stream,
        exit.reason,
        exit.terminal,
        exit.refresh_error,
    )
}

struct LogStreamExit {
    reason: &'static str,
    terminal: bool,
    refresh_error: Option<CliError>,
}

fn refresh_provider_logs(
    dry_run: bool,
    ingestor: &mut impl ProviderLogIngestor,
    local_job_id: &LocalJobId,
) -> (ProviderLogIngestStatus, Option<CliError>) {
    if dry_run {
        return (ProviderLogIngestStatus::default(), None);
    }
    match ingestor.ingest_once(local_job_id) {
        Ok(status) => (status, None),
        Err(error) => (ProviderLogIngestStatus::default(), Some(error)),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one stream iteration receives every explicit filter, proof state, and bounded refresh result"
)]
fn process_log_stream_iteration(
    store: &JobStore,
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    event_page_limit: usize,
    state: &mut LogStreamState,
    post_terminal_log_fetches: &mut usize,
    refresh: (ProviderLogIngestStatus, Option<CliError>),
) -> Result<Option<LogStreamExit>, CliError> {
    let (ingest, refresh_error) = refresh;
    let record = store.latest(&arguments.local_job_id)?;
    let durable_log_identity = durable_worker_log_identity(&record);
    state.drain_event_pages(
        store,
        arguments,
        json_stream,
        event_page_limit,
        durable_log_identity.as_ref(),
    )?;
    let terminal = job_lifecycle_is_settled(&record);
    let finish = |reason, refresh_error| {
        Some(LogStreamExit {
            reason,
            terminal,
            refresh_error,
        })
    };
    if let Some(error) = refresh_error {
        return Ok(finish("provider_refresh_failed", Some(error)));
    }
    if !dry_run && let Err(error) = validate_log_ingest_status(&record, &ingest) {
        return Ok(finish("provider_refresh_failed", Some(error)));
    }
    let provider_logs_expected =
        provider_logs_are_expected(&record) || ingest.provider_fetch_performed;
    if terminal && provider_logs_expected && !state.provider_full_logs {
        *post_terminal_log_fetches = post_terminal_log_fetches.saturating_add(1);
    }
    if dry_run {
        return Ok(finish("dry_run", None));
    }
    if !arguments.follow && terminal && provider_logs_expected && !state.provider_full_logs {
        return Ok(finish(
            "provider_logs_incomplete",
            Some(provider_logs_incomplete_error(&arguments.local_job_id)),
        ));
    }
    if !arguments.follow {
        return Ok(finish("snapshot_complete", None));
    }
    if rustferry_core::process_control::interrupt_requested() {
        return Ok(finish("interrupted", None));
    }
    if terminal && (!provider_logs_expected || state.provider_full_logs) {
        return Ok(finish("terminal", None));
    }
    if terminal && *post_terminal_log_fetches >= MAX_POST_TERMINAL_LOG_FETCHES {
        return Ok(finish(
            "provider_logs_incomplete",
            Some(provider_logs_incomplete_error(&arguments.local_job_id)),
        ));
    }
    Ok(None)
}

fn finish_log_stream(
    state: LogStreamState,
    arguments: &JobsLogsArgs,
    dry_run: bool,
    json_stream: bool,
    reason: &'static str,
    terminal: bool,
    refresh_error: Option<CliError>,
) -> Result<(), CliError> {
    let output_written = if let Some(sink) = state.sink {
        sink.finish()?;
        true
    } else {
        false
    };
    let finished = JobLogStreamFinishedV1 {
        schema_version: 1,
        event: "job_logs_finished",
        local_job_id: arguments.local_job_id.as_str().to_owned(),
        log_scope: JOB_LOG_SCOPE,
        provider_full_logs: state.provider_full_logs,
        dry_run,
        followed: arguments.follow && !dry_run,
        returned: state.returned,
        next_sequence: state.cursor,
        terminal,
        output_written,
        reason,
    };
    let finish_result = if json_stream {
        write_stdout_json_line(&finished)
    } else {
        write_stdout_text(&format!(
            "Job {} journal complete: events={} next_sequence={} terminal={} provider_full_logs={} reason={}\n",
            finished.local_job_id,
            finished.returned,
            finished.next_sequence,
            finished.terminal,
            finished.provider_full_logs,
            finished.reason
        ))
    };
    finish_result?;
    if let Some(error) = refresh_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn cancel(arguments: &JobsJobArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let (output, summary) = if dry_run {
        let record = JobStore::open_default_read_only()?.latest(&arguments.local_job_id)?;
        let action = validate_cancel_preflight(&record)?;
        (
            cancel_output_from_record(
                &record,
                true,
                false,
                0,
                action == CancelPreflightAction::ReconcileWithoutDispatch,
            ),
            format!(
                "Cancellation preflight passed for {} at revision {}. No intent was written and no provider request was made.",
                record.local_job_id.as_str(),
                record.revision
            ),
        )
    } else {
        let store = JobStore::open_default()?;
        let initial = store.latest(&arguments.local_job_id)?;
        validate_cancel_preflight(&initial)?;
        let prepared = PreparedGithubJobSession::prepare_cancel(&store, &arguments.local_job_id)?;
        let receipt = execute_cancel_session(prepared, "user_requested")?;
        validate_cancel_completion(&initial, &receipt)?;
        let output = JobCancelOutputV1 {
            dry_run: false,
            local_job_id: receipt.local_job_id.as_str().to_owned(),
            revision: receipt.revision,
            state: job_state_name(receipt.state),
            cancellation_status: cancellation_status_name(receipt.cancellation_status),
            exact_resume_available: true,
            durable_intent_before_network: true,
            maximum_provider_cancel_requests: 1,
            provider_cancel_requests_made: receipt.provider_cancel_posts,
            intent_written: receipt.intent_written_by_this_call,
            get_only_reconciliation: receipt.get_only_reconciliation,
            provider_state: Some(provider_job_state_name(receipt.provider_state)),
            terminal_outcome: Some(build_outcome_name(receipt.terminal_outcome)),
            cleanup_status: cleanup_status_name(receipt.cleanup_status),
        };
        let summary = if receipt.terminal_outcome == StoredBuildOutcome::Cancelled {
            format!(
                "Cancellation and cleanup confirmed for {} at revision {}.",
                output.local_job_id, output.revision
            )
        } else {
            format!(
                "{} reached terminal outcome {} before cancellation; cleanup is confirmed.",
                output.local_job_id,
                build_outcome_name(receipt.terminal_outcome)
            )
        };
        (output, summary)
    };
    reporter.success("jobs-cancel", &output, || summary, &[]);
    Ok(())
}

fn validate_cancel_completion(
    initial: &StoredJobV1,
    receipt: &GithubCancellationSessionReceipt,
) -> Result<(), CliError> {
    let cancellation_status_matches = match receipt.terminal_outcome {
        StoredBuildOutcome::Cancelled => {
            receipt.cancellation_status == StoredCancellationStatus::Confirmed
        }
        StoredBuildOutcome::Succeeded
        | StoredBuildOutcome::Failed
        | StoredBuildOutcome::Expired => {
            receipt.cancellation_status == StoredCancellationStatus::Failed
        }
    };
    let terminal_state_matches = match receipt.terminal_outcome {
        StoredBuildOutcome::Succeeded => {
            receipt.state == StoredJobState::Succeeded
                && receipt.provider_state == JobState::Succeeded
        }
        StoredBuildOutcome::Failed => {
            receipt.state == StoredJobState::Failed && receipt.provider_state == JobState::Failed
        }
        StoredBuildOutcome::Cancelled => {
            receipt.state == StoredJobState::Cancelled
                && receipt.provider_state == JobState::Cancelled
        }
        StoredBuildOutcome::Expired => receipt.state == StoredJobState::Expired,
    };
    let pending_intent_mode_matches = if matches!(
        initial.cancellation_status,
        StoredCancellationStatus::Requested
            | StoredCancellationStatus::Dispatched
            | StoredCancellationStatus::Uncertain
    ) {
        receipt.get_only_reconciliation
            && !receipt.intent_written_by_this_call
            && receipt.provider_cancel_posts == 0
    } else {
        true
    };
    let preexisting_terminal_cancel_mode_matches = if matches!(
        initial.cancellation_status,
        StoredCancellationStatus::Confirmed | StoredCancellationStatus::Failed
    ) {
        !receipt.intent_written_by_this_call && receipt.provider_cancel_posts == 0
    } else {
        true
    };
    let revision_matches = receipt.revision >= initial.revision
        && (!receipt.intent_written_by_this_call || receipt.revision > initial.revision);
    let exact = receipt.local_job_id == initial.local_job_id
        && revision_matches
        && receipt.cleanup_status == StoredCleanupStatus::Confirmed
        && receipt.provider_cancel_posts <= 1
        && (!receipt.get_only_reconciliation || receipt.provider_cancel_posts == 0)
        && (receipt.intent_written_by_this_call || receipt.provider_cancel_posts == 0)
        && cancellation_status_matches
        && terminal_state_matches
        && pending_intent_mode_matches
        && preexisting_terminal_cancel_mode_matches;
    if exact {
        return Ok(());
    }
    Err(jobs_lifecycle_error(
        "cancellation_completion_identity_mismatch",
        "the completed cancellation receipt violates its durable intent, provider request, terminal, or cleanup contract",
        "Preserve the job and reconcile its exact provider and cleanup checkpoints before reporting success.",
        &receipt.local_job_id,
    ))
}

fn execute_cancel_session<Prepared, Durable, Bound, Receipt>(
    prepared: Prepared,
    reason: &str,
) -> Result<Receipt, CliError>
where
    Prepared: PreparedCancellationSession<Durable = Durable>,
    Durable: DurableCancellationSession<Bound = Bound>,
    Bound: BoundCancellationSession<Receipt = Receipt>,
{
    let cancellation = CancellationToken::new();
    let durable = prepared.persist_intent()?;
    let bound = durable.bind_live(&cancellation)?;
    bound.finish_cancel(reason, cancellation)
}

fn cancel_output_from_record(
    record: &StoredJobV1,
    dry_run: bool,
    intent_written: bool,
    provider_cancel_requests_made: u8,
    get_only_reconciliation: bool,
) -> JobCancelOutputV1 {
    JobCancelOutputV1 {
        dry_run,
        local_job_id: record.local_job_id.as_str().to_owned(),
        revision: record.revision,
        state: job_state_name(record.state),
        cancellation_status: cancellation_status_name(record.cancellation_status),
        exact_resume_available: record.provider_resume.is_some(),
        durable_intent_before_network: true,
        maximum_provider_cancel_requests: 1,
        provider_cancel_requests_made,
        intent_written,
        get_only_reconciliation,
        provider_state: record
            .provider_resume
            .as_ref()
            .map(|resume| provider_job_state_name(resume.state)),
        terminal_outcome: record.terminal_outcome.map(build_outcome_name),
        cleanup_status: cleanup_status_name(record.cleanup_status),
    }
}

fn retry(arguments: &JobsRetryArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    if arguments.use_current_source {
        return retry_current_source(arguments, dry_run, reporter);
    }
    if dry_run {
        let store = JobStore::open_default_read_only()?;
        let record = store.latest(&arguments.local_job_id)?;
        let persisted = persisted_retry_binding(&store, &record)?;
        let effective_force = persisted.as_ref().is_some_and(|binding| {
            binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
        }) || (persisted.is_none() && arguments.force);
        if let Some(binding) = persisted.as_ref() {
            let child = store.latest(&binding.child_job_id)?;
            validate_existing_retry_child_preflight(&record, binding, &child)?;
        }
        validate_retry_request(&record, effective_force, false)?;
        let output = retry_output_from_parent(&record, arguments.force, persisted.as_ref(), None)?;
        let summary = format!(
            "Retry preflight passed for {} at revision {} using the exact stored source. No child job was created.",
            output.parent_job_id, output.parent_revision
        );
        reporter.success("jobs-retry", &output, || summary, &[]);
        return Ok(());
    }

    let store = JobStore::open_default()?;
    let cancellation = CancellationToken::new();
    let receipt = execute_exact_retry_in_store(
        &store,
        &arguments.local_job_id,
        arguments.force,
        cancellation,
        reporter,
    )?;
    let completed_parent = store.latest(&arguments.local_job_id)?;
    let completed_binding = persisted_retry_binding(&store, &completed_parent)?;
    let output = retry_output_from_parent(
        &completed_parent,
        arguments.force,
        completed_binding.as_ref(),
        Some(&receipt),
    )?;
    let summary = retry_completion_summary(&receipt);
    // The completion receipt retains the exact project and artifact identities through rendering.
    reporter.success("jobs-retry", &output, || summary, &[]);
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "zero-write preview, explicit consent, leased staging, lineage, and completion stay visibly ordered"
)]
fn retry_current_source(
    arguments: &JobsRetryArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let cancellation = CancellationToken::new();
    let preview_store = JobStore::open_default_read_only()?;
    let parent = preview_store.latest(&arguments.local_job_id)?;
    let persisted = persisted_retry_binding(&preview_store, &parent)?;
    let effective_force = persisted.as_ref().is_some_and(|binding| {
        binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
    }) || (persisted.is_none() && arguments.force);
    validate_retry_request(&parent, effective_force, true)?;

    if persisted_retry_bypasses_recapture(&preview_store, &parent, persisted.as_ref())? {
        if dry_run {
            let output =
                retry_output_from_parent(&parent, arguments.force, persisted.as_ref(), None)?;
            let summary = format!(
                "Retry preflight passed for {} at revision {}; its durable child will resume through the persisted source policy without recapture.",
                output.parent_job_id, output.parent_revision
            );
            reporter.success("jobs-retry", &output, || summary, &[]);
            return Ok(());
        }
        drop(preview_store);
        let store = JobStore::open_default()?;
        let receipt = execute_exact_retry_in_store(
            &store,
            &arguments.local_job_id,
            arguments.force,
            cancellation,
            reporter,
        )?;
        let completed_parent = store.latest(&arguments.local_job_id)?;
        let completed_binding = persisted_retry_binding(&store, &completed_parent)?;
        let output = retry_output_from_parent(
            &completed_parent,
            arguments.force,
            completed_binding.as_ref(),
            Some(&receipt),
        )?;
        reporter.success(
            "jobs-retry",
            &output,
            || retry_completion_summary(&receipt),
            &[],
        );
        return Ok(());
    }

    let prepared = prepare_current_snapshot_retry_in_store(
        &preview_store,
        &parent,
        format!("ferry-{}", Uuid::new_v4().simple()),
        unix_time_ms()?,
        &cancellation,
    )?;
    let preview = prepared.preview().clone();
    reporter.progress(render_current_source_retry_preview(&preview));
    if dry_run {
        let mut output =
            retry_output_from_parent(&parent, arguments.force, persisted.as_ref(), None)?;
        output.source_policy = "recaptured_current_source";
        output.current_source_preview = Some(preview.clone());
        let summary = format!(
            "Current-source retry preview for {}: {} added, {} modified, {} removed; no stage, ref, lineage, or network write occurred.",
            output.parent_job_id,
            preview.diff.added_count,
            preview.diff.modified_count,
            preview.diff.removed_count,
        );
        reporter.success("jobs-retry", &output, || summary, &[]);
        return Ok(());
    }

    let confirmed = prepared.confirm(arguments.yes, reporter)?;
    let operation_id = preview.operation_id.clone();
    drop(preview_store);
    let store = JobStore::open_default()?;
    let initial_parent = store.latest(&arguments.local_job_id)?;
    let persisted = persisted_retry_binding(&store, &initial_parent)?;
    let effective_force = persisted.as_ref().is_some_and(|binding| {
        binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
    }) || (persisted.is_none() && arguments.force);
    let prepared_parent =
        PreparedGithubRetrySession::prepare_retry(&store, &arguments.local_job_id)?;
    let prepared_parent = validate_retry_parent_session(*prepared_parent, effective_force, true)?;
    let bound = bind_retry_parent_session(prepared_parent, &cancellation)?;
    let parent_policy = persisted.as_ref().map_or_else(
        || {
            if arguments.force {
                RetryParentPolicyV1::AllowSuccessful
            } else {
                RetryParentPolicyV1::RequireUnsuccessful
            }
        },
        |binding| binding.options.parent_policy,
    );
    let child = bound.create_or_resume_recaptured_git_snapshot_child(
        parent_policy,
        confirmed,
        &operation_id,
        LocalJobId::generate(),
        build_snapshot_retry_child,
        &cancellation,
    )?;
    let receipt = child.complete(cancellation, reporter)?;
    let completed_parent = store.latest(&arguments.local_job_id)?;
    validate_retry_completion(&store, &initial_parent, &completed_parent, &receipt)?;
    let completed_binding = persisted_retry_binding(&store, &completed_parent)?;
    let mut output = retry_output_from_parent(
        &completed_parent,
        arguments.force,
        completed_binding.as_ref(),
        Some(&receipt),
    )?;
    output.current_source_preview = Some(preview);
    reporter.success(
        "jobs-retry",
        &output,
        || retry_completion_summary(&receipt),
        &[],
    );
    Ok(())
}

fn persisted_retry_bypasses_recapture(
    store: &JobStore,
    parent: &StoredJobV1,
    binding: Option<&RetryLineageBindingV1>,
) -> Result<bool, CliError> {
    let Some(binding) = binding else {
        return Ok(false);
    };
    let child = store.latest(&binding.child_job_id)?;
    if parent.retry_lineage.child_job_ids.last() != Some(&child.local_job_id)
        || child.retry_lineage.parent_job_id.as_ref() != Some(&parent.local_job_id)
    {
        return Err(jobs_lifecycle_error(
            "retry_child_identity_mismatch",
            "the persisted current-source retry binding differs from its durable child",
            "Preserve the parent, child, and administrative lineage transaction for inspection.",
            &parent.local_job_id,
        ));
    }
    validate_existing_retry_child_base(parent, binding, &child)?;
    Ok(!matches!(
        binding.options.source_policy,
        RetrySourcePolicyV1::RecapturedGitSnapshot { .. }
    ) || child.provider_resume.is_some())
}

fn render_current_source_retry_preview(preview: &CurrentSnapshotRetryPreviewV1) -> String {
    use std::fmt::Write as _;

    let mut summary = format!(
        "Current-source retry preview {} (consent {}): {} file(s), {} byte(s); {} added, {} modified, {} removed",
        preview.operation_id,
        preview.snapshot_consent_sha256,
        preview.file_count,
        preview.total_bytes,
        preview.diff.added_count,
        preview.diff.modified_count,
        preview.diff.removed_count,
    );
    for (label, paths) in [
        ("added", &preview.diff.added_paths),
        ("modified", &preview.diff.modified_paths),
        ("removed", &preview.diff.removed_paths),
    ] {
        if !paths.is_empty() {
            let _ = write!(&mut summary, "\n  {label}: {}", paths.join(", "));
        }
    }
    if preview.diff.paths_truncated {
        summary.push_str("\n  paths: bounded summary truncated");
    }
    summary
}

struct PreparedExactRetry {
    parent: Box<StoredJobV1>,
    persisted: Option<RetryLineageBindingV1>,
    bound: BoundGithubRetrySession,
    parent_policy: RetryParentPolicyV1,
    effective_force: bool,
    exact_snapshot: bool,
}

struct ExactRetryPreflight {
    parent: Box<StoredJobV1>,
    persisted: Option<RetryLineageBindingV1>,
    parent_policy: RetryParentPolicyV1,
    effective_force: bool,
    exact_snapshot: bool,
}

fn execute_exact_retry_in_store(
    store: &JobStore,
    parent_job_id: &LocalJobId,
    force: bool,
    cancellation: CancellationToken,
    reporter: &Reporter,
) -> Result<GithubRetryCompletionReceipt, CliError> {
    let preflight = exact_retry_preflight(store, parent_job_id, force)?;
    let prepared = PreparedGithubRetrySession::prepare_retry(store, parent_job_id)?;
    let prepared = validate_retry_parent_session(*prepared, preflight.effective_force, false)?;
    let bound = bind_retry_parent_session(prepared, &cancellation)?;
    let bound = bound.validate_live_parent(|live_parent| {
        validate_retry_request(live_parent, preflight.effective_force, false)
    })?;
    let ExactRetryPreflight {
        parent,
        persisted,
        parent_policy,
        effective_force,
        exact_snapshot,
    } = *preflight;
    let prepared = Box::new(PreparedExactRetry {
        parent,
        persisted,
        bound,
        parent_policy,
        effective_force,
        exact_snapshot,
    });
    finish_exact_retry(store, parent_job_id, cancellation, reporter, prepared)
}

fn exact_retry_preflight(
    store: &JobStore,
    parent_job_id: &LocalJobId,
    force: bool,
) -> Result<Box<ExactRetryPreflight>, CliError> {
    let parent = Box::new(store.latest(parent_job_id)?);
    let persisted = persisted_retry_binding(store, &parent)?;
    if let Some(binding) = persisted.as_ref() {
        let child = store.latest(&binding.child_job_id)?;
        validate_existing_retry_child_preflight(&parent, binding, &child)?;
    }
    let effective_force = persisted.as_ref().is_some_and(|binding| {
        binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
    }) || (persisted.is_none() && force);
    validate_retry_request(&parent, effective_force, false)?;
    let parent_policy = persisted.as_ref().map_or_else(
        || {
            if force {
                RetryParentPolicyV1::AllowSuccessful
            } else {
                RetryParentPolicyV1::RequireUnsuccessful
            }
        },
        |binding| binding.options.parent_policy,
    );
    let exact_snapshot = persisted.as_ref().map_or(
        parent.request.source_mode == SourceMode::GitSnapshot,
        |binding| {
            matches!(
                binding.options.source_policy,
                RetrySourcePolicyV1::ExactGitSnapshot { .. }
            )
        },
    );
    Ok(Box::new(ExactRetryPreflight {
        parent,
        persisted,
        parent_policy,
        effective_force,
        exact_snapshot,
    }))
}

fn finish_exact_retry(
    store: &JobStore,
    parent_job_id: &LocalJobId,
    cancellation: CancellationToken,
    reporter: &Reporter,
    prepared: Box<PreparedExactRetry>,
) -> Result<GithubRetryCompletionReceipt, CliError> {
    let PreparedExactRetry {
        parent,
        persisted,
        bound,
        parent_policy,
        effective_force,
        exact_snapshot,
    } = *prepared;
    let receipt = if exact_snapshot {
        let child = bound.create_or_resume_exact_git_snapshot_child(
            parent_policy,
            LocalJobId::generate(),
            format!("ferry-{}", Uuid::new_v4().simple()),
            unix_time_ms()?,
            build_snapshot_retry_child,
            &cancellation,
        )?;
        child.complete(cancellation, reporter)?
    } else {
        let options = persisted.as_ref().map_or_else(
            || RetryLineageOptionsV1 {
                parent_policy,
                source_policy: RetrySourcePolicyV1::Exact,
            },
            |binding| binding.options.clone(),
        );
        execute_bound_retry_session(
            bound,
            &options,
            |leased_parent| {
                validate_retry_preflight(leased_parent, effective_force)?;
                new_exact_retry_child(leased_parent, unix_time_ms()?)
            },
            cancellation,
            reporter,
        )?
    };
    let completed_parent = store.latest(parent_job_id)?;
    validate_retry_completion(store, &parent, &completed_parent, &receipt)?;
    Ok(receipt)
}

fn persisted_retry_binding(
    store: &JobStore,
    parent: &StoredJobV1,
) -> Result<Option<RetryLineageBindingV1>, CliError> {
    parent
        .retry_lineage
        .child_job_ids
        .last()
        .map(|child_job_id| store.retry_lineage_binding(&parent.local_job_id, child_job_id))
        .transpose()
        .map_err(Into::into)
}

fn validate_existing_retry_child_preflight(
    parent: &StoredJobV1,
    binding: &RetryLineageBindingV1,
    child: &StoredJobV1,
) -> Result<(), CliError> {
    validate_existing_retry_child_base(parent, binding, child)?;
    if matches!(
        binding.options.source_policy,
        RetrySourcePolicyV1::RecapturedGitSnapshot { .. }
    ) && child.provider_resume.is_none()
    {
        return Err(jobs_lifecycle_error(
            "retry_current_source_consent_required",
            "the durable current-source retry child has no provider checkpoint and requires fresh source consent",
            "Resume it through `jobs retry --use-current-source --yes`; exact retry never recaptures source implicitly.",
            &parent.local_job_id,
        ));
    }
    Ok(())
}

fn validate_existing_retry_child_base(
    parent: &StoredJobV1,
    binding: &RetryLineageBindingV1,
    child: &StoredJobV1,
) -> Result<(), CliError> {
    if binding.child_job_id != child.local_job_id
        || binding.child_operation_id != child.operation_id
    {
        return Err(jobs_lifecycle_error(
            "retry_child_identity_mismatch",
            "the latest retry child differs from its immutable lineage binding",
            "Preserve the retry lineage and reconcile its durable transaction.",
            &parent.local_job_id,
        ));
    }
    if job_lifecycle_is_settled(child)
        && !(child.state == StoredJobState::Succeeded
            && child.terminal_outcome == Some(StoredBuildOutcome::Succeeded)
            && child.cleanup_status == StoredCleanupStatus::Confirmed
            && child.failure.is_none())
    {
        return Err(jobs_lifecycle_error(
            "retry_child_already_settled",
            "the parent already has a settled retry child that cannot be resumed",
            "Inspect the existing child; exact retry never creates a sibling behind it.",
            &parent.local_job_id,
        ));
    }
    Ok(())
}

fn retry_completion_summary(receipt: &GithubRetryCompletionReceipt) -> String {
    match receipt.disposition {
        GithubRetryChildDisposition::Created => format!(
            "Exact retry child {} succeeded with {} validated artifact(s); cleanup confirmed.",
            receipt.child_job_id.as_str(),
            receipt.artifacts.len()
        ),
        GithubRetryChildDisposition::Existing => format!(
            "Recovered exact successful retry child {} with {} validated artifact(s); cleanup confirmed.",
            receipt.child_job_id.as_str(),
            receipt.artifacts.len()
        ),
    }
}

#[cfg(test)]
fn execute_after_retry_preflight<T>(
    record: &StoredJobV1,
    force: bool,
    use_current_source: bool,
    action: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    validate_retry_request(record, force, use_current_source)?;
    action()
}

fn validate_retry_request(
    record: &StoredJobV1,
    force: bool,
    _use_current_source: bool,
) -> Result<(), CliError> {
    validate_retry_preflight(record, force)?;
    Ok(())
}

fn validate_retry_completion(
    store: &JobStore,
    initial_parent: &StoredJobV1,
    latest_parent: &StoredJobV1,
    receipt: &GithubRetryCompletionReceipt,
) -> Result<(), CliError> {
    let lineage_revision_matches = match receipt.disposition {
        GithubRetryChildDisposition::Created => receipt.parent_revision > initial_parent.revision,
        GithubRetryChildDisposition::Existing => receipt.parent_revision >= initial_parent.revision,
    };
    let binding =
        store.retry_lineage_binding(&latest_parent.local_job_id, &receipt.child_job_id)?;
    let child_initial = store.revision(&receipt.child_job_id, 1)?;
    let source_policy_matches = match &binding.options.source_policy {
        RetrySourcePolicyV1::Exact => {
            latest_parent.request.source_mode != SourceMode::GitSnapshot
                && child_initial.source == latest_parent.source
                && child_initial.semantic_retry_sha256 == latest_parent.semantic_retry_sha256
        }
        RetrySourcePolicyV1::ExactGitSnapshot { .. } => {
            latest_parent.request.source_mode == SourceMode::GitSnapshot
                && child_initial.request.source_mode == SourceMode::GitSnapshot
        }
        RetrySourcePolicyV1::RecapturedGitSnapshot { .. } => {
            child_initial.request.source_mode == SourceMode::GitSnapshot
        }
    };
    let child_lineage_count = latest_parent
        .retry_lineage
        .child_job_ids
        .iter()
        .filter(|child| *child == &receipt.child_job_id)
        .count();
    let complete = initial_parent.local_job_id == latest_parent.local_job_id
        && initial_parent.semantic_retry_sha256 == latest_parent.semantic_retry_sha256
        && initial_parent.source == latest_parent.source
        && receipt.parent_job_id == latest_parent.local_job_id
        && lineage_revision_matches
        && receipt.parent_revision <= latest_parent.revision
        && child_lineage_count == 1
        && receipt.child_job_id != latest_parent.local_job_id
        && receipt.child_revision > 0
        && receipt.operation_id != latest_parent.operation_id
        && binding.child_job_id == receipt.child_job_id
        && binding.child_operation_id == receipt.operation_id
        && binding.parent_next_revision <= receipt.parent_revision
        && child_initial.operation_id == receipt.operation_id
        && child_initial.request_sha256 == receipt.request_sha256
        && child_initial.semantic_retry_sha256 == receipt.semantic_retry_sha256
        && child_initial.source.revision == receipt.source_revision
        && child_initial.source.manifest_sha256 == receipt.source_manifest_sha256
        && source_policy_matches
        && receipt.state == StoredJobState::Succeeded
        && receipt.terminal_outcome == StoredBuildOutcome::Succeeded
        && receipt.cleanup_status == StoredCleanupStatus::Confirmed
        && !receipt.provider_job_id.is_empty()
        && receipt
            .provider_run_id
            .as_deref()
            .is_some_and(|run_id| !run_id.is_empty())
        && !receipt.artifacts.is_empty()
        && receipt.artifacts.iter().all(|artifact| {
            !artifact.artifact_id.is_empty()
                && is_lower_sha256(&artifact.sha256)
                && !artifact.local_path.is_empty()
        });
    if complete {
        return Ok(());
    }
    Err(jobs_lifecycle_error(
        "retry_completion_identity_mismatch",
        "the completed retry receipt differs from its exact parent or validated artifact lifecycle",
        "Preserve both job IDs and inspect their immutable provider, source, artifact, and cleanup evidence.",
        &latest_parent.local_job_id,
    ))
}

#[cfg(test)]
fn validate_retry_completion_evidence(
    initial_parent: &StoredJobV1,
    latest_parent: &StoredJobV1,
    receipt: &GithubRetryCompletionReceipt,
) -> Result<(), CliError> {
    let lineage_revision_matches = match receipt.disposition {
        GithubRetryChildDisposition::Created => receipt.parent_revision > initial_parent.revision,
        GithubRetryChildDisposition::Existing => receipt.parent_revision >= initial_parent.revision,
    };
    let mut expected_child_request = latest_parent.request.clone();
    expected_child_request
        .operation_id
        .clone_from(&receipt.operation_id);
    let expected_request_sha256 = canonical_request_sha256(&expected_child_request).ok();
    let expected_semantic_sha256 = canonical_retry_template_sha256_v1(&expected_child_request).ok();
    let child_lineage_count = latest_parent
        .retry_lineage
        .child_job_ids
        .iter()
        .filter(|child| *child == &receipt.child_job_id)
        .count();
    if initial_parent.local_job_id == latest_parent.local_job_id
        && initial_parent.semantic_retry_sha256 == latest_parent.semantic_retry_sha256
        && initial_parent.source == latest_parent.source
        && receipt.parent_job_id == latest_parent.local_job_id
        && lineage_revision_matches
        && receipt.parent_revision <= latest_parent.revision
        && child_lineage_count == 1
        && receipt.child_job_id != latest_parent.local_job_id
        && receipt.child_revision > 0
        && receipt.operation_id != latest_parent.operation_id
        && expected_request_sha256.as_deref() == Some(receipt.request_sha256.as_str())
        && expected_semantic_sha256.as_deref() == Some(receipt.semantic_retry_sha256.as_str())
        && receipt.semantic_retry_sha256 == latest_parent.semantic_retry_sha256
        && receipt.source_revision == latest_parent.source.revision
        && receipt.source_manifest_sha256 == latest_parent.source.manifest_sha256
        && receipt.state == StoredJobState::Succeeded
        && receipt.terminal_outcome == StoredBuildOutcome::Succeeded
        && receipt.cleanup_status == StoredCleanupStatus::Confirmed
        && !receipt.provider_job_id.is_empty()
        && receipt
            .provider_run_id
            .as_deref()
            .is_some_and(|run_id| !run_id.is_empty())
        && !receipt.artifacts.is_empty()
        && receipt.artifacts.iter().all(|artifact| {
            !artifact.artifact_id.is_empty()
                && is_lower_sha256(&artifact.sha256)
                && !artifact.local_path.is_empty()
        })
    {
        return Ok(());
    }
    Err(jobs_lifecycle_error(
        "retry_completion_identity_mismatch",
        "the completed retry receipt differs from its exact parent or validated artifact lifecycle",
        "Preserve both job IDs and inspect their immutable provider, source, artifact, and cleanup evidence.",
        &latest_parent.local_job_id,
    ))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bind_retry_parent_session<Prepared, Bound>(
    prepared: Prepared,
    cancellation: &CancellationToken,
) -> Result<Bound, CliError>
where
    Prepared: PreparedRetrySession<Bound = Bound>,
    Bound: BoundRetrySession,
{
    prepared.bind_parent(cancellation)
}

fn validate_retry_parent_session<Prepared>(
    prepared: Prepared,
    force: bool,
    use_current_source: bool,
) -> Result<Prepared, CliError>
where
    Prepared: PreparedRetrySession,
{
    prepared.validate_parent(|leased_parent| {
        validate_retry_request(leased_parent, force, use_current_source)
    })
}

fn execute_bound_retry_session<Bound, Child, Receipt, MakeChild>(
    bound: Bound,
    options: &RetryLineageOptionsV1,
    make_child: MakeChild,
    cancellation: CancellationToken,
    reporter: &Reporter,
) -> Result<Receipt, CliError>
where
    Bound: BoundRetrySession<Child = Child>,
    Child: RetryChildSession<Receipt = Receipt>,
    MakeChild: FnOnce(&StoredJobV1) -> Result<StoredJobV1, CliError>,
{
    let child = bound.create_or_resume_child(options, make_child)?;
    child.complete(cancellation, reporter)
}

fn retry_output_from_parent(
    parent: &StoredJobV1,
    requested_force: bool,
    binding: Option<&RetryLineageBindingV1>,
    receipt: Option<&GithubRetryCompletionReceipt>,
) -> Result<JobRetryOutputV1, CliError> {
    let Some(outcome) = parent.terminal_outcome.map(build_outcome_name) else {
        return Err(jobs_lifecycle_error(
            "job_not_retryable",
            "retry requires an exact terminal outcome",
            "Wait for an exact terminal outcome and reconcile any unknown state first.",
            &parent.local_job_id,
        ));
    };
    let disposition = receipt.map(|receipt| receipt.disposition);
    let force = binding.map_or(requested_force, |binding| {
        binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
    });
    let source_policy = binding.map_or("exact_stored_source", |binding| {
        retry_source_policy_name(&binding.options.source_policy)
    });
    Ok(JobRetryOutputV1 {
        dry_run: receipt.is_none(),
        parent_job_id: parent.local_job_id.as_str().to_owned(),
        parent_revision: receipt.map_or(parent.revision, |receipt| receipt.parent_revision),
        parent_state: job_state_name(parent.state),
        parent_outcome: outcome,
        force,
        source_policy,
        source_revision: receipt.map_or_else(
            || parent.source.revision.clone(),
            |receipt| receipt.source_revision.clone(),
        ),
        source_manifest_sha256: receipt.map_or_else(
            || parent.source.manifest_sha256.clone(),
            |receipt| receipt.source_manifest_sha256.clone(),
        ),
        current_source_preview: None,
        atomic_lineage_required: true,
        child_created: disposition == Some(GithubRetryChildDisposition::Created),
        resumed_existing_child: disposition == Some(GithubRetryChildDisposition::Existing),
        child_local_job_id: receipt.map(|receipt| receipt.child_job_id.as_str().to_owned()),
        child_revision: receipt.map(|receipt| receipt.child_revision),
        child_state: receipt.map(|receipt| job_state_name(receipt.state)),
        child_operation_id: receipt.map(|receipt| receipt.operation_id.clone()),
        child_request_sha256: receipt.map(|receipt| receipt.request_sha256.clone()),
        child_semantic_retry_sha256: receipt.map(|receipt| receipt.semantic_retry_sha256.clone()),
        child_terminal_outcome: receipt.map(|receipt| build_outcome_name(receipt.terminal_outcome)),
        cleanup_status: receipt.map(|receipt| cleanup_status_name(receipt.cleanup_status)),
        provider_job_id: receipt.map(|receipt| receipt.provider_job_id.clone()),
        provider_run_id: receipt.and_then(|receipt| receipt.provider_run_id.clone()),
        submission_confirmed: receipt.is_some(),
        completion_confirmed: receipt.is_some(),
        validated_artifact_count: receipt.map_or(0, |receipt| receipt.artifacts.len()),
        artifacts: receipt.map_or_else(Vec::new, |receipt| {
            receipt
                .artifacts
                .iter()
                .map(|artifact| JobRetryArtifactV1 {
                    artifact_id: artifact.artifact_id.clone(),
                    sha256: artifact.sha256.clone(),
                    local_path: artifact.local_path.clone(),
                })
                .collect()
        }),
    })
}

fn retry_source_policy_name(source_policy: &RetrySourcePolicyV1) -> &'static str {
    match source_policy {
        RetrySourcePolicyV1::Exact | RetrySourcePolicyV1::ExactGitSnapshot { .. } => {
            "exact_stored_source"
        }
        RetrySourcePolicyV1::RecapturedGitSnapshot { .. } => "recaptured_current_source",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the CLI keeps consent, retained leases, provider release, exact replan, and deletion visibly ordered"
)]
fn prune(arguments: &JobsPruneArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let preview_store = JobStore::open_default_read_only()?;
    let pending_release = preview_store.pending_prune_release_plan()?;
    let plan = if let Some(plan) = pending_release.clone() {
        plan
    } else {
        preview_store.plan_prune(arguments.before, arguments.max_jobs)?
    };
    if !dry_run && !plan.candidates.is_empty() && !arguments.yes {
        return Err(CliError::JobsLifecycle {
            code: "prune_confirmation_required",
            message: format!(
                "refusing to prune {} exact terminal job(s) without confirmation",
                plan.candidates.len()
            ),
            help: "Review `cargo ferry --dry-run jobs prune --before <UNIX_MS>`, then repeat the exact command with --yes.".to_owned(),
            details: vec![format!("planned_jobs={}", plan.candidates.len())],
        });
    }
    let candidates = plan
        .candidates
        .iter()
        .map(JobPruneCandidateV1::from)
        .collect::<Vec<_>>();
    let (executed, transaction_sha256, already_complete, pruned_job_ids) =
        if dry_run || plan.candidates.is_empty() {
            (false, None, None, Vec::new())
        } else {
            drop(preview_store);
            let store = JobStore::open_default()?;
            let lease_set = if let Some(lease_set) = store.resume_prune_release_leases()? {
                let resumed = store.pending_prune_release_plan()?.ok_or_else(|| {
                    CliError::JobsLifecycle {
                    code: "prune_release_authorization_lost",
                    message: "the durable prune release authorization disappeared during recovery"
                        .to_owned(),
                    help: "Preserve the job store and inspect its immutable administrative journal."
                        .to_owned(),
                    details: Vec::new(),
                }
                })?;
                if resumed != plan {
                    return Err(CliError::JobsLifecycle {
                        code: "prune_plan_changed",
                        message: "the durable prune recovery plan changed before execution"
                            .to_owned(),
                        help:
                            "Run the dry-run again and confirm the recovered complete-lineage plan."
                                .to_owned(),
                        details: vec![
                            format!("preview_jobs={}", plan.candidates.len()),
                            format!("revalidated_jobs={}", resumed.candidates.len()),
                        ],
                    });
                }
                lease_set
            } else {
                let revalidated = store.plan_prune(arguments.before, arguments.max_jobs)?;
                if revalidated != plan {
                    return Err(CliError::JobsLifecycle {
                        code: "prune_plan_changed",
                        message: "the exact prune plan changed before execution".to_owned(),
                        help: "Run the dry-run again and confirm the new complete-lineage plan."
                            .to_owned(),
                        details: vec![
                            format!("preview_jobs={}", plan.candidates.len()),
                            format!("revalidated_jobs={}", revalidated.candidates.len()),
                        ],
                    });
                }
                store.acquire_prune_leases(&revalidated)?
            };
            let cancellation = CancellationToken::new();
            for release in store.snapshot_keepalive_releases(&lease_set)? {
                let authorization = GithubGitSnapshotKeepaliveReleaseAuthorizationV1::new(
                    release.operation_id,
                    release.complete_lineage_authorization_sha256,
                )
                .map_err(|_| CliError::JobsLifecycle {
                    code: "snapshot_prune_authorization_invalid",
                    message: "the durable snapshot prune authorization is invalid".to_owned(),
                    help: "Preserve the job store and inspect the exact complete-lineage journal."
                        .to_owned(),
                    details: vec![format!("local_job_id={}", release.local_job_id.as_str())],
                })?;
                let lease = lease_set.lease(&release.local_job_id).ok_or_else(|| {
                    CliError::JobsLifecycle {
                        code: "prune_lease_missing",
                        message: "the complete prune lease set omitted a snapshot job".to_owned(),
                        help: "Stop and recover the durable complete-lineage prune authorization."
                            .to_owned(),
                        details: vec![format!("local_job_id={}", release.local_job_id.as_str())],
                    }
                })?;
                PreparedGithubJobSession::release_snapshot_keepalive_for_prune(
                    &store,
                    &release.local_job_id,
                    lease,
                    &authorization,
                    &cancellation,
                )?;
            }
            let post_release_plan = store.replan_prune_after_keepalive_releases(&lease_set)?;
            if !plan.candidates.is_empty()
                && post_release_plan.candidates.len() != plan.candidates.len()
            {
                return Err(CliError::JobsLifecycle {
                    code: "prune_plan_changed",
                    message: "the complete-lineage prune plan changed after snapshot release"
                        .to_owned(),
                    help: "Preserve the durable authorization and resume the same prune command."
                        .to_owned(),
                    details: vec![
                        format!("preview_jobs={}", plan.candidates.len()),
                        format!("revalidated_jobs={}", post_release_plan.candidates.len()),
                    ],
                });
            }
            let receipt = store.prune(lease_set, &post_release_plan, unix_time_ms()?)?;
            (
                true,
                Some(receipt.transaction_sha256),
                Some(receipt.already_complete),
                receipt
                    .pruned_job_ids
                    .into_iter()
                    .map(|identifier| identifier.as_str().to_owned())
                    .collect(),
            )
        };
    let output = JobPruneOutputV1 {
        dry_run,
        terminal_before_ms: plan.terminal_before_ms,
        max_jobs: plan.selection_max_jobs,
        confirmation_provided: arguments.yes,
        planned: candidates.len(),
        executed,
        transaction_sha256,
        already_complete,
        pruned_job_ids,
        candidates,
    };
    let warnings = if output.candidates.is_empty() {
        vec![
            "No eligible complete terminal lineages were selected. A job with a downloaded artifact remains ineligible until each artifact is removed with `cargo ferry artifact remove <provider-artifact-id> --job <local-job-id> --yes`."
                .to_owned(),
        ]
    } else if pending_release.is_some() {
        vec![
            "Resuming the durable prune release authorization shown above; newly supplied cutoff and maximum values do not replace it."
                .to_owned(),
        ]
    } else {
        Vec::new()
    };
    reporter.success(
        "jobs-prune",
        &output,
        || render_job_prune(&output),
        &warnings,
    );
    Ok(())
}

fn validate_cancel_preflight(record: &StoredJobV1) -> Result<CancelPreflightAction, CliError> {
    let terminal = record.terminal_outcome.is_some()
        || matches!(
            record.state,
            StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::CleanupFailed
                | StoredJobState::Expired
        );
    if terminal && record.cancellation_status == StoredCancellationStatus::NotRequested {
        return Err(jobs_lifecycle_error(
            "job_not_cancellable",
            "the selected job already has a terminal outcome",
            "Use `cargo ferry jobs show <local-job-id>` to inspect its final state.",
            &record.local_job_id,
        ));
    }
    if record.provider_resume.is_none() {
        return Err(jobs_lifecycle_error(
            "cancel_resume_unavailable",
            "the selected job has no complete durable provider resume identity",
            "Inspect the job record and recover its exact provider checkpoint before cancellation.",
            &record.local_job_id,
        ));
    }
    if record.provider_job_id.is_none() {
        return Err(jobs_lifecycle_error(
            "cancel_resume_unavailable",
            "the selected job has no complete durable provider resume identity",
            "Inspect the job record and recover its exact provider checkpoint before cancellation.",
            &record.local_job_id,
        ));
    }
    if terminal {
        return Ok(CancelPreflightAction::ReconcileWithoutDispatch);
    }
    let action = match record.cancellation_status {
        StoredCancellationStatus::NotRequested => CancelPreflightAction::PersistIntentThenDispatch,
        StoredCancellationStatus::Requested
        | StoredCancellationStatus::Dispatched
        | StoredCancellationStatus::Uncertain => CancelPreflightAction::ReconcileWithoutDispatch,
        StoredCancellationStatus::Confirmed | StoredCancellationStatus::Failed => {
            return Err(jobs_lifecycle_error(
                "cancel_already_terminal",
                "the selected job already has a durable cancellation result",
                "Use `cargo ferry jobs show <local-job-id>` to inspect its final state.",
                &record.local_job_id,
            ));
        }
    };
    Ok(action)
}

fn validate_retry_preflight(record: &StoredJobV1, force: bool) -> Result<(), CliError> {
    let successful = record.state == StoredJobState::Succeeded
        && record.terminal_outcome == Some(StoredBuildOutcome::Succeeded);
    let unsuccessful = matches!(
        record.state,
        StoredJobState::Failed | StoredJobState::Cancelled | StoredJobState::Expired
    ) && matches!(
        record.terminal_outcome,
        Some(
            StoredBuildOutcome::Failed
                | StoredBuildOutcome::Cancelled
                | StoredBuildOutcome::Expired
        )
    );
    if successful && !force {
        return Err(jobs_lifecycle_error(
            "retry_force_required",
            "retrying a successful job requires explicit --force",
            "Review the successful job, then repeat with --force only if a new provider run is intended.",
            &record.local_job_id,
        ));
    }
    if force && !successful {
        return Err(jobs_lifecycle_error(
            "retry_force_not_applicable",
            "--force is accepted only for a fully evidenced successful job",
            "Omit --force when retrying a failed, cancelled, or expired job.",
            &record.local_job_id,
        ));
    }
    if !(successful || unsuccessful) {
        return Err(jobs_lifecycle_error(
            "job_not_retryable",
            "retry requires an exact failed, cancelled, expired, or explicitly forced successful parent",
            "Wait for an exact terminal outcome and reconcile any unknown or uncertain state first.",
            &record.local_job_id,
        ));
    }
    let has_provider_obligations = record.provider_job_id.is_some()
        || record.provider_run_id.is_some()
        || record.provider_resume.is_some()
        || record.submitted_at_ms.is_some();
    let cleanup_safe = record.cleanup_status == StoredCleanupStatus::Confirmed
        || (record.cleanup_status == StoredCleanupStatus::NotStarted && !has_provider_obligations);
    if !cleanup_safe {
        return Err(jobs_lifecycle_error(
            "retry_cleanup_not_safe",
            "retry requires exact cleanup confirmation whenever provider-side obligations exist",
            "Reconcile cleanup before creating another provider attempt.",
            &record.local_job_id,
        ));
    }
    validate_retry_cancellation(record)?;
    if record.state == StoredJobState::Failed
        && !record
            .failure
            .as_ref()
            .is_some_and(|failure| failure.retryable)
    {
        return Err(jobs_lifecycle_error(
            "job_failure_not_retryable",
            "the stored terminal failure is not marked retryable",
            "Inspect the failure code and correct the underlying request or configuration.",
            &record.local_job_id,
        ));
    }
    if successful
        && (record.provider_resume.is_none()
            || record.compile_evidence.is_none()
            || record.cleanup_status != StoredCleanupStatus::Confirmed)
    {
        return Err(jobs_lifecycle_error(
            "successful_retry_evidence_incomplete",
            "the successful parent lacks the complete evidence required for forced retry",
            "Preserve and reconcile provider, compile, and cleanup evidence before retrying.",
            &record.local_job_id,
        ));
    }
    Ok(())
}

fn validate_retry_cancellation(record: &StoredJobV1) -> Result<(), CliError> {
    let mismatch = |message| {
        jobs_lifecycle_error(
            "retry_cancellation_outcome_mismatch",
            message,
            "Reconcile the cancellation outcome before creating another attempt.",
            &record.local_job_id,
        )
    };
    match record.cancellation_status {
        StoredCancellationStatus::Requested | StoredCancellationStatus::Dispatched => {
            Err(jobs_lifecycle_error(
                "retry_cancellation_pending",
                "retry is blocked by a pending or dispatched cancellation intent",
                "Reconcile the exact provider cancellation before creating another attempt.",
                &record.local_job_id,
            ))
        }
        StoredCancellationStatus::Uncertain => Err(jobs_lifecycle_error(
            "retry_cancellation_uncertain",
            "retry is blocked by an uncertain cancellation result",
            "Reconcile the exact provider cancellation before creating another attempt.",
            &record.local_job_id,
        )),
        StoredCancellationStatus::NotRequested
            if record.terminal_outcome == Some(StoredBuildOutcome::Cancelled) =>
        {
            Err(mismatch(
                "the cancelled parent lacks exact cancellation confirmation",
            ))
        }
        StoredCancellationStatus::Confirmed
            if record.terminal_outcome != Some(StoredBuildOutcome::Cancelled) =>
        {
            Err(mismatch(
                "the cancellation confirmation contradicts the parent terminal outcome",
            ))
        }
        StoredCancellationStatus::Failed
            if record.terminal_outcome == Some(StoredBuildOutcome::Cancelled) =>
        {
            Err(mismatch(
                "the failed cancellation result contradicts the cancelled parent outcome",
            ))
        }
        StoredCancellationStatus::NotRequested
        | StoredCancellationStatus::Confirmed
        | StoredCancellationStatus::Failed => Ok(()),
    }
}

fn new_exact_retry_child(
    parent: &StoredJobV1,
    created_at_ms: u64,
) -> Result<StoredJobV1, CliError> {
    build_exact_retry_child(
        parent,
        LocalJobId::generate(),
        format!("ferry-{}", Uuid::new_v4().simple()),
        created_at_ms,
    )
}

fn build_exact_retry_child(
    parent: &StoredJobV1,
    local_job_id: LocalJobId,
    operation_id: String,
    created_at_ms: u64,
) -> Result<StoredJobV1, CliError> {
    let mut request = parent.request.clone();
    request.operation_id = operation_id;
    let child = build_retry_child_from_request(
        parent,
        local_job_id,
        request,
        created_at_ms.max(parent.updated_at_ms),
    )?;
    if child.semantic_retry_sha256 != parent.semantic_retry_sha256 {
        return Err(jobs_lifecycle_error(
            "retry_semantic_identity_mismatch",
            "rebinding the retry operation changed the stored semantic request identity",
            "Do not submit the child; preserve and inspect the immutable parent record.",
            &parent.local_job_id,
        ));
    }
    Ok(child)
}

fn build_snapshot_retry_child(
    parent: &StoredJobV1,
    local_job_id: LocalJobId,
    request: IosDeviceBuildRequest,
    created_at_ms: u64,
) -> Result<StoredJobV1, CliError> {
    if request.source_mode != SourceMode::GitSnapshot {
        return Err(jobs_lifecycle_error(
            "retry_snapshot_request_invalid",
            "the retained snapshot retry plan did not produce a Git snapshot request",
            "Preserve the parent keepalive and inspect the provider retry plan.",
            &parent.local_job_id,
        ));
    }
    build_retry_child_from_request(
        parent,
        local_job_id,
        request,
        created_at_ms.max(parent.created_at_ms),
    )
}

fn build_retry_child_from_request(
    parent: &StoredJobV1,
    local_job_id: LocalJobId,
    request: IosDeviceBuildRequest,
    created_at_ms: u64,
) -> Result<StoredJobV1, CliError> {
    let attempt = parent.retry_lineage.attempt.checked_add(1).ok_or_else(|| {
        jobs_lifecycle_error(
            "retry_attempt_exhausted",
            "the retry attempt counter cannot advance",
            "Preserve the existing lineage and do not create another retry child.",
            &parent.local_job_id,
        )
    })?;
    let operation_id = request.operation_id.clone();
    let request_sha256 = canonical_request_sha256(&request).map_err(|_| {
        jobs_lifecycle_error(
            "retry_request_invalid",
            "the planned retry request cannot be hashed canonically",
            "Preserve the parent record and inspect its validated request identity.",
            &parent.local_job_id,
        )
    })?;
    let semantic_retry_sha256 = canonical_retry_template_sha256_v1(&request).map_err(|_| {
        jobs_lifecycle_error(
            "retry_request_invalid",
            "the exact stored request has no canonical retry identity",
            "Preserve the parent record and inspect its validated request identity.",
            &parent.local_job_id,
        )
    })?;
    let source = cargo_ferry::job_store::StoredSourceIdentityV1 {
        revision: request.source_revision.clone(),
        manifest_sha256: request.source.sha256.clone(),
    };
    let child = StoredJobV1 {
        schema_version: parent.schema_version,
        local_job_id,
        revision: 1,
        project: parent.project.clone(),
        provider: parent.provider.clone(),
        provider_job_id: None,
        provider_run_id: None,
        operation_id,
        request,
        request_sha256,
        semantic_retry_sha256,
        source,
        target: parent.target.clone(),
        profile: parent.profile,
        signing_mode: parent.signing_mode,
        created_at_ms,
        submitted_at_ms: None,
        updated_at_ms: created_at_ms,
        state: StoredJobState::SourceReady,
        last_confirmed_state: Some(StoredJobState::SourceReady),
        terminal_outcome: None,
        compile_evidence: None,
        signed_cleanup_evidence: None,
        artifacts: Vec::new(),
        log_location: None,
        cleanup_status: StoredCleanupStatus::NotStarted,
        retry_lineage: StoredRetryLineageV1 {
            attempt,
            parent_job_id: Some(parent.local_job_id.clone()),
            child_job_ids: Vec::new(),
        },
        cancellation_status: StoredCancellationStatus::NotRequested,
        failure: None,
        provider_resume: None,
    };
    child.validate()?;
    Ok(child)
}

fn jobs_lifecycle_error(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    local_job_id: &LocalJobId,
) -> CliError {
    CliError::JobsLifecycle {
        code,
        message: message.into(),
        help: help.into(),
        details: vec![format!("local_job_id={}", local_job_id.as_str())],
    }
}

fn unix_time_ms() -> Result<u64, CliError> {
    let elapsed =
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CliError::JobsLifecycle {
                code: "system_clock_invalid",
                message: "the system clock predates the Unix epoch".to_owned(),
                help: "Correct the system clock before committing a durable job-store mutation."
                    .to_owned(),
                details: Vec::new(),
            })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| CliError::JobsLifecycle {
        code: "system_clock_invalid",
        message: "the system clock is outside the supported millisecond range".to_owned(),
        help: "Correct the system clock before committing a durable job-store mutation.".to_owned(),
        details: Vec::new(),
    })
}

fn event_matches_filters(event: &ManagedJobEventV1, since_ms: u64, phase: Option<&str>) -> bool {
    event.occurred_at_ms >= since_ms
        && phase.is_none_or(|phase| event.phase.as_deref() == Some(phase))
}

fn durable_worker_log_identity(record: &StoredJobV1) -> Option<GithubDurableRunAttemptLogIdentity> {
    let resume = record.provider_resume.as_ref()?;
    let run = resume.run.as_ref()?;
    let expected_run_id = run.run_id.to_string();
    if run.status != GithubRunStatusV1::Completed
        || run.conclusion.is_none()
        || record.provider_run_id.as_deref() != Some(expected_run_id.as_str())
    {
        return None;
    }
    let endpoint = GithubGitEndpoint::parse(&resume.execution_repository).ok()?;
    GithubDurableRunAttemptLogIdentity::new(
        endpoint.repository().clone(),
        RunId::new(run.run_id).ok()?,
        run.run_attempt,
        CommitSha::new(run.head_sha.clone()).ok()?,
        WorkflowId::new(run.workflow_id).ok()?,
    )
    .ok()
}

fn provider_logs_incomplete_error(local_job_id: &LocalJobId) -> CliError {
    jobs_lifecycle_error(
        "provider_logs_incomplete",
        "the exact terminal GitHub attempt did not yield a durable complete worker-log marker within the bounded refresh",
        "Preserve the emitted durable events and retry jobs logs later; no raw or partial provider response was accepted as complete.",
        local_job_id,
    )
}

fn validate_log_ingest_status(
    record: &StoredJobV1,
    status: &ProviderLogIngestStatus,
) -> Result<(), CliError> {
    let Some(revision) = status.revision else {
        return Ok(());
    };
    if revision == record.revision
        && (status.provider_fetch_performed == (status.durable_records_observed > 0))
    {
        return Ok(());
    }
    Err(jobs_lifecycle_error(
        "provider_log_receipt_stale",
        "the bounded provider-log receipt does not match the latest durable job revision or append result",
        "Retry one bounded log poll from the latest exact job revision.",
        &record.local_job_id,
    ))
}

fn provider_logs_are_expected(record: &StoredJobV1) -> bool {
    record.provider_job_id.is_some()
        && record
            .provider_resume
            .as_ref()
            .and_then(|resume| resume.run.as_ref())
            .is_some()
}

fn job_lifecycle_is_settled(record: &StoredJobV1) -> bool {
    matches!(
        record.state,
        StoredJobState::Succeeded
            | StoredJobState::Failed
            | StoredJobState::Cancelled
            | StoredJobState::CleanupFailed
            | StoredJobState::Expired
    ) && record.terminal_outcome.is_some()
        && record.cleanup_status != StoredCleanupStatus::Pending
}

impl From<&ManagedJobEventV1> for JobLogEventV1 {
    fn from(event: &ManagedJobEventV1) -> Self {
        Self {
            schema_version: 1,
            event: "job_log_event",
            record_kind: "sanitized_lifecycle_event",
            local_job_id: event.local_job_id.as_str().to_owned(),
            sequence: event.sequence,
            occurred_at_ms: event.occurred_at_ms,
            source: managed_event_source_name(event.source),
            source_sequence: event.source_sequence,
            source_event_sha256: event.source_event_sha256.clone(),
            phase: event.phase.clone(),
            level: managed_event_level_name(event.level),
            code: event.code.clone(),
            message: event.message.clone(),
        }
    }
}

impl From<&PruneCandidateV1> for JobPruneCandidateV1 {
    fn from(candidate: &PruneCandidateV1) -> Self {
        Self {
            local_job_id: candidate.local_job_id.as_str().to_owned(),
            operation_id: candidate.operation_id.clone(),
            revision: candidate.revision,
            revision_sha256: candidate.revision_sha256.clone(),
            updated_at_ms: candidate.updated_at_ms,
            attempt: candidate.attempt,
            parent_job_id: candidate
                .parent_job_id
                .as_ref()
                .map(|identifier| identifier.as_str().to_owned()),
            child_job_ids: candidate
                .child_job_ids
                .iter()
                .map(|identifier| identifier.as_str().to_owned())
                .collect(),
            complete_lineage_authorization_sha256: candidate
                .complete_lineage_authorization_sha256
                .clone(),
            has_git_snapshot_keepalive: candidate.has_git_snapshot_keepalive,
        }
    }
}

struct LogFileSink {
    path: Utf8PathBuf,
    writer: BufWriter<File>,
    json_lines: bool,
}

impl LogFileSink {
    fn open(path: &Utf8Path, json_lines: bool) -> Result<Self, CliError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| CliError::Io {
                action: "create job log output",
                path: path.to_owned(),
                source,
            })?;
        let mut sink = Self {
            path: path.to_owned(),
            writer: BufWriter::new(file),
            json_lines,
        };
        if !json_lines {
            sink.write_bytes(format!("{JOB_LOG_WARNING}\n").as_bytes())?;
        }
        Ok(sink)
    }

    fn write_event(&mut self, event: &JobLogEventV1) -> Result<(), CliError> {
        if self.json_lines {
            let mut encoded = encode_json(event)?;
            encoded.push(b'\n');
            self.write_bytes(&encoded)
        } else {
            self.write_bytes(format!("{}\n", render_job_log_event(event)).as_bytes())
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        self.writer.write_all(bytes).map_err(|source| CliError::Io {
            action: "write job log output",
            path: self.path.clone(),
            source,
        })
    }

    fn finish(mut self) -> Result<(), CliError> {
        self.writer.flush().map_err(|source| CliError::Io {
            action: "flush job log output",
            path: self.path.clone(),
            source,
        })?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|source| CliError::Io {
                action: "sync job log output",
                path: self.path,
                source,
            })
    }
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec(value).map_err(|_| CliError::JobsLifecycle {
        code: "jobs_output_serialization_failed",
        message: "could not serialize the stable jobs output".to_owned(),
        help: "Preserve the local job store and report this cargo-ferry serialization failure."
            .to_owned(),
        details: Vec::new(),
    })
}

fn write_stdout_json_line(value: &impl Serialize) -> Result<(), CliError> {
    let mut encoded = encode_json(value)?;
    encoded.push(b'\n');
    write_stdout_bytes(&encoded)
}

fn write_stdout_text(value: &str) -> Result<(), CliError> {
    write_stdout_bytes(value.as_bytes())
}

fn write_stdout_bytes(value: &[u8]) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(value).map_err(|source| CliError::Io {
        action: "write jobs output",
        path: Utf8PathBuf::from("<stdout>"),
        source,
    })?;
    stdout.flush().map_err(|source| CliError::Io {
        action: "flush jobs output",
        path: Utf8PathBuf::from("<stdout>"),
        source,
    })
}

/// Build the secret-free newest-job view for one exact project selector.
pub(crate) fn list_for_project(
    store: &JobStore,
    canonical_root: &str,
    filesystem_identity: &str,
    limit: usize,
) -> Result<ProjectJobsListV1, CliError> {
    let summaries = store.list_latest_for_project(canonical_root, filesystem_identity, limit)?;
    let mut jobs = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let record =
            store.latest_for_project(&summary.local_job_id, canonical_root, filesystem_identity)?;
        jobs.push(IdeJobListItemV1::from(JobListItemV1::from(&record)));
    }
    Ok(ProjectJobsListV1 {
        limit,
        returned: jobs.len(),
        jobs,
    })
}

/// Build secret-free details for one job owned by the exact project selector.
pub(crate) fn show_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
) -> Result<ProjectJobDetailsV1, CliError> {
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    Ok(ProjectJobDetailsV1::from(JobShowOutputV1::from_record(
        &record, false,
    )))
}

/// Build the secret-free artifact view for one job owned by the exact project selector.
pub(crate) fn artifacts_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
) -> Result<ProjectJobArtifactsV1, CliError> {
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    Ok(ProjectJobArtifactsV1 {
        local_job_id: record.local_job_id.as_str().to_owned(),
        revision: record.revision,
        artifacts: record
            .artifacts
            .iter()
            .map(JobArtifactV1::from)
            .map(IdeJobArtifactV1::from)
            .collect(),
    })
}

/// Build one finite sanitized event snapshot for a job owned by the exact project selector.
pub(crate) fn logs_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
    since_ms: u64,
    phase: Option<&str>,
) -> Result<ProjectJobLogsV1, CliError> {
    let initial_record =
        store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let durable_log_identity = durable_worker_log_identity(&initial_record);
    let mut proof = WorkerLogJournalProof::default();
    let mut cursor = 0_u64;
    let mut events = Vec::new();
    loop {
        let page = store.read_managed_events(local_job_id, cursor, MAX_MANAGED_EVENT_PAGE)?;
        for event in &page.events {
            if let Some(identity) = durable_log_identity.as_ref() {
                proof.observe(event, local_job_id, identity);
            }
            if event_matches_filters(event, since_ms, phase) {
                events.push(IdeJobLogEventV1::from(JobLogEventV1::from(event)));
            }
        }
        cursor = page.next_after_sequence;
        if !page.has_more {
            break;
        }
    }
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let current_log_identity = durable_worker_log_identity(&record);
    let provider_full_logs = current_log_identity.as_ref() == durable_log_identity.as_ref()
        && current_log_identity
            .as_ref()
            .is_some_and(|identity| proof.is_complete(identity));
    Ok(ProjectJobLogsV1 {
        local_job_id: record.local_job_id.as_str().to_owned(),
        log_scope: JOB_LOG_SCOPE.to_owned(),
        provider_full_logs,
        since_ms,
        phase: phase.map(ToOwned::to_owned),
        returned: events.len(),
        next_sequence: cursor,
        terminal: job_lifecycle_is_settled(&record),
        events,
    })
}

/// Return action eligibility derived from the same lifecycle validators used at mutation time.
pub(crate) fn eligibility_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
) -> Result<ProjectJobEligibilityV1, CliError> {
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let (can_cancel, cancel_reason_code) = eligibility_result(validate_cancel_preflight(&record));
    let retry =
        validate_project_retry_preflight(store, &record, canonical_root, filesystem_identity);
    let (can_retry, retry_reason_code) = eligibility_result(retry);
    Ok(ProjectJobEligibilityV1 {
        local_job_id: record.local_job_id.as_str().to_owned(),
        revision: record.revision,
        can_cancel,
        cancel_reason_code,
        can_retry,
        retry_reason_code,
    })
}

fn validate_project_retry_preflight(
    store: &JobStore,
    record: &StoredJobV1,
    canonical_root: &str,
    filesystem_identity: &str,
) -> Result<(), CliError> {
    let persisted = persisted_retry_binding(store, record)?;
    let effective_force = persisted.as_ref().is_some_and(|binding| {
        binding.options.parent_policy == RetryParentPolicyV1::AllowSuccessful
    });
    validate_retry_preflight(record, effective_force)?;
    let Some(binding) = persisted else {
        return Ok(());
    };
    let child =
        store.latest_for_project(&binding.child_job_id, canonical_root, filesystem_identity)?;
    validate_existing_retry_child_preflight(record, &binding, &child)?;
    Ok(())
}

fn eligibility_result<T>(result: Result<T, CliError>) -> (bool, Option<String>) {
    match result {
        Ok(_) => (true, None),
        Err(error) => (false, Some(error.code().to_owned())),
    }
}

/// Read one bounded page after at most one provider refresh and one cancellation-aware wait.
#[allow(
    clippy::too_many_arguments,
    reason = "workspace identity, cursor, bounded effects, and cancellation remain explicit"
)]
pub(crate) fn logs_page_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
    after_sequence: u64,
    limit: usize,
    phase: Option<&str>,
    refresh: bool,
    wait: bool,
    cancellation: &CancellationToken,
) -> Result<ProjectJobLogsPageV1, CliError> {
    if !(1..=MAX_MANAGED_EVENT_PAGE).contains(&limit) {
        return Err(CliError::JobsLifecycle {
            code: "job_log_page_limit_invalid",
            message: "the requested job log page exceeds the bounded store limit".to_owned(),
            help: format!("Use a page limit from 1 through {MAX_MANAGED_EVENT_PAGE}."),
            details: vec![format!("limit={limit}")],
        });
    }
    let mut record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    cancellation
        .check()
        .map_err(|_| cancelled_jobs_operation(local_job_id))?;
    let mut provider_refresh_performed = false;
    if refresh {
        let receipt = ingest_github_job_logs_once_in_store(store, local_job_id, cancellation)?;
        if receipt.local_job_id != *local_job_id {
            return Err(jobs_lifecycle_error(
                "provider_log_receipt_identity_mismatch",
                "the bounded provider-log receipt belongs to a different local job",
                "Preserve the journal and retry only through the exact job-bound Logs session.",
                local_job_id,
            ));
        }
        provider_refresh_performed = receipt.provider_fetch_performed;
        record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    }
    let mut page = read_filtered_job_log_page(store, local_job_id, after_sequence, limit, phase)?;
    let mut waited = false;
    if page.0.is_empty() && wait && !job_lifecycle_is_settled(&record) {
        waited = true;
        cancellation_aware_job_log_wait(local_job_id, cancellation)?;
        store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
        page = read_filtered_job_log_page(store, local_job_id, after_sequence, limit, phase)?;
    }
    let latest = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let provider_full_logs = complete_worker_log_proof(store, &latest)?;
    Ok(ProjectJobLogsPageV1 {
        local_job_id: latest.local_job_id.as_str().to_owned(),
        log_scope: JOB_LOG_SCOPE.to_owned(),
        provider_full_logs,
        after_sequence,
        phase: phase.map(ToOwned::to_owned),
        limit,
        returned: page.0.len(),
        next_after_sequence: page.1,
        has_more: page.2,
        terminal: job_lifecycle_is_settled(&latest),
        provider_refresh_performed,
        waited,
        events: page.0,
    })
}

fn read_filtered_job_log_page(
    store: &JobStore,
    local_job_id: &LocalJobId,
    after_sequence: u64,
    limit: usize,
    phase: Option<&str>,
) -> Result<(Vec<IdeJobLogEventV1>, u64, bool), CliError> {
    let mut scan_cursor = after_sequence;
    let mut events = Vec::with_capacity(limit);
    let mut has_more = false;
    loop {
        let page = store.read_managed_events(local_job_id, scan_cursor, MAX_MANAGED_EVENT_PAGE)?;
        for event in &page.events {
            if phase.is_some_and(|phase| event.phase.as_deref() != Some(phase)) {
                continue;
            }
            if events.len() == limit {
                has_more = true;
                break;
            }
            events.push(IdeJobLogEventV1::from(JobLogEventV1::from(event)));
        }
        if has_more || !page.has_more {
            break;
        }
        if page.next_after_sequence <= scan_cursor {
            return Err(jobs_lifecycle_error(
                "job_log_cursor_invalid",
                "the durable event journal did not advance its bounded scan cursor",
                "Preserve the job store and inspect its immutable event sequence.",
                local_job_id,
            ));
        }
        scan_cursor = page.next_after_sequence;
    }
    let next_after_sequence = events.last().map_or(after_sequence, |event| event.sequence);
    debug_assert!(!has_more || !events.is_empty());
    Ok((events, next_after_sequence, has_more))
}

fn cancellation_aware_job_log_wait(
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
) -> Result<(), CliError> {
    for _ in 0..5 {
        cancellation
            .check()
            .map_err(|_| cancelled_jobs_operation(local_job_id))?;
        thread::sleep(Duration::from_millis(100));
    }
    cancellation
        .check()
        .map_err(|_| cancelled_jobs_operation(local_job_id))
}

fn cancelled_jobs_operation(local_job_id: &LocalJobId) -> CliError {
    jobs_lifecycle_error(
        "jobs_operation_cancelled",
        "the bounded jobs operation was cancelled",
        "Retry the exact workspace-bound operation when cancellation is no longer requested.",
        local_job_id,
    )
}

fn complete_worker_log_proof(store: &JobStore, record: &StoredJobV1) -> Result<bool, CliError> {
    let Some(identity) = durable_worker_log_identity(record) else {
        return Ok(false);
    };
    let mut proof = WorkerLogJournalProof::default();
    let mut cursor = 0_u64;
    loop {
        let page =
            store.read_managed_events(&record.local_job_id, cursor, MAX_MANAGED_EVENT_PAGE)?;
        for event in &page.events {
            proof.observe(event, &record.local_job_id, &identity);
        }
        cursor = page.next_after_sequence;
        if !page.has_more {
            break;
        }
    }
    let latest = store.latest(&record.local_job_id)?;
    Ok(
        durable_worker_log_identity(&latest).as_ref() == Some(&identity)
            && proof.is_complete(&identity),
    )
}

/// Durably cancel one exact workspace-owned job without renderer or stdout side effects.
pub(crate) fn cancel_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
    cancellation: CancellationToken,
) -> Result<ProjectJobCancellationV1, CliError> {
    let initial = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    validate_cancel_preflight(&initial)?;
    let prepared = PreparedGithubJobSession::prepare_cancel(store, local_job_id)?;
    let durable = prepared.persist_cancellation_requested()?;
    let bound = durable.bind_live(&cancellation)?;
    let receipt = bound.cancel_or_reconcile_once("user_requested", cancellation)?;
    validate_cancel_completion(&initial, &receipt)?;
    let latest = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    if latest.revision != receipt.revision
        || latest.local_job_id != receipt.local_job_id
        || latest.state != receipt.state
        || latest.cancellation_status != receipt.cancellation_status
        || latest.terminal_outcome != Some(receipt.terminal_outcome)
        || latest.cleanup_status != receipt.cleanup_status
    {
        return Err(jobs_lifecycle_error(
            "cancellation_completion_identity_mismatch",
            "the durable cancellation result changed before its workspace receipt was bound",
            "Preserve the job and reconcile its exact terminal checkpoint.",
            local_job_id,
        ));
    }
    Ok(ProjectJobCancellationV1 {
        parent: ProjectJobDetailsV1::from(JobShowOutputV1::from_record(&latest, false)),
        durable: true,
        intent_written: receipt.intent_written_by_this_call,
        provider_cancel_requests: receipt.provider_cancel_posts,
        get_only_reconciliation: receipt.get_only_reconciliation,
    })
}

/// Create or resume one exact stored-source retry for an exact workspace-owned parent.
pub(crate) fn retry_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    canonical_root: &str,
    filesystem_identity: &str,
    cancellation: CancellationToken,
) -> Result<ProjectJobRetryV1, CliError> {
    let initial = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    validate_project_retry_preflight(store, &initial, canonical_root, filesystem_identity)?;
    let quiet = Reporter::new(false, true, false);
    let receipt = execute_exact_retry_in_store(store, local_job_id, false, cancellation, &quiet)?;
    let parent = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let child =
        store.latest_for_project(&receipt.child_job_id, canonical_root, filesystem_identity)?;
    if parent.retry_lineage.child_job_ids.last() != Some(&child.local_job_id)
        || child.retry_lineage.parent_job_id.as_ref() != Some(&parent.local_job_id)
        || receipt.parent_job_id != parent.local_job_id
        || receipt.child_job_id != child.local_job_id
        || receipt.child_revision != child.revision
    {
        return Err(jobs_lifecycle_error(
            "retry_completion_identity_mismatch",
            "the durable retry lineage changed before its workspace receipt was bound",
            "Preserve the parent and child and inspect their immutable lineage transaction.",
            local_job_id,
        ));
    }
    Ok(ProjectJobRetryV1 {
        parent: ProjectJobDetailsV1::from(JobShowOutputV1::from_record(&parent, false)),
        child: ProjectJobDetailsV1::from(JobShowOutputV1::from_record(&child, false)),
        parent_revision: receipt.parent_revision,
        child_revision: receipt.child_revision,
        child_created: receipt.disposition == GithubRetryChildDisposition::Created,
        resumed_existing_child: receipt.disposition == GithubRetryChildDisposition::Existing,
        durable: true,
    })
}

impl From<JobListItemV1> for IdeJobListItemV1 {
    fn from(item: JobListItemV1) -> Self {
        Self {
            local_job_id: item.local_job_id,
            revision: item.revision,
            provider: item.provider,
            provider_job_id: item.provider_job_id,
            provider_run_id: item.provider_run_id,
            operation_id: item.operation_id,
            app_label: item.app_label,
            application_identifier: item.application_identifier,
            target: item.target,
            profile: item.profile.to_owned(),
            signing_mode: item.signing_mode.to_owned(),
            created_at_ms: item.created_at_ms,
            submitted_at_ms: item.submitted_at_ms,
            updated_at_ms: item.updated_at_ms,
            state: item.state.to_owned(),
            last_confirmed_state: item.last_confirmed_state.map(ToOwned::to_owned),
            terminal_outcome: item.terminal_outcome.map(ToOwned::to_owned),
            cleanup_status: item.cleanup_status.to_owned(),
            cancellation_status: item.cancellation_status.to_owned(),
        }
    }
}

impl From<JobShowOutputV1> for ProjectJobDetailsV1 {
    fn from(job: JobShowOutputV1) -> Self {
        Self {
            local_job_id: job.local_job_id,
            revision: job.revision,
            provider: IdeJobProviderIdentityV1::from(job.provider),
            provider_job_id: job.provider_job_id,
            provider_run_id: job.provider_run_id,
            operation_id: job.operation_id,
            request_sha256: job.request_sha256,
            semantic_retry_sha256: job.semantic_retry_sha256,
            application_identifier: job.application_identifier,
            source_revision: job.source_revision,
            source_manifest_sha256: job.source_manifest_sha256,
            target: job.target,
            profile: job.profile.to_owned(),
            signing_mode: job.signing_mode.to_owned(),
            created_at_ms: job.created_at_ms,
            submitted_at_ms: job.submitted_at_ms,
            updated_at_ms: job.updated_at_ms,
            state: job.state.to_owned(),
            last_confirmed_state: job.last_confirmed_state.map(ToOwned::to_owned),
            terminal_outcome: job.terminal_outcome.map(ToOwned::to_owned),
            cleanup_status: job.cleanup_status.to_owned(),
            cancellation_status: job.cancellation_status.to_owned(),
            retry: IdeJobRetryLineageV1 {
                attempt: job.retry.attempt,
                parent_job_id: job.retry.parent_job_id,
                child_job_ids: job.retry.child_job_ids,
            },
            failure: job.failure.map(|failure| IdeJobFailureV1 {
                code: failure.code,
                retryable: failure.retryable,
            }),
            artifact_count: job.artifact_count,
            event_journal_bound: job.event_journal_bound,
            provider_resume_available: job.provider_resume_available,
        }
    }
}

impl From<JobProviderIdentityV1> for IdeJobProviderIdentityV1 {
    fn from(provider: JobProviderIdentityV1) -> Self {
        Self {
            name: provider.name,
            config_sha256: provider.config_sha256,
            principal: match provider.principal {
                JobPrincipalIdentityV1::User { id, login } => {
                    IdeJobPrincipalIdentityV1::User { id, login }
                }
                JobPrincipalIdentityV1::RepositoryCredential => {
                    IdeJobPrincipalIdentityV1::RepositoryCredential
                }
            },
            execution_repository_id: provider.execution_repository_id,
        }
    }
}

impl From<JobArtifactV1> for IdeJobArtifactV1 {
    fn from(artifact: JobArtifactV1) -> Self {
        Self {
            artifact_id: artifact.artifact_id,
            kind: artifact.kind.to_owned(),
            file_name: artifact.file_name,
            size: artifact.size,
            sha256: artifact.sha256,
            media_type: artifact.media_type,
            download_destination: artifact.download_destination,
            download_parent_identity: artifact.download_parent_identity,
            local_path: artifact.local_path,
            local_file_identity: artifact.local_file_identity,
            locally_validated: artifact.locally_validated,
            current_status: artifact.current_status.to_owned(),
        }
    }
}

impl From<JobLogEventV1> for IdeJobLogEventV1 {
    fn from(event: JobLogEventV1) -> Self {
        Self {
            record_kind: event.record_kind.to_owned(),
            sequence: event.sequence,
            occurred_at_ms: event.occurred_at_ms,
            phase: event.phase,
            source: event.source.to_owned(),
            source_sequence: event.source_sequence,
            source_event_sha256: event.source_event_sha256,
            level: event.level.to_owned(),
            code: event.code,
            message: event.message,
        }
    }
}

fn list_output(
    store: &JobStore,
    limit: usize,
    dry_run: bool,
) -> Result<JobsListOutputV1, CliError> {
    let summaries = store.list_latest(limit)?;
    let mut jobs = Vec::with_capacity(summaries.len());
    for summary in summaries {
        jobs.push(JobListItemV1::from(&store.latest(&summary.local_job_id)?));
    }
    Ok(JobsListOutputV1 {
        dry_run,
        limit,
        returned: jobs.len(),
        jobs,
    })
}

fn show_output(
    store: &JobStore,
    local_job_id: &LocalJobId,
    dry_run: bool,
) -> Result<JobShowOutputV1, CliError> {
    Ok(JobShowOutputV1::from_record(
        &store.latest(local_job_id)?,
        dry_run,
    ))
}

fn artifacts_output(
    store: &JobStore,
    local_job_id: &LocalJobId,
    dry_run: bool,
) -> Result<JobArtifactsOutputV1, CliError> {
    let record = store.latest(local_job_id)?;
    Ok(JobArtifactsOutputV1 {
        dry_run,
        local_job_id: record.local_job_id.as_str().to_owned(),
        revision: record.revision,
        artifacts: record.artifacts.iter().map(JobArtifactV1::from).collect(),
    })
}

impl From<&StoredJobV1> for JobListItemV1 {
    fn from(record: &StoredJobV1) -> Self {
        Self {
            local_job_id: record.local_job_id.as_str().to_owned(),
            revision: record.revision,
            provider: record.provider.provider.clone(),
            provider_job_id: record.provider_job_id.clone(),
            provider_run_id: record.provider_run_id.clone(),
            operation_id: record.operation_id.clone(),
            app_label: record.request.product_name.clone(),
            application_identifier: record.project.application_identifier.clone(),
            target: record.target.clone(),
            profile: profile_name(record.profile),
            signing_mode: signing_mode_name(record.signing_mode),
            created_at_ms: record.created_at_ms,
            submitted_at_ms: record.submitted_at_ms,
            updated_at_ms: record.updated_at_ms,
            state: job_state_name(record.state),
            last_confirmed_state: record.last_confirmed_state.map(job_state_name),
            terminal_outcome: record.terminal_outcome.map(build_outcome_name),
            cleanup_status: cleanup_status_name(record.cleanup_status),
            cancellation_status: cancellation_status_name(record.cancellation_status),
        }
    }
}

impl JobShowOutputV1 {
    fn from_record(record: &StoredJobV1, dry_run: bool) -> Self {
        Self {
            dry_run,
            local_job_id: record.local_job_id.as_str().to_owned(),
            revision: record.revision,
            provider: JobProviderIdentityV1::from(record),
            provider_job_id: record.provider_job_id.clone(),
            provider_run_id: record.provider_run_id.clone(),
            operation_id: record.operation_id.clone(),
            request_sha256: record.request_sha256.clone(),
            semantic_retry_sha256: record.semantic_retry_sha256.clone(),
            application_identifier: record.project.application_identifier.clone(),
            source_revision: record.source.revision.clone(),
            source_manifest_sha256: record.source.manifest_sha256.clone(),
            target: record.target.clone(),
            profile: profile_name(record.profile),
            signing_mode: signing_mode_name(record.signing_mode),
            created_at_ms: record.created_at_ms,
            submitted_at_ms: record.submitted_at_ms,
            updated_at_ms: record.updated_at_ms,
            state: job_state_name(record.state),
            last_confirmed_state: record.last_confirmed_state.map(job_state_name),
            terminal_outcome: record.terminal_outcome.map(build_outcome_name),
            cleanup_status: cleanup_status_name(record.cleanup_status),
            cancellation_status: cancellation_status_name(record.cancellation_status),
            retry: JobRetryLineageV1 {
                attempt: record.retry_lineage.attempt,
                parent_job_id: record
                    .retry_lineage
                    .parent_job_id
                    .as_ref()
                    .map(|identifier| identifier.as_str().to_owned()),
                child_job_ids: record
                    .retry_lineage
                    .child_job_ids
                    .iter()
                    .map(|identifier| identifier.as_str().to_owned())
                    .collect(),
            },
            failure: record.failure.as_ref().map(|failure| JobFailureV1 {
                code: failure.code.clone(),
                retryable: failure.retryable,
            }),
            artifact_count: record.artifacts.len(),
            event_journal_bound: record.log_location.as_deref() == Some("events/v1"),
            provider_resume_available: record.provider_resume.is_some(),
        }
    }
}

impl From<&StoredJobV1> for JobProviderIdentityV1 {
    fn from(record: &StoredJobV1) -> Self {
        Self {
            name: record.provider.provider.clone(),
            config_sha256: record.provider.provider_config_sha256.clone(),
            principal: match &record.provider.principal {
                GithubPrincipalIdentityV1::User { id, login } => JobPrincipalIdentityV1::User {
                    id: *id,
                    login: login.clone(),
                },
                GithubPrincipalIdentityV1::RepositoryCredential => {
                    JobPrincipalIdentityV1::RepositoryCredential
                }
            },
            execution_repository_id: record.provider.execution_repository_id,
        }
    }
}

impl From<&StoredArtifactV1> for JobArtifactV1 {
    fn from(artifact: &StoredArtifactV1) -> Self {
        Self {
            artifact_id: artifact.record.artifact_id.clone(),
            kind: artifact_kind_name(artifact.record.kind),
            file_name: artifact.record.file_name.clone(),
            size: artifact.record.size,
            sha256: artifact.record.sha256.clone(),
            media_type: artifact.record.media_type.clone(),
            download_destination: artifact.download_destination.clone(),
            download_parent_identity: artifact.download_parent_identity.clone(),
            local_path: artifact.local_path.clone(),
            local_file_identity: artifact.local_file_identity.clone(),
            locally_validated: artifact.locally_validated,
            current_status: "not_revalidated",
        }
    }
}

fn render_job_list(output: &JobsListOutputV1) -> String {
    if output.jobs.is_empty() {
        return "No local remote-build jobs.".to_owned();
    }
    output
        .jobs
        .iter()
        .map(|job| {
            format!(
                "{}  {}  {}  {}  {}  updated_at_ms={}",
                job.local_job_id,
                job.state,
                job.app_label,
                job.profile,
                job.provider,
                job.updated_at_ms
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_job_show(job: &JobShowOutputV1) -> String {
    let principal = match &job.provider.principal {
        JobPrincipalIdentityV1::User { id, login } => format!("user:{login} ({id})"),
        JobPrincipalIdentityV1::RepositoryCredential => "repository_credential".to_owned(),
    };
    let failure = job.failure.as_ref().map_or_else(
        || "-".to_owned(),
        |failure| format!("{} (retryable={})", failure.code, failure.retryable),
    );
    let retry_children = if job.retry.child_job_ids.is_empty() {
        "-".to_owned()
    } else {
        job.retry.child_job_ids.join(",")
    };
    format!(
        "{}\n  state: {}\n  last_confirmed_state: {}\n  terminal_outcome: {}\n  operation_id: {}\n  application_identifier: {}\n  target: {}\n  profile: {}\n  signing_mode: {}\n  source_revision: {}\n  source_manifest_sha256: {}\n  request_sha256: {}\n  semantic_retry_sha256: {}\n  provider: {}\n  provider_config_sha256: {}\n  principal: {}\n  execution_repository_id: {}\n  provider_job_id: {}\n  provider_run_id: {}\n  provider_resume_available: {}\n  event_journal_bound: {}\n  cleanup_status: {}\n  cancellation_status: {}\n  retry_attempt: {}\n  retry_parent_job_id: {}\n  retry_child_job_ids: {}\n  failure: {}\n  artifacts: {}\n  updated_at_ms: {}",
        job.local_job_id,
        job.state,
        job.last_confirmed_state.unwrap_or("-"),
        job.terminal_outcome.unwrap_or("-"),
        job.operation_id,
        job.application_identifier,
        job.target,
        job.profile,
        job.signing_mode,
        job.source_revision.as_deref().unwrap_or("-"),
        job.source_manifest_sha256,
        job.request_sha256,
        job.semantic_retry_sha256,
        job.provider.name,
        job.provider.config_sha256,
        principal,
        job.provider.execution_repository_id,
        job.provider_job_id.as_deref().unwrap_or("-"),
        job.provider_run_id.as_deref().unwrap_or("-"),
        job.provider_resume_available,
        job.event_journal_bound,
        job.cleanup_status,
        job.cancellation_status,
        job.retry.attempt,
        job.retry.parent_job_id.as_deref().unwrap_or("-"),
        retry_children,
        failure,
        job.artifact_count,
        job.updated_at_ms,
    )
}

fn render_job_artifacts(output: &JobArtifactsOutputV1) -> String {
    if output.artifacts.is_empty() {
        return format!("{} has no recorded artifacts.", output.local_job_id);
    }
    output
        .artifacts
        .iter()
        .map(|artifact| {
            format!(
                "{}  {}  {} bytes\n  artifact_id: {}\n  sha256: {}\n  download_destination: {}\n  download_parent_identity: {}\n  stored_validation={} (current_status={})\n  stored_file_identity: {}\n  local_path: {}",
                artifact.file_name,
                artifact.kind,
                artifact.size,
                artifact.artifact_id,
                artifact.sha256,
                artifact.download_destination.as_deref().unwrap_or("-"),
                artifact.download_parent_identity.as_deref().unwrap_or("-"),
                artifact.locally_validated,
                artifact.current_status,
                artifact.local_file_identity.as_deref().unwrap_or("-"),
                artifact.local_path.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_job_logs(output: &JobLogsOutputV1) -> String {
    let mut lines = vec![format!(
        "Job {} durable sanitized job events (provider_full_logs={}):",
        output.local_job_id, output.provider_full_logs
    )];
    if output.events.is_empty() {
        lines.push("  No matching durable sanitized events.".to_owned());
    } else {
        lines.extend(output.events.iter().map(render_job_log_event));
    }
    lines.push(format!(
        "  returned={} next_sequence={} has_more={} terminal={} output_written={}",
        output.returned,
        output.next_sequence,
        output.has_more,
        output.terminal,
        output.output_written
    ));
    if output.dry_run && output.follow_requested {
        lines.push("  dry-run: follow polling was not started".to_owned());
    }
    lines.join("\n")
}

fn render_job_log_event(event: &JobLogEventV1) -> String {
    let phase = event.phase.as_deref().unwrap_or("-");
    let message = event.message.as_deref().unwrap_or("-");
    format!(
        "{}  {}  {}  {}  {}  {}  {}",
        event.sequence, event.occurred_at_ms, event.source, phase, event.level, event.code, message
    )
}

fn render_job_prune(output: &JobPruneOutputV1) -> String {
    let action = if output.dry_run {
        "would prune"
    } else if output.executed {
        "pruned"
    } else {
        "selected"
    };
    let mut lines = vec![format!(
        "Managed job-store plan {} {} job(s) updated before {}.",
        action, output.planned, output.terminal_before_ms
    )];
    lines.extend(output.candidates.iter().map(|candidate| {
        format!(
            "  {}  revision={}  updated_at_ms={}  attempt={}",
            candidate.local_job_id, candidate.revision, candidate.updated_at_ms, candidate.attempt
        )
    }));
    if let Some(transaction) = &output.transaction_sha256 {
        lines.push(format!("  transaction_sha256: {transaction}"));
    }
    lines.join("\n")
}

const fn managed_event_source_name(source: ManagedEventSource) -> &'static str {
    match source {
        ManagedEventSource::Controller => "controller",
        ManagedEventSource::Provider => "provider",
        ManagedEventSource::Worker => "worker",
    }
}

const fn managed_event_level_name(level: ManagedEventLevel) -> &'static str {
    match level {
        ManagedEventLevel::Info => "info",
        ManagedEventLevel::Warning => "warning",
        ManagedEventLevel::Error => "error",
    }
}

const fn job_state_name(state: StoredJobState) -> &'static str {
    match state {
        StoredJobState::Created => "created",
        StoredJobState::SourcePreparing => "source_preparing",
        StoredJobState::SourceReady => "source_ready",
        StoredJobState::Submitting => "submitting",
        StoredJobState::Queued => "queued",
        StoredJobState::Running => "running",
        StoredJobState::CompileRunning => "compile_running",
        StoredJobState::SigningWaiting => "signing_waiting",
        StoredJobState::SigningRunning => "signing_running",
        StoredJobState::ArtifactUploading => "artifact_uploading",
        StoredJobState::ArtifactReady => "artifact_ready",
        StoredJobState::Downloading => "downloading",
        StoredJobState::Downloaded => "downloaded",
        StoredJobState::Validating => "validating",
        StoredJobState::Succeeded => "succeeded",
        StoredJobState::Failed => "failed",
        StoredJobState::CancellationRequested => "cancellation_requested",
        StoredJobState::Cancelled => "cancelled",
        StoredJobState::CleanupPending => "cleanup_pending",
        StoredJobState::CleanupFailed => "cleanup_failed",
        StoredJobState::Expired => "expired",
        StoredJobState::Unknown => "unknown",
    }
}

const fn build_outcome_name(outcome: StoredBuildOutcome) -> &'static str {
    match outcome {
        StoredBuildOutcome::Succeeded => "succeeded",
        StoredBuildOutcome::Failed => "failed",
        StoredBuildOutcome::Cancelled => "cancelled",
        StoredBuildOutcome::Expired => "expired",
    }
}

const fn cleanup_status_name(status: StoredCleanupStatus) -> &'static str {
    match status {
        StoredCleanupStatus::NotStarted => "not_started",
        StoredCleanupStatus::Pending => "pending",
        StoredCleanupStatus::Confirmed => "confirmed",
        StoredCleanupStatus::Failed => "failed",
        StoredCleanupStatus::Uncertain => "uncertain",
    }
}

const fn cancellation_status_name(status: StoredCancellationStatus) -> &'static str {
    match status {
        StoredCancellationStatus::NotRequested => "not_requested",
        StoredCancellationStatus::Requested => "requested",
        StoredCancellationStatus::Dispatched => "dispatched",
        StoredCancellationStatus::Confirmed => "confirmed",
        StoredCancellationStatus::Failed => "failed",
        StoredCancellationStatus::Uncertain => "uncertain",
    }
}

const fn provider_job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Created => "created",
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Cancelling => "cancelling",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
        JobState::Cleaning => "cleaning",
        JobState::Cleaned => "cleaned",
        JobState::CleanupFailed => "cleanup_failed",
    }
}

const fn profile_name(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Debug => "debug",
        BuildProfile::Release => "release",
    }
}

const fn signing_mode_name(mode: SigningMode) -> &'static str {
    match mode {
        SigningMode::UnsignedCompileOnly => "unsigned-compile-only",
        SigningMode::Development => "development",
        SigningMode::ManualDevelopment => "manual-development",
        SigningMode::PersonalTeam => "personal-team",
        SigningMode::AdHoc => "ad-hoc",
        SigningMode::AppStore => "app-store",
    }
}

const fn artifact_kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::App => "app",
        ArtifactKind::Xcarchive => "xcarchive",
        ArtifactKind::Ipa => "ipa",
        ArtifactKind::Dsym => "dsym",
        ArtifactKind::Manifest => "manifest",
        ArtifactKind::SigningReport => "signing_report",
        ArtifactKind::ValidationReport => "validation_report",
        ArtifactKind::SanitizedLog => "sanitized_log",
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

    use cargo_ferry::job_store::{
        JOB_STORE_SCHEMA_VERSION, JobOperationKind, ManagedJobEventInputV1, RetryLineageOptionsV1,
        StoredArtifactV1, StoredCancellationStatus, StoredCleanupStatus, StoredFailureV1,
        StoredProjectIdentityV1, StoredProviderIdentityV1, StoredRetryLineageV1,
        StoredSourceIdentityV1, retry_recapture_confirmation_sha256,
    };
    use rustferry_github::provider::{
        GITHUB_PROVIDER_ID, GithubJobResumeV1, GithubPrincipalIdentityV1, GithubRunConclusionV1,
        GithubRunEventV1, GithubRunIdentityV1, GithubRunStatusV1,
    };
    use rustferry_remote::{
        ArtifactRecord, BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType,
        IosDeviceBuildRequest, IosDeviceProductExpectation, JobState, SigningPlan, SigningTarget,
        SigningTargetKind, SourceManifest, SourceMode, canonical_request_sha256,
        canonical_retry_template_sha256_v1,
    };
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::commands::remote::test_retry_completion_receipt;

    const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    #[derive(Default)]
    struct FakeCancelTrace {
        steps: Vec<&'static str>,
        intent_durable: bool,
        network_before_intent: bool,
        provider_cancel_posts: u8,
    }

    struct FakePreparedCancel {
        trace: Rc<RefCell<FakeCancelTrace>>,
        fail_intent: bool,
        fail_bind: bool,
    }

    struct FakeDurableCancel {
        trace: Rc<RefCell<FakeCancelTrace>>,
        fail_bind: bool,
    }

    struct FakeBoundCancel {
        trace: Rc<RefCell<FakeCancelTrace>>,
    }

    #[derive(Debug, Default)]
    struct FakeRetryTrace {
        steps: Vec<&'static str>,
        parent_live_bound: bool,
        lineage_durable: bool,
        provider_completions: u8,
    }

    #[derive(Debug)]
    struct FakePreparedRetry {
        trace: Rc<RefCell<FakeRetryTrace>>,
        parent: StoredJobV1,
        fail_bind: bool,
        fail_lineage: bool,
    }

    #[derive(Debug)]
    struct FakeBoundRetry {
        trace: Rc<RefCell<FakeRetryTrace>>,
        parent: StoredJobV1,
        fail_lineage: bool,
    }

    struct FakeRetryChild {
        trace: Rc<RefCell<FakeRetryTrace>>,
    }

    #[derive(Debug, Default)]
    struct FakeLogIngestTrace {
        calls: usize,
        lease_held: bool,
        sleep_calls: usize,
    }

    struct FakeLogIngestor {
        trace: Rc<RefCell<FakeLogIngestTrace>>,
        fail_after: Option<usize>,
    }

    impl PreparedCancellationSession for FakePreparedCancel {
        type Durable = FakeDurableCancel;

        fn persist_intent(self) -> Result<Self::Durable, CliError> {
            self.trace.borrow_mut().steps.push("persist_intent");
            if self.fail_intent {
                return Err(fake_session_error("fake_intent_failed"));
            }
            self.trace.borrow_mut().intent_durable = true;
            Ok(FakeDurableCancel {
                trace: self.trace,
                fail_bind: self.fail_bind,
            })
        }
    }

    impl DurableCancellationSession for FakeDurableCancel {
        type Bound = FakeBoundCancel;

        fn bind_live(self, _cancellation: &CancellationToken) -> Result<Self::Bound, CliError> {
            let mut trace = self.trace.borrow_mut();
            trace.steps.push("bind_live");
            if !trace.intent_durable {
                trace.network_before_intent = true;
            }
            if self.fail_bind {
                return Err(fake_session_error("fake_bind_failed"));
            }
            drop(trace);
            Ok(FakeBoundCancel { trace: self.trace })
        }
    }

    impl BoundCancellationSession for FakeBoundCancel {
        type Receipt = ();

        fn finish_cancel(
            self,
            reason: &str,
            _cancellation: CancellationToken,
        ) -> Result<Self::Receipt, CliError> {
            assert_eq!(reason, "user_requested");
            let mut trace = self.trace.borrow_mut();
            assert!(trace.intent_durable);
            trace.steps.push("finish_cancel");
            trace.provider_cancel_posts = trace.provider_cancel_posts.saturating_add(1);
            Ok(())
        }
    }

    impl PreparedRetrySession for FakePreparedRetry {
        type Bound = FakeBoundRetry;

        fn validate_parent(
            self,
            validate: impl FnOnce(&StoredJobV1) -> Result<(), CliError>,
        ) -> Result<Self, CliError> {
            self.trace.borrow_mut().steps.push("validate_parent");
            validate(&self.parent)?;
            Ok(self)
        }

        fn bind_parent(self, _cancellation: &CancellationToken) -> Result<Self::Bound, CliError> {
            self.trace.borrow_mut().steps.push("bind_parent");
            if self.fail_bind {
                return Err(fake_session_error("fake_retry_bind_failed"));
            }
            self.trace.borrow_mut().parent_live_bound = true;
            Ok(FakeBoundRetry {
                trace: self.trace,
                parent: self.parent,
                fail_lineage: self.fail_lineage,
            })
        }
    }

    impl BoundRetrySession for FakeBoundRetry {
        type Child = FakeRetryChild;

        fn create_or_resume_child<F>(
            self,
            options: &RetryLineageOptionsV1,
            make_child: F,
        ) -> Result<Self::Child, CliError>
        where
            F: FnOnce(&StoredJobV1) -> Result<StoredJobV1, CliError>,
        {
            assert_eq!(options.source_policy, RetrySourcePolicyV1::Exact);
            let mut trace = self.trace.borrow_mut();
            assert!(trace.parent_live_bound);
            trace.steps.push("create_lineage");
            drop(trace);
            let _candidate = make_child(&self.parent)?;
            if self.fail_lineage {
                return Err(fake_session_error("fake_retry_lineage_failed"));
            }
            self.trace.borrow_mut().lineage_durable = true;
            Ok(FakeRetryChild { trace: self.trace })
        }
    }

    impl RetryChildSession for FakeRetryChild {
        type Receipt = ();

        fn complete(
            self,
            _cancellation: CancellationToken,
            _reporter: &Reporter,
        ) -> Result<Self::Receipt, CliError> {
            let mut trace = self.trace.borrow_mut();
            assert!(trace.lineage_durable);
            trace.steps.push("complete");
            trace.provider_completions = trace.provider_completions.saturating_add(1);
            Ok(())
        }
    }

    impl ProviderLogIngestor for FakeLogIngestor {
        fn ingest_once(
            &mut self,
            _local_job_id: &LocalJobId,
        ) -> Result<ProviderLogIngestStatus, CliError> {
            let mut trace = self.trace.borrow_mut();
            trace.calls += 1;
            if self.fail_after == Some(trace.calls) {
                return Err(fake_session_error("fake_log_ingest_failed"));
            }
            trace.lease_held = true;
            trace.lease_held = false;
            Ok(ProviderLogIngestStatus {
                provider_fetch_performed: true,
                ..ProviderLogIngestStatus::default()
            })
        }
    }

    fn fake_session_error(code: &'static str) -> CliError {
        CliError::JobsLifecycle {
            code,
            message: "fake session failure".to_owned(),
            help: "test-only failure".to_owned(),
            details: Vec::new(),
        }
    }

    fn fake_prepared_cancel(
        trace: Rc<RefCell<FakeCancelTrace>>,
        fail_intent: bool,
        fail_bind: bool,
    ) -> FakePreparedCancel {
        FakePreparedCancel {
            trace,
            fail_intent,
            fail_bind,
        }
    }

    #[test]
    fn local_store_outputs_use_bounded_public_dtos_without_provider_internals() {
        let temporary = TempDir::new().expect("temporary directory");
        let config = temporary.path().join("config");
        let writer = JobStore::open_at(&config).expect("private job store");
        let artifact = artifact(&temporary);
        let record = record(&temporary);
        writer.create(&record).expect("first job revision");
        drop(writer);
        let store = JobStore::open_at_read_only(config).expect("read-only job store");

        let listed = list_output(&store, 50, false).expect("job list");
        assert!(!listed.dry_run);
        assert_eq!(listed.limit, 50);
        assert_eq!(listed.returned, 1);
        assert_eq!(listed.jobs.len(), 1);
        assert_eq!(listed.jobs[0].local_job_id, "job-cli-output-1");
        assert_eq!(listed.jobs[0].state, "source_ready");
        assert_eq!(listed.jobs[0].operation_id, "operation-cli-output-1");
        assert_eq!(listed.jobs[0].app_label, "App");
        assert_eq!(listed.jobs[0].profile, "release");
        assert_eq!(listed.jobs[0].signing_mode, "unsigned-compile-only");

        let shown = show_output(&store, &record.local_job_id, true).expect("job show");
        assert!(shown.dry_run);
        assert!(!shown.provider_resume_available);
        assert_eq!(shown.provider.execution_repository_id, 42);
        assert_eq!(shown.artifact_count, 0);
        assert_eq!(shown.request_sha256, record.request_sha256);
        assert_eq!(shown.semantic_retry_sha256, record.semantic_retry_sha256);
        let encoded = serde_json::to_value(&shown).expect("show DTO JSON");
        let Value::Object(root) = encoded else {
            panic!("show output must be an object");
        };
        assert!(root.get("request").is_none());
        assert!(root.get("project").is_none());
        assert!(root.get("provider_resume").is_none());
        let provider = root["provider"].as_object().expect("provider DTO");
        assert!(provider.get("execution_repository").is_none());
        assert_eq!(provider["principal"]["kind"], "user");
        assert_eq!(provider["principal"]["id"], 7);
        assert_eq!(provider["principal"]["login"], "example-user");

        let artifacts =
            artifacts_output(&store, &record.local_job_id, false).expect("job artifacts");
        assert!(!artifacts.dry_run);
        assert!(artifacts.artifacts.is_empty());
        let mapped = JobArtifactV1::from(&artifact);
        assert_eq!(mapped.kind, "xcarchive");
        assert_eq!(
            mapped.download_destination.as_deref(),
            artifact.download_destination.as_deref()
        );
        assert_eq!(
            mapped.download_parent_identity.as_deref(),
            artifact.download_parent_identity.as_deref()
        );
        assert_eq!(mapped.local_path.as_deref(), artifact.local_path.as_deref());
        assert_eq!(
            mapped.local_file_identity.as_deref(),
            artifact.local_file_identity.as_deref()
        );
        assert!(mapped.locally_validated);
        assert_eq!(mapped.current_status, "not_revalidated");

        let shown_json = serde_json::to_string(&shown).expect("show JSON");
        assert!(!shown_json.contains("https://github.com/example/private-execution"));
        assert!(!shown_json.contains("refs/heads/rustferry/goal3/builds"));
    }

    #[test]
    fn renderers_are_finite_for_empty_local_results() {
        assert_eq!(
            render_job_list(&JobsListOutputV1 {
                dry_run: false,
                limit: 50,
                returned: 0,
                jobs: Vec::new(),
            }),
            "No local remote-build jobs."
        );
        assert_eq!(
            render_job_artifacts(&JobArtifactsOutputV1 {
                dry_run: false,
                local_job_id: "job-empty".to_owned(),
                revision: 1,
                artifacts: Vec::new(),
            }),
            "job-empty has no recorded artifacts."
        );
    }

    #[test]
    fn cancellation_typestate_orders_intent_before_live_network_and_one_dispatch() {
        let trace = Rc::new(RefCell::new(FakeCancelTrace::default()));
        execute_cancel_session(
            fake_prepared_cancel(Rc::clone(&trace), false, false),
            "user_requested",
        )
        .expect("fake cancellation");
        let trace = trace.borrow();
        assert_eq!(
            trace.steps,
            vec!["persist_intent", "bind_live", "finish_cancel"]
        );
        assert!(trace.intent_durable);
        assert!(!trace.network_before_intent);
        assert_eq!(trace.provider_cancel_posts, 1);
    }

    #[test]
    fn cancellation_typestate_stops_before_network_or_dispatch_on_prior_failure() {
        let intent_trace = Rc::new(RefCell::new(FakeCancelTrace::default()));
        let error = execute_cancel_session(
            fake_prepared_cancel(Rc::clone(&intent_trace), true, false),
            "user_requested",
        )
        .expect_err("intent failure");
        assert_eq!(error.code(), "fake_intent_failed");
        let intent_trace = intent_trace.borrow();
        assert_eq!(intent_trace.steps, vec!["persist_intent"]);
        assert!(!intent_trace.network_before_intent);
        assert_eq!(intent_trace.provider_cancel_posts, 0);
        drop(intent_trace);

        let bind_trace = Rc::new(RefCell::new(FakeCancelTrace::default()));
        let error = execute_cancel_session(
            fake_prepared_cancel(Rc::clone(&bind_trace), false, true),
            "user_requested",
        )
        .expect_err("live bind failure");
        assert_eq!(error.code(), "fake_bind_failed");
        let bind_trace = bind_trace.borrow();
        assert_eq!(bind_trace.steps, vec!["persist_intent", "bind_live"]);
        assert!(bind_trace.intent_durable);
        assert!(!bind_trace.network_before_intent);
        assert_eq!(bind_trace.provider_cancel_posts, 0);
    }

    #[test]
    fn retry_typestate_binds_parent_then_persists_lineage_before_completion() {
        let temporary = TempDir::new().expect("temporary directory");
        let parent = record(&temporary);
        let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let cancellation = CancellationToken::new();
        let bound = bind_retry_parent_session(
            FakePreparedRetry {
                trace: Rc::clone(&trace),
                parent,
                fail_bind: false,
                fail_lineage: false,
            },
            &cancellation,
        )
        .expect("live parent bind");
        execute_bound_retry_session(
            bound,
            &RetryLineageOptionsV1::default(),
            |leased_parent| {
                build_exact_retry_child(
                    leased_parent,
                    LocalJobId::new("job-cli-fake-retry-child").unwrap(),
                    "ferry-22222222222222222222222222222222".to_owned(),
                    leased_parent.updated_at_ms + 1,
                )
            },
            cancellation,
            &Reporter::new(false, true, false),
        )
        .expect("fake retry completion");
        let trace = trace.borrow();
        assert_eq!(
            trace.steps,
            vec!["bind_parent", "create_lineage", "complete"]
        );
        assert!(trace.parent_live_bound);
        assert!(trace.lineage_durable);
        assert_eq!(trace.provider_completions, 1);
    }

    #[test]
    fn leased_retry_preflight_rejects_a_raced_parent_before_live_bind_or_lineage() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut parent = record(&temporary);
        parent.state = StoredJobState::Failed;
        parent.last_confirmed_state = Some(StoredJobState::Failed);
        parent.terminal_outcome = Some(StoredBuildOutcome::Failed);
        parent.failure = Some(StoredFailureV1 {
            code: "controller.failed".to_owned(),
            retryable: true,
        });
        parent.cancellation_status = StoredCancellationStatus::Requested;
        let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));

        let error = validate_retry_parent_session(
            FakePreparedRetry {
                trace: Rc::clone(&trace),
                parent,
                fail_bind: false,
                fail_lineage: false,
            },
            false,
            false,
        )
        .expect_err("leased cancellation intent must block before live revalidation");

        assert_eq!(error.code(), "retry_cancellation_pending");
        let trace = trace.borrow();
        assert_eq!(trace.steps, vec!["validate_parent"]);
        assert!(!trace.parent_live_bound);
        assert!(!trace.lineage_durable);
        assert_eq!(trace.provider_completions, 0);
    }

    #[test]
    fn retry_typestate_never_completes_after_bind_or_lineage_failure() {
        let temporary = TempDir::new().expect("temporary directory");
        let parent = record(&temporary);
        let bind_trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let error = bind_retry_parent_session(
            FakePreparedRetry {
                trace: Rc::clone(&bind_trace),
                parent: parent.clone(),
                fail_bind: true,
                fail_lineage: false,
            },
            &CancellationToken::new(),
        )
        .expect_err("retry bind failure");
        assert_eq!(error.code(), "fake_retry_bind_failed");
        let bind_trace = bind_trace.borrow();
        assert_eq!(bind_trace.steps, vec!["bind_parent"]);
        assert!(!bind_trace.lineage_durable);
        assert_eq!(bind_trace.provider_completions, 0);
        drop(bind_trace);

        let lineage_trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let cancellation = CancellationToken::new();
        let bound = bind_retry_parent_session(
            FakePreparedRetry {
                trace: Rc::clone(&lineage_trace),
                parent,
                fail_bind: false,
                fail_lineage: true,
            },
            &cancellation,
        )
        .expect("retry parent bind");
        let error = execute_bound_retry_session(
            bound,
            &RetryLineageOptionsV1::default(),
            |leased_parent| {
                build_exact_retry_child(
                    leased_parent,
                    LocalJobId::new("job-cli-fake-failed-lineage").unwrap(),
                    "ferry-33333333333333333333333333333333".to_owned(),
                    leased_parent.updated_at_ms + 1,
                )
            },
            cancellation,
            &Reporter::new(false, true, false),
        )
        .expect_err("retry lineage failure");
        assert_eq!(error.code(), "fake_retry_lineage_failed");
        let lineage_trace = lineage_trace.borrow();
        assert_eq!(lineage_trace.steps, vec!["bind_parent", "create_lineage"]);
        assert!(!lineage_trace.lineage_durable);
        assert_eq!(lineage_trace.provider_completions, 0);
    }

    #[test]
    fn retry_completion_output_binds_exact_request_and_existing_child_truth() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut initial_parent = record(&temporary);
        initial_parent.state = StoredJobState::Failed;
        initial_parent.last_confirmed_state = Some(StoredJobState::Failed);
        initial_parent.terminal_outcome = Some(StoredBuildOutcome::Failed);
        initial_parent.failure = Some(StoredFailureV1 {
            code: "controller.failed".to_owned(),
            retryable: true,
        });
        let child_job_id = LocalJobId::new("job-cli-recovered-child").unwrap();
        let mut latest_parent = initial_parent.clone();
        latest_parent.revision += 2;
        latest_parent.updated_at_ms += 2;
        latest_parent
            .retry_lineage
            .child_job_ids
            .push(child_job_id.clone());
        let operation_id = "ferry-44444444444444444444444444444444".to_owned();
        let mut child_request = latest_parent.request.clone();
        child_request.operation_id.clone_from(&operation_id);
        let request_sha256 = canonical_request_sha256(&child_request).unwrap();
        let semantic_retry_sha256 = canonical_retry_template_sha256_v1(&child_request).unwrap();
        let mut receipt = test_retry_completion_receipt(
            GithubRetryChildDisposition::Existing,
            initial_parent.local_job_id.clone(),
            initial_parent.revision + 1,
            child_job_id,
            9,
            operation_id.clone(),
            request_sha256.clone(),
            semantic_retry_sha256,
            initial_parent.source.revision.clone(),
            initial_parent.source.manifest_sha256.clone(),
            "provider-job-recovered".to_owned(),
            Some("4242".to_owned()),
            StoredJobState::Succeeded,
            StoredBuildOutcome::Succeeded,
            StoredCleanupStatus::Confirmed,
            vec![(
                "artifact-recovered".to_owned(),
                "d".repeat(64),
                temporary
                    .path()
                    .join("validated.ipa")
                    .to_string_lossy()
                    .into_owned(),
            )],
        );

        validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect("existing child at a concurrent newer parent revision");
        let output = retry_output_from_parent(&latest_parent, false, None, Some(&receipt))
            .expect("existing child output");
        assert!(!output.child_created);
        assert!(output.resumed_existing_child);
        assert!(output.completion_confirmed);
        assert_eq!(output.cleanup_status, Some("confirmed"));
        assert_eq!(output.validated_artifact_count, 1);
        let summary = retry_completion_summary(&receipt);
        assert!(summary.starts_with("Recovered exact successful retry child"));
        assert!(!summary.contains("created"));

        receipt.disposition = GithubRetryChildDisposition::Created;
        validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect("created child receipt");
        let output = retry_output_from_parent(&latest_parent, false, None, Some(&receipt))
            .expect("created child output");
        assert!(output.child_created);
        assert!(!output.resumed_existing_child);

        receipt.disposition = GithubRetryChildDisposition::Existing;
        receipt.request_sha256 = "a".repeat(64);
        let error = validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect_err("arbitrary lowercase request hash");
        assert_eq!(error.code(), "retry_completion_identity_mismatch");
        receipt.request_sha256 = request_sha256;

        receipt.operation_id.clear();
        let error = validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect_err("empty operation ID");
        assert_eq!(error.code(), "retry_completion_identity_mismatch");
        receipt.operation_id = operation_id;

        receipt.cleanup_status = StoredCleanupStatus::Uncertain;
        let error = validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect_err("uncertain retry cleanup");
        assert_eq!(error.code(), "retry_completion_identity_mismatch");
        receipt.cleanup_status = StoredCleanupStatus::Confirmed;

        receipt.artifacts.clear();
        let error = validate_retry_completion_evidence(&initial_parent, &latest_parent, &receipt)
            .expect_err("missing validated artifacts");
        assert_eq!(error.code(), "retry_completion_identity_mismatch");
    }

    #[test]
    fn retry_output_uses_the_durable_policy_when_restart_flags_differ() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut parent = record(&temporary);
        parent.state = StoredJobState::Succeeded;
        parent.last_confirmed_state = Some(StoredJobState::Succeeded);
        parent.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        let binding = RetryLineageBindingV1 {
            authorization_sha256: "a".repeat(64),
            parent_before_revision: parent.revision,
            parent_next_revision: parent.revision + 1,
            child_job_id: LocalJobId::new("job-cli-durable-policy-child").unwrap(),
            child_operation_id: "ferry-55555555555555555555555555555555".to_owned(),
            options: RetryLineageOptionsV1 {
                parent_policy: RetryParentPolicyV1::AllowSuccessful,
                source_policy: RetrySourcePolicyV1::RecapturedGitSnapshot {
                    confirmation_sha256: "b".repeat(64),
                    snapshot_consent_sha256: "c".repeat(64),
                    source_archive_sha256: "d".repeat(64),
                },
            },
        };

        let output = retry_output_from_parent(&parent, false, Some(&binding), None)
            .expect("durable retry output");
        assert!(
            output.force,
            "persisted force authority wins over restart flags"
        );
        assert_eq!(output.source_policy, "recaptured_current_source");
    }

    #[test]
    fn followed_log_ingest_releases_each_bounded_lease_before_sleep() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = record(&temporary);
        store.create(&record).expect("active job");
        let trace = Rc::new(RefCell::new(FakeLogIngestTrace::default()));
        let mut ingestor = FakeLogIngestor {
            trace: Rc::clone(&trace),
            fail_after: Some(2),
        };
        let arguments = JobsLogsArgs {
            local_job_id: record.local_job_id,
            follow: true,
            since: 0,
            phase: None,
            output: None,
        };
        let mut wait = |duration: Duration| {
            assert_eq!(duration, Duration::from_millis(500));
            let mut trace = trace.borrow_mut();
            assert!(!trace.lease_held, "Logs lease survived into follow sleep");
            trace.sleep_calls += 1;
        };
        let error =
            stream_logs_with_wait(&store, &arguments, false, true, &mut ingestor, &mut wait)
                .expect_err("second bounded ingest failure");
        assert_eq!(error.code(), "fake_log_ingest_failed");
        let trace = trace.borrow();
        assert_eq!(trace.calls, 2);
        assert_eq!(trace.sleep_calls, 1);
        assert!(!trace.lease_held);
    }

    #[test]
    fn phase_filtered_log_pages_advance_only_through_returned_events() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("jobs")).expect("job store");
        let record = record(&temporary);
        store.create(&record).expect("durable job");
        for (offset, phase) in ["alpha", "beta", "alpha", "alpha"].into_iter().enumerate() {
            store
                .append_managed_events(
                    &record.local_job_id,
                    record.updated_at_ms + 1 + offset as u64,
                    &[ManagedJobEventInputV1 {
                        source: ManagedEventSource::Controller,
                        source_sequence: None,
                        source_event_sha256: None,
                        occurred_at_ms: record.updated_at_ms + 1 + offset as u64,
                        phase: Some(phase.to_owned()),
                        level: ManagedEventLevel::Info,
                        code: format!("test.{phase}.{offset}"),
                        message: None,
                    }],
                )
                .expect("managed event");
        }

        let first = read_filtered_job_log_page(&store, &record.local_job_id, 0, 2, Some("alpha"))
            .expect("first filtered page");
        assert_eq!(first.0.len(), 2);
        assert_eq!(first.0[0].sequence, 1);
        assert_eq!(first.0[1].sequence, 3);
        assert_eq!(first.1, 3);
        assert!(first.2);

        let second =
            read_filtered_job_log_page(&store, &record.local_job_id, first.1, 2, Some("alpha"))
                .expect("second filtered page");
        assert_eq!(second.0.len(), 1);
        assert_eq!(second.0[0].sequence, 4);
        assert_eq!(second.1, 4);
        assert!(!second.2);

        let empty = read_filtered_job_log_page(&store, &record.local_job_id, 2, 2, Some("missing"))
            .expect("empty filtered page");
        assert!(empty.0.is_empty());
        assert_eq!(empty.1, 2);
        assert!(!empty.2);
    }

    #[test]
    fn one_log_fetch_drains_every_durable_event_page_before_returning() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = record(&temporary);
        store.create(&record).expect("active job");
        let events = [1_u64, 2].map(|source_sequence| ManagedJobEventInputV1 {
            source: ManagedEventSource::Worker,
            source_sequence: Some(source_sequence),
            source_event_sha256: Some(format!("{source_sequence:064x}")),
            occurred_at_ms: record.updated_at_ms + source_sequence,
            phase: Some("build".to_owned()),
            level: ManagedEventLevel::Info,
            code: "worker.line".to_owned(),
            message: None,
        });
        store
            .append_managed_events(&record.local_job_id, record.updated_at_ms + 2, &events)
            .expect("two paged events");
        let trace = Rc::new(RefCell::new(FakeLogIngestTrace::default()));
        let mut ingestor = FakeLogIngestor {
            trace: Rc::clone(&trace),
            fail_after: None,
        };
        let arguments = JobsLogsArgs {
            local_job_id: record.local_job_id,
            follow: false,
            since: 0,
            phase: Some("filtered-out".to_owned()),
            output: None,
        };
        let mut wait = |_duration: Duration| trace.borrow_mut().sleep_calls += 1;

        stream_logs_with_wait_and_page_limit(
            &store,
            &arguments,
            false,
            true,
            &mut ingestor,
            &mut wait,
            1,
        )
        .expect("single fetch with two durable pages");

        let trace = trace.borrow();
        assert_eq!(trace.calls, 1);
        assert_eq!(trace.sleep_calls, 0);
        assert!(!trace.lease_held);
    }

    #[test]
    fn durable_completion_marker_is_bound_to_the_exact_terminal_job_and_digest() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let initial = record(&temporary);
        store.create(&initial).expect("active job");
        let terminal = terminal_record_with_resume(&temporary);
        let identity = durable_worker_log_identity(&terminal).expect("terminal log identity");
        let line_sequence = 1_u64 << 32 | 1;
        let line_digest = "c".repeat(64);
        let worker_events = vec![(line_sequence, line_digest.clone())];
        let line = worker_log_line(&terminal, line_sequence, &line_digest);
        let exact_marker = worker_completion_marker(&terminal, &worker_events);
        let mut proof = WorkerLogJournalProof::default();
        proof.observe(&line, &terminal.local_job_id, &identity);
        proof.observe(&exact_marker, &terminal.local_job_id, &identity);
        assert!(proof.is_complete(&identity));

        let mut spoofed_marker = exact_marker.clone();
        spoofed_marker.phase = None;
        let mut spoofed_proof = WorkerLogJournalProof::default();
        spoofed_proof.observe(&line, &terminal.local_job_id, &identity);
        spoofed_proof.observe(&spoofed_marker, &terminal.local_job_id, &identity);
        assert!(!spoofed_proof.is_complete(&identity));

        spoofed_marker = exact_marker.clone();
        spoofed_marker.source_event_sha256 = Some("f".repeat(64));
        let mut spoofed_proof = WorkerLogJournalProof::default();
        spoofed_proof.observe(&line, &terminal.local_job_id, &identity);
        spoofed_proof.observe(&spoofed_marker, &terminal.local_job_id, &identity);
        assert!(!spoofed_proof.is_complete(&identity));

        let mut wrong_run = terminal.clone();
        wrong_run
            .provider_resume
            .as_mut()
            .unwrap()
            .run
            .as_mut()
            .unwrap()
            .run_id += 1;
        wrong_run.provider_run_id = Some("4243".to_owned());
        let wrong_run_identity =
            durable_worker_log_identity(&wrong_run).expect("wrong run identity");
        let mut wrong_run_proof = WorkerLogJournalProof::default();
        wrong_run_proof.observe(&line, &terminal.local_job_id, &wrong_run_identity);
        wrong_run_proof.observe(&exact_marker, &terminal.local_job_id, &wrong_run_identity);
        assert!(!wrong_run_proof.is_complete(&wrong_run_identity));

        let mut wrong_repository = terminal.clone();
        wrong_repository
            .provider_resume
            .as_mut()
            .unwrap()
            .execution_repository = "https://github.com/example/other-execution".to_owned();
        let wrong_repository_identity =
            durable_worker_log_identity(&wrong_repository).expect("wrong repository identity");
        let mut wrong_repository_proof = WorkerLogJournalProof::default();
        wrong_repository_proof.observe(&line, &terminal.local_job_id, &wrong_repository_identity);
        wrong_repository_proof.observe(
            &exact_marker,
            &terminal.local_job_id,
            &wrong_repository_identity,
        );
        assert!(!wrong_repository_proof.is_complete(&wrong_repository_identity));

        spoofed_marker = exact_marker.clone();
        spoofed_marker.local_job_id = LocalJobId::new("job-cli-cross-job").unwrap();
        let mut cross_job_proof = WorkerLogJournalProof::default();
        cross_job_proof.observe(&line, &terminal.local_job_id, &identity);
        cross_job_proof.observe(&spoofed_marker, &terminal.local_job_id, &identity);
        assert!(!cross_job_proof.is_complete(&identity));

        let forged = ManagedJobEventInputV1 {
            source: exact_marker.source,
            source_sequence: exact_marker.source_sequence,
            source_event_sha256: exact_marker.source_event_sha256.clone(),
            occurred_at_ms: exact_marker.occurred_at_ms,
            phase: exact_marker.phase.clone(),
            level: exact_marker.level,
            code: exact_marker.code.clone(),
            message: exact_marker.message.clone(),
        };
        store
            .append_managed_events(
                &initial.local_job_id,
                exact_marker.occurred_at_ms,
                &[forged],
            )
            .expect("public store accepts a structurally valid but unbound marker");
        let snapshot = logs_for_project(
            &store,
            &initial.local_job_id,
            &initial.project.canonical_root,
            &initial.project.filesystem_identity,
            u64::MAX,
            Some("filtered-out"),
        )
        .expect("snapshot with a forged marker");

        assert!(!snapshot.provider_full_logs);
        assert_eq!(snapshot.log_scope, JOB_LOG_SCOPE);
        assert!(snapshot.events.is_empty());
    }

    #[test]
    fn durable_completion_requires_the_exact_ordered_worker_event_set() {
        let temporary = TempDir::new().expect("temporary directory");
        let terminal = terminal_record_with_resume(&temporary);
        let identity = durable_worker_log_identity(&terminal).expect("terminal log identity");
        let first_sequence = 1_u64 << 32 | 1;
        let first_digest = "c".repeat(64);
        let worker_events = vec![(first_sequence, first_digest.clone())];
        let first = worker_log_line(&terminal, first_sequence, &first_digest);
        let marker = worker_completion_marker(&terminal, &worker_events);

        let mut partial = WorkerLogJournalProof::default();
        partial.observe(&marker, &terminal.local_job_id, &identity);
        assert!(!partial.is_complete(&identity));

        let second = worker_log_line(&terminal, 1_u64 << 32 | 2, &"d".repeat(64));
        let mut extra = WorkerLogJournalProof::default();
        extra.observe(&first, &terminal.local_job_id, &identity);
        extra.observe(&second, &terminal.local_job_id, &identity);
        extra.observe(&marker, &terminal.local_job_id, &identity);
        assert!(!extra.is_complete(&identity));

        let mut duplicate = WorkerLogJournalProof::default();
        duplicate.observe(&first, &terminal.local_job_id, &identity);
        duplicate.observe(&first, &terminal.local_job_id, &identity);
        duplicate.observe(&marker, &terminal.local_job_id, &identity);
        assert!(!duplicate.is_complete(&identity));

        let mut unknown = first.clone();
        unknown.code = "worker.unknown".to_owned();
        let mut unknown_proof = WorkerLogJournalProof::default();
        unknown_proof.observe(&unknown, &terminal.local_job_id, &identity);
        unknown_proof.observe(&marker, &terminal.local_job_id, &identity);
        assert!(!unknown_proof.is_complete(&identity));

        let mut zero_timestamp = first.clone();
        zero_timestamp.occurred_at_ms = 0;
        let mut zero_timestamp_proof = WorkerLogJournalProof::default();
        zero_timestamp_proof.observe(&zero_timestamp, &terminal.local_job_id, &identity);
        zero_timestamp_proof.observe(&marker, &terminal.local_job_id, &identity);
        assert!(!zero_timestamp_proof.is_complete(&identity));

        let cross_attempt = worker_log_line(&terminal, 2_u64 << 32 | 1, &first_digest);
        let cross_attempt_marker = worker_completion_marker(
            &terminal,
            &[(cross_attempt.source_sequence.unwrap(), first_digest)],
        );
        let mut cross_attempt_proof = WorkerLogJournalProof::default();
        cross_attempt_proof.observe(&cross_attempt, &terminal.local_job_id, &identity);
        cross_attempt_proof.observe(&cross_attempt_marker, &terminal.local_job_id, &identity);
        assert!(!cross_attempt_proof.is_complete(&identity));

        let zero_line_marker = worker_completion_marker(&terminal, &[]);
        let mut zero_line = WorkerLogJournalProof::default();
        zero_line.observe(&zero_line_marker, &terminal.local_job_id, &identity);
        assert!(zero_line.is_complete(&identity));

        let mut not_append_last = WorkerLogJournalProof::default();
        not_append_last.observe(&marker, &terminal.local_job_id, &identity);
        not_append_last.observe(&first, &terminal.local_job_id, &identity);
        assert!(!not_append_last.is_complete(&identity));
    }

    #[test]
    fn terminal_provider_marker_is_retained_before_local_lifecycle_settles() {
        let temporary = TempDir::new().expect("temporary directory");
        let settled = terminal_record_with_resume(&temporary);
        let mut before_local_settlement = settled.clone();
        before_local_settlement.state = StoredJobState::Running;
        before_local_settlement.last_confirmed_state = Some(StoredJobState::Running);
        before_local_settlement.terminal_outcome = None;
        before_local_settlement.cleanup_status = StoredCleanupStatus::Pending;
        before_local_settlement.failure = None;
        let early_identity = durable_worker_log_identity(&before_local_settlement)
            .expect("provider-terminal identity before local settlement");
        let settled_identity =
            durable_worker_log_identity(&settled).expect("settled provider identity");
        assert_eq!(early_identity, settled_identity);

        let line_sequence = 1_u64 << 32 | 1;
        let line_digest = "c".repeat(64);
        let worker_events = vec![(line_sequence, line_digest.clone())];
        let line = worker_log_line(&settled, line_sequence, &line_digest);
        let marker = worker_completion_marker(&settled, &worker_events);
        let mut proof = WorkerLogJournalProof::default();
        proof.observe(&line, &settled.local_job_id, &early_identity);
        proof.observe(&marker, &settled.local_job_id, &early_identity);
        assert!(proof.is_complete(&settled_identity));
    }

    #[test]
    fn provider_log_ingest_receipt_is_revision_and_append_bound() {
        let temporary = TempDir::new().expect("temporary directory");
        let record = record(&temporary);
        let not_applicable = ProviderLogIngestStatus {
            revision: Some(record.revision),
            ..ProviderLogIngestStatus::default()
        };
        validate_log_ingest_status(&record, &not_applicable).expect("exact no-fetch receipt");

        let mut raced = record.clone();
        raced.revision += 1;
        let error = validate_log_ingest_status(&raced, &not_applicable)
            .expect_err("post-return job revision race");
        assert_eq!(error.code(), "provider_log_receipt_stale");

        let empty_fetch = ProviderLogIngestStatus {
            provider_fetch_performed: true,
            revision: Some(record.revision),
            durable_records_observed: 0,
        };
        let error = validate_log_ingest_status(&record, &empty_fetch)
            .expect_err("fetch without a durable event or marker");
        assert_eq!(error.code(), "provider_log_receipt_stale");

        let exact_fetch = ProviderLogIngestStatus {
            durable_records_observed: 1,
            ..empty_fetch
        };
        validate_log_ingest_status(&record, &exact_fetch).expect("exact fetched receipt");
    }

    #[test]
    fn provider_log_poll_honors_a_preexisting_process_interrupt() {
        assert!(log_poll_cancellation_token(true).is_cancelled());
        assert!(!log_poll_cancellation_token(false).is_cancelled());
    }

    #[test]
    fn failed_log_refresh_still_flushes_existing_durable_events() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = record(&temporary);
        store.create(&record).expect("active job");
        store
            .append_managed_events(
                &record.local_job_id,
                record.updated_at_ms + 1,
                &[ManagedJobEventInputV1 {
                    source: ManagedEventSource::Worker,
                    source_sequence: Some(1),
                    source_event_sha256: Some("1".repeat(64)),
                    occurred_at_ms: record.updated_at_ms + 1,
                    phase: Some("build".to_owned()),
                    level: ManagedEventLevel::Info,
                    code: "worker.log_line".to_owned(),
                    message: Some("preserved sanitized line".to_owned()),
                }],
            )
            .expect("existing durable event");
        let output = Utf8PathBuf::from_path_buf(temporary.path().join("logs.ndjson"))
            .expect("UTF-8 test output");
        let trace = Rc::new(RefCell::new(FakeLogIngestTrace::default()));
        let mut ingestor = FakeLogIngestor {
            trace,
            fail_after: Some(1),
        };
        let arguments = JobsLogsArgs {
            local_job_id: record.local_job_id,
            follow: false,
            since: 0,
            phase: None,
            output: Some(output.clone()),
        };

        let error = stream_logs_with_wait(
            &store,
            &arguments,
            false,
            true,
            &mut ingestor,
            &mut |_duration| {},
        )
        .expect_err("refresh failure remains nonzero");

        assert_eq!(error.code(), "fake_log_ingest_failed");
        let persisted = std::fs::read_to_string(output).expect("flushed durable log output");
        assert!(persisted.contains("preserved sanitized line"));
    }

    #[test]
    fn followed_log_ingest_caps_incomplete_post_terminal_fetches() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let initial = record(&temporary);
        store.create(&initial).expect("initial job");
        store
            .update(&initial.local_job_id, |previous| {
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
            .expect("terminal job");
        let trace = Rc::new(RefCell::new(FakeLogIngestTrace::default()));
        let mut ingestor = FakeLogIngestor {
            trace: Rc::clone(&trace),
            fail_after: None,
        };
        let arguments = JobsLogsArgs {
            local_job_id: initial.local_job_id,
            follow: true,
            since: 0,
            phase: None,
            output: None,
        };
        let mut wait = |_duration: Duration| {
            let mut trace = trace.borrow_mut();
            assert!(!trace.lease_held);
            trace.sleep_calls += 1;
        };
        let error =
            stream_logs_with_wait(&store, &arguments, false, true, &mut ingestor, &mut wait)
                .expect_err("bounded incomplete log result");
        assert_eq!(error.code(), "provider_logs_incomplete");
        let trace = trace.borrow();
        assert_eq!(trace.calls, MAX_POST_TERMINAL_LOG_FETCHES);
        assert_eq!(trace.sleep_calls, MAX_POST_TERMINAL_LOG_FETCHES - 1);
        assert!(!trace.lease_held);
    }

    #[test]
    fn successful_retry_requires_force_and_complete_evidence() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut successful = record(&temporary);
        successful.state = StoredJobState::Succeeded;
        successful.last_confirmed_state = Some(StoredJobState::Succeeded);
        successful.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        successful.cleanup_status = StoredCleanupStatus::Confirmed;

        let without_force = validate_retry_preflight(&successful, false)
            .expect_err("successful retry without force");
        assert_eq!(without_force.code(), "retry_force_required");

        let incomplete =
            validate_retry_preflight(&successful, true).expect_err("successful retry evidence");
        assert_eq!(incomplete.code(), "successful_retry_evidence_incomplete");
    }

    #[test]
    fn invalid_retry_preflights_make_zero_live_calls() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut successful = record(&temporary);
        successful.state = StoredJobState::Succeeded;
        successful.last_confirmed_state = Some(StoredJobState::Succeeded);
        successful.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        successful.cleanup_status = StoredCleanupStatus::Confirmed;

        let mut failed = record(&temporary);
        failed.state = StoredJobState::Failed;
        failed.last_confirmed_state = Some(StoredJobState::Failed);
        failed.terminal_outcome = Some(StoredBuildOutcome::Failed);
        failed.failure = Some(StoredFailureV1 {
            code: "controller.failed".to_owned(),
            retryable: true,
        });

        let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let error = execute_after_retry_preflight(&successful, false, false, || {
            trace.borrow_mut().steps.push("live_call");
            Ok(())
        })
        .expect_err("invalid retry preflight");
        assert_eq!(error.code(), "retry_force_required");
        assert!(trace.borrow().steps.is_empty());

        let current_source_trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        execute_after_retry_preflight(&failed, false, true, || {
            current_source_trace
                .borrow_mut()
                .steps
                .push("leased_action");
            Ok(())
        })
        .expect("current-source retry is available after terminal policy validation");
        assert_eq!(current_source_trace.borrow().steps, ["leased_action"]);

        failed.cancellation_status = StoredCancellationStatus::Uncertain;
        let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let error = execute_after_retry_preflight(&failed, false, false, || {
            trace.borrow_mut().steps.push("live_call");
            Ok(())
        })
        .expect_err("uncertain cancellation preflight");
        assert_eq!(error.code(), "retry_cancellation_uncertain");
        assert!(trace.borrow().steps.is_empty());

        for status in [
            StoredCancellationStatus::Requested,
            StoredCancellationStatus::Dispatched,
        ] {
            failed.cancellation_status = status;
            let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
            let error = execute_after_retry_preflight(&failed, false, false, || {
                trace.borrow_mut().steps.push("live_call");
                Ok(())
            })
            .expect_err("pending cancellation preflight");
            assert_eq!(error.code(), "retry_cancellation_pending");
            assert!(trace.borrow().steps.is_empty());
        }

        failed.cancellation_status = StoredCancellationStatus::NotRequested;
        failed.provider_job_id = Some("provider-job-1".to_owned());
        let trace = Rc::new(RefCell::new(FakeRetryTrace::default()));
        let error = execute_after_retry_preflight(&failed, false, false, || {
            trace.borrow_mut().steps.push("live_call");
            Ok(())
        })
        .expect_err("unconfirmed provider cleanup preflight");
        assert_eq!(error.code(), "retry_cleanup_not_safe");
        assert!(trace.borrow().steps.is_empty());
    }

    #[test]
    fn cancellation_preflight_never_redispatches_an_ambiguous_provider_intent() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut record = active_record_with_resume(&temporary);
        assert_eq!(
            validate_cancel_preflight(&record).expect("fresh cancellation"),
            CancelPreflightAction::PersistIntentThenDispatch
        );

        record.cancellation_status = StoredCancellationStatus::Requested;
        let action = validate_cancel_preflight(&record).expect("persisted local intent");
        assert_eq!(action, CancelPreflightAction::ReconcileWithoutDispatch);
        let preview = cancel_output_from_record(
            &record,
            true,
            false,
            0,
            action == CancelPreflightAction::ReconcileWithoutDispatch,
        );
        assert!(preview.get_only_reconciliation);
        assert!(!preview.intent_written);
        assert_eq!(preview.provider_cancel_requests_made, 0);

        record
            .provider_resume
            .as_mut()
            .expect("provider resume")
            .cancellation_requested = true;
        assert_eq!(
            validate_cancel_preflight(&record).expect("ambiguous provider boundary"),
            CancelPreflightAction::ReconcileWithoutDispatch
        );

        record.cancellation_status = StoredCancellationStatus::Dispatched;
        record
            .provider_resume
            .as_mut()
            .expect("provider resume")
            .cancellation_dispatched = true;
        assert_eq!(
            validate_cancel_preflight(&record).expect("dispatched cancellation"),
            CancelPreflightAction::ReconcileWithoutDispatch
        );

        record.cancellation_status = StoredCancellationStatus::Uncertain;
        assert_eq!(
            validate_cancel_preflight(&record).expect("uncertain cancellation"),
            CancelPreflightAction::ReconcileWithoutDispatch
        );
    }

    #[test]
    fn cancellation_preflight_allows_only_existing_intent_to_finish_terminal_cleanup() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut terminal = active_record_with_resume(&temporary);
        terminal.state = StoredJobState::Cancelled;
        terminal.last_confirmed_state = Some(StoredJobState::Cancelled);
        terminal.terminal_outcome = Some(StoredBuildOutcome::Cancelled);
        terminal.cleanup_status = StoredCleanupStatus::Uncertain;
        let error = validate_cancel_preflight(&terminal).expect_err("fresh terminal job");
        assert_eq!(error.code(), "job_not_cancellable");

        terminal.cancellation_status = StoredCancellationStatus::Confirmed;
        terminal
            .provider_resume
            .as_mut()
            .expect("provider resume")
            .state = JobState::Cancelled;
        assert_eq!(
            validate_cancel_preflight(&terminal).expect("terminal cleanup recovery"),
            CancelPreflightAction::ReconcileWithoutDispatch
        );
    }

    #[test]
    fn cancellation_output_rejects_false_request_or_cleanup_success() {
        let temporary = TempDir::new().expect("temporary directory");
        let initial = active_record_with_resume(&temporary);
        let mut receipt = GithubCancellationSessionReceipt {
            local_job_id: initial.local_job_id.clone(),
            revision: initial.revision + 1,
            state: StoredJobState::Cancelled,
            cancellation_status: StoredCancellationStatus::Confirmed,
            terminal_outcome: StoredBuildOutcome::Cancelled,
            cleanup_status: StoredCleanupStatus::Confirmed,
            provider_state: JobState::Cancelled,
            provider_cancel_posts: 1,
            get_only_reconciliation: false,
            intent_written_by_this_call: true,
        };
        validate_cancel_completion(&initial, &receipt).expect("exact cancellation receipt");

        receipt.get_only_reconciliation = true;
        let error =
            validate_cancel_completion(&initial, &receipt).expect_err("GET-only request count");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.get_only_reconciliation = false;
        receipt.provider_cancel_posts = 0;
        receipt.cleanup_status = StoredCleanupStatus::Uncertain;
        let error = validate_cancel_completion(&initial, &receipt).expect_err("uncertain cleanup");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.cleanup_status = StoredCleanupStatus::Confirmed;
        receipt.terminal_outcome = StoredBuildOutcome::Succeeded;
        let error = validate_cancel_completion(&initial, &receipt).expect_err("false race status");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.terminal_outcome = StoredBuildOutcome::Cancelled;
        receipt.local_job_id = LocalJobId::new("job-cli-wrong-cancel-receipt").unwrap();
        let error = validate_cancel_completion(&initial, &receipt).expect_err("wrong job receipt");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.local_job_id = initial.local_job_id.clone();
        receipt.state = StoredJobState::Running;
        receipt.provider_state = JobState::Queued;
        let error =
            validate_cancel_completion(&initial, &receipt).expect_err("nonterminal state receipt");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        let mut existing_intent = initial.clone();
        existing_intent.cancellation_status = StoredCancellationStatus::Requested;
        receipt.state = StoredJobState::Cancelled;
        receipt.provider_state = JobState::Cancelled;
        receipt.provider_cancel_posts = 1;
        receipt.get_only_reconciliation = false;
        receipt.intent_written_by_this_call = true;
        let error = validate_cancel_completion(&existing_intent, &receipt)
            .expect_err("preexisting intent redispatch");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.provider_cancel_posts = 0;
        receipt.get_only_reconciliation = true;
        receipt.intent_written_by_this_call = false;
        validate_cancel_completion(&existing_intent, &receipt)
            .expect("preexisting intent GET-only completion");

        receipt.get_only_reconciliation = false;
        receipt.intent_written_by_this_call = true;
        receipt.provider_cancel_posts = 1;
        receipt.revision = initial.revision;
        let error = validate_cancel_completion(&initial, &receipt)
            .expect_err("intent without durable revision advance");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        let mut terminal_recovery = initial.clone();
        terminal_recovery.state = StoredJobState::Cancelled;
        terminal_recovery.last_confirmed_state = Some(StoredJobState::Cancelled);
        terminal_recovery.terminal_outcome = Some(StoredBuildOutcome::Cancelled);
        terminal_recovery.cancellation_status = StoredCancellationStatus::Confirmed;
        terminal_recovery.cleanup_status = StoredCleanupStatus::Uncertain;
        receipt.revision = terminal_recovery.revision + 1;
        let error = validate_cancel_completion(&terminal_recovery, &receipt)
            .expect_err("terminal recovery redispatch");
        assert_eq!(error.code(), "cancellation_completion_identity_mismatch");

        receipt.intent_written_by_this_call = false;
        receipt.provider_cancel_posts = 0;
        validate_cancel_completion(&terminal_recovery, &receipt)
            .expect("terminal recovery without redispatch");
    }

    #[test]
    fn exact_retry_child_rebinds_only_operation_and_resets_provider_state() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut parent = record(&temporary);
        parent.retry_lineage.attempt = 4;
        parent.provider_job_id = Some(parent.operation_id.clone());
        parent.provider_run_id = Some("12345".to_owned());
        parent.submitted_at_ms = Some(102);
        parent.state = StoredJobState::Failed;
        parent.last_confirmed_state = Some(StoredJobState::Failed);
        parent.terminal_outcome = Some(StoredBuildOutcome::Failed);
        parent.cleanup_status = StoredCleanupStatus::Confirmed;
        parent.cancellation_status = StoredCancellationStatus::Failed;
        parent.failure = Some(cargo_ferry::job_store::StoredFailureV1 {
            code: "provider.failed".to_owned(),
            retryable: true,
        });
        parent.artifacts.push(artifact(&temporary));
        parent.log_location = Some("managed-events".to_owned());

        let child_id = LocalJobId::new("job-cli-retry-child").unwrap();
        let child = build_exact_retry_child(
            &parent,
            child_id.clone(),
            "ferry-0123456789abcdef0123456789abcdef".to_owned(),
            90,
        )
        .expect("exact retry child");

        assert_eq!(child.local_job_id, child_id);
        assert_eq!(child.revision, 1);
        assert_eq!(child.project, parent.project);
        assert_eq!(child.provider, parent.provider);
        assert_eq!(child.source, parent.source);
        assert_eq!(child.semantic_retry_sha256, parent.semantic_retry_sha256);
        assert_eq!(child.operation_id, child.request.operation_id);
        assert_ne!(child.operation_id, parent.operation_id);
        assert_ne!(child.request_sha256, parent.request_sha256);
        assert_eq!(child.created_at_ms, parent.updated_at_ms);
        assert_eq!(child.updated_at_ms, parent.updated_at_ms);
        assert_eq!(child.state, StoredJobState::SourceReady);
        assert_eq!(
            child.last_confirmed_state,
            Some(StoredJobState::SourceReady)
        );
        assert_eq!(child.retry_lineage.attempt, 5);
        assert_eq!(
            child.retry_lineage.parent_job_id.as_ref(),
            Some(&parent.local_job_id)
        );
        assert!(child.retry_lineage.child_job_ids.is_empty());
        assert!(child.provider_job_id.is_none());
        assert!(child.provider_run_id.is_none());
        assert!(child.submitted_at_ms.is_none());
        assert!(child.terminal_outcome.is_none());
        assert!(child.compile_evidence.is_none());
        assert!(child.signed_cleanup_evidence.is_none());
        assert!(child.artifacts.is_empty());
        assert!(child.log_location.is_none());
        assert_eq!(child.cleanup_status, StoredCleanupStatus::NotStarted);
        assert_eq!(
            child.cancellation_status,
            StoredCancellationStatus::NotRequested
        );
        assert!(child.failure.is_none());
        assert!(child.provider_resume.is_none());
    }

    #[test]
    fn exact_retry_child_fails_closed_on_counter_or_semantic_drift() {
        let temporary = TempDir::new().expect("temporary directory");
        let mut exhausted = record(&temporary);
        exhausted.retry_lineage.attempt = u32::MAX;
        let error = build_exact_retry_child(
            &exhausted,
            LocalJobId::new("job-cli-retry-overflow").unwrap(),
            "ferry-0123456789abcdef0123456789abcdef".to_owned(),
            102,
        )
        .expect_err("attempt overflow");
        assert_eq!(error.code(), "retry_attempt_exhausted");

        let mut drifted = record(&temporary);
        drifted.semantic_retry_sha256 = "f".repeat(64);
        let error = build_exact_retry_child(
            &drifted,
            LocalJobId::new("job-cli-retry-drift").unwrap(),
            "ferry-fedcba9876543210fedcba9876543210".to_owned(),
            102,
        )
        .expect_err("semantic drift");
        assert_eq!(error.code(), "retry_semantic_identity_mismatch");
    }

    #[test]
    fn exact_retry_child_is_accepted_by_atomic_store_lineage() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let initial = record(&temporary);
        store.create(&initial).expect("initial parent");
        store
            .update(&initial.local_job_id, |previous| {
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
            .expect("failed parent");
        let parent = store.latest(&initial.local_job_id).expect("latest parent");
        let lease = store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .expect("retry lease");
        let child = build_exact_retry_child(
            &parent,
            LocalJobId::new("job-cli-retry-transaction-child").unwrap(),
            "ferry-11111111111111111111111111111111".to_owned(),
            parent.updated_at_ms + 1,
        )
        .expect("exact child");
        let options = RetryLineageOptionsV1::default();
        let receipt = store
            .create_retry_lineage(&parent.local_job_id, &lease, &child, &options)
            .expect("atomic lineage");
        assert!(!receipt.parent.already_present);
        assert!(!receipt.child.already_present);
        assert_eq!(
            store
                .latest(&parent.local_job_id)
                .expect("parent successor")
                .retry_lineage
                .child_job_ids,
            vec![child.local_job_id.clone()]
        );
        assert_eq!(
            store
                .latest(&child.local_job_id)
                .expect("child revision")
                .retry_lineage
                .parent_job_id,
            Some(parent.local_job_id.clone())
        );
        let replay = store
            .create_retry_lineage(&parent.local_job_id, &lease, &child, &options)
            .expect("idempotent lineage replay");
        assert!(replay.parent.already_present);
        assert!(replay.child.already_present);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial restart scenario proves active and settled recaptured-child policy across CLI and IDE entrypoints"
    )]
    fn project_retry_requires_fresh_consent_for_an_unsubmitted_recaptured_child() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let initial = record(&temporary);
        store.create(&initial).expect("initial parent");
        store
            .update(&initial.local_job_id, |previous| {
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
            .expect("failed parent");
        let parent = store.latest(&initial.local_job_id).expect("latest parent");
        let mut child = build_exact_retry_child(
            &parent,
            LocalJobId::new("job-cli-recaptured-child").unwrap(),
            "ferry-22222222222222222222222222222222".to_owned(),
            parent.updated_at_ms + 1,
        )
        .expect("retry child");
        child.request.source_mode = SourceMode::GitSnapshot;
        child.request.source_revision = Some("f".repeat(40));
        child
            .source
            .revision
            .clone_from(&child.request.source_revision);
        child.request_sha256 = canonical_request_sha256(&child.request).unwrap();
        child.semantic_retry_sha256 = canonical_retry_template_sha256_v1(&child.request).unwrap();
        let options = RetryLineageOptionsV1 {
            parent_policy: RetryParentPolicyV1::RequireUnsuccessful,
            source_policy: RetrySourcePolicyV1::RecapturedGitSnapshot {
                confirmation_sha256: retry_recapture_confirmation_sha256(&parent, &child).unwrap(),
                snapshot_consent_sha256: "d".repeat(64),
                source_archive_sha256: "e".repeat(64),
            },
        };
        let lease = store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .expect("retry lease");
        store
            .create_retry_lineage(&parent.local_job_id, &lease, &child, &options)
            .expect("recaptured lineage");
        drop(lease);

        let parent = store.latest(&parent.local_job_id).expect("lineage parent");
        let error = validate_project_retry_preflight(
            &store,
            &parent,
            &parent.project.canonical_root,
            &parent.project.filesystem_identity,
        )
        .expect_err("unsubmitted recaptured child requires fresh consent");
        assert_eq!(error.code(), "retry_current_source_consent_required");
        let eligibility = eligibility_for_project(
            &store,
            &parent.local_job_id,
            &parent.project.canonical_root,
            &parent.project.filesystem_identity,
        )
        .expect("project eligibility");
        assert!(!eligibility.can_retry);
        assert_eq!(
            eligibility.retry_reason_code.as_deref(),
            Some("retry_current_source_consent_required")
        );
        let error = retry_for_project(
            &store,
            &parent.local_job_id,
            &parent.project.canonical_root,
            &parent.project.filesystem_identity,
            CancellationToken::new(),
        )
        .expect_err("IDE exact retry must not bypass fresh consent");
        assert_eq!(error.code(), "retry_current_source_consent_required");
        let parent_before = store.latest(&parent.local_job_id).unwrap();
        let child_before = store.latest(&child.local_job_id).unwrap();
        let error = exact_retry_preflight(&store, &parent.local_job_id, false)
            .err()
            .expect("default CLI retry must reject before provider reconstruction");
        assert_eq!(error.code(), "retry_current_source_consent_required");
        assert_eq!(store.latest(&parent.local_job_id).unwrap(), parent_before);
        assert_eq!(store.latest(&child.local_job_id).unwrap(), child_before);

        let binding = store
            .retry_lineage_binding(&parent.local_job_id, &child.local_job_id)
            .unwrap();
        store
            .update(&child.local_job_id, |previous| {
                let mut settled = previous.clone();
                settled.revision += 1;
                settled.updated_at_ms += 1;
                settled.state = StoredJobState::Failed;
                settled.last_confirmed_state = Some(StoredJobState::Failed);
                settled.terminal_outcome = Some(StoredBuildOutcome::Failed);
                settled.failure = Some(StoredFailureV1 {
                    code: "controller.failed".to_owned(),
                    retryable: true,
                });
                Ok(settled)
            })
            .expect("settled recaptured child");
        let error = persisted_retry_bypasses_recapture(&store, &parent, Some(&binding))
            .expect_err("current-source retry rejects a settled existing child before preview");
        assert_eq!(error.code(), "retry_child_already_settled");
        let error = exact_retry_preflight(&store, &parent.local_job_id, false)
            .err()
            .expect("settled child takes precedence over recapture consent");
        assert_eq!(error.code(), "retry_child_already_settled");
    }

    fn record(temporary: &TempDir) -> StoredJobV1 {
        let request = request();
        let project_filesystem_identity =
            rustferry_core::DirectoryFilesystemIdentity::capture(temporary.path())
                .expect("project fixture identity")
                .to_string();
        StoredJobV1 {
            schema_version: JOB_STORE_SCHEMA_VERSION,
            local_job_id: LocalJobId::new("job-cli-output-1").unwrap(),
            revision: 1,
            project: StoredProjectIdentityV1 {
                canonical_root: temporary.path().to_string_lossy().into_owned(),
                filesystem_identity: project_filesystem_identity,
                application_identifier: request.bundle_identifier.clone(),
            },
            provider: StoredProviderIdentityV1 {
                provider: GITHUB_PROVIDER_ID.to_owned(),
                provider_config_sha256: "a".repeat(64),
                principal: GithubPrincipalIdentityV1::User {
                    id: 7,
                    login: "example-user".to_owned(),
                },
                execution_repository: "https://github.com/example/private-execution".to_owned(),
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
            updated_at_ms: 101,
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

    fn active_record_with_resume(temporary: &TempDir) -> StoredJobV1 {
        let mut record = record(temporary);
        record.provider_job_id = Some(record.operation_id.clone());
        record.provider_run_id = Some("4242".to_owned());
        record.submitted_at_ms = Some(102);
        record.state = StoredJobState::Queued;
        record.last_confirmed_state = Some(StoredJobState::Queued);
        record.provider_resume = Some(github_resume(&record));
        record
    }

    fn terminal_record_with_resume(temporary: &TempDir) -> StoredJobV1 {
        let mut record = active_record_with_resume(temporary);
        record.state = StoredJobState::Failed;
        record.last_confirmed_state = Some(StoredJobState::Failed);
        record.terminal_outcome = Some(StoredBuildOutcome::Failed);
        record.cleanup_status = StoredCleanupStatus::Confirmed;
        record.cancellation_status = StoredCancellationStatus::Failed;
        record.failure = Some(StoredFailureV1 {
            code: "provider.failed".to_owned(),
            retryable: true,
        });
        let resume = record.provider_resume.as_mut().unwrap();
        resume.state = JobState::Failed;
        let run = resume.run.as_mut().unwrap();
        run.status = GithubRunStatusV1::Completed;
        run.conclusion = Some(GithubRunConclusionV1::Failure);
        record
    }

    fn worker_log_line(
        record: &StoredJobV1,
        source_sequence: u64,
        digest: &str,
    ) -> ManagedJobEventV1 {
        ManagedJobEventV1 {
            schema_version: 1,
            local_job_id: record.local_job_id.clone(),
            sequence: source_sequence,
            occurred_at_ms: record.updated_at_ms + 1,
            phase: Some(WORKER_LOG_PHASE.to_owned()),
            source: ManagedEventSource::Worker,
            source_sequence: Some(source_sequence),
            source_event_sha256: Some(digest.to_owned()),
            level: ManagedEventLevel::Info,
            code: WORKER_LOG_LINE_CODE.to_owned(),
            message: Some("sanitized worker line".to_owned()),
        }
    }

    fn worker_completion_marker(
        record: &StoredJobV1,
        worker_events: &[(u64, String)],
    ) -> ManagedJobEventV1 {
        let resume = record.provider_resume.as_ref().unwrap();
        let run = resume.run.as_ref().unwrap();
        let source_sequence =
            (run.run_attempt << 32) | (u64::from(u16::MAX) << 16) | u64::from(u16::MAX);
        let job_set_sha256 = "a".repeat(64);
        let event_set_sha256 = test_worker_event_set_sha256(worker_events);
        let message = format!(
            "run_id={} run_attempt={} head_sha={} workflow_id={} job_count=1 job_set_sha256={} event_count={} event_set_sha256={}",
            run.run_id,
            run.run_attempt,
            run.head_sha,
            run.workflow_id,
            job_set_sha256,
            worker_events.len(),
            event_set_sha256,
        );
        let occurred_at_ms = record.updated_at_ms + 2;
        let source_event_sha256 = test_worker_completion_sha256(
            record,
            occurred_at_ms,
            &job_set_sha256,
            worker_events.len() as u64,
            &event_set_sha256,
            source_sequence,
            &message,
        );
        ManagedJobEventV1 {
            schema_version: 1,
            local_job_id: record.local_job_id.clone(),
            sequence: source_sequence,
            occurred_at_ms,
            phase: Some(WORKER_LOG_PHASE.to_owned()),
            source: ManagedEventSource::Worker,
            source_sequence: Some(source_sequence),
            source_event_sha256: Some(source_event_sha256),
            level: ManagedEventLevel::Info,
            code: WORKER_LOGS_COMPLETE_CODE.to_owned(),
            message: Some(message),
        }
    }

    fn test_worker_event_set_sha256(worker_events: &[(u64, String)]) -> String {
        let mut digest = Sha256::new();
        digest.update(b"rustferry.github.worker-log-event-set.v1\0");
        digest.update((worker_events.len() as u64).to_be_bytes());
        for (source_sequence, source_event_sha256) in worker_events {
            digest.update(source_sequence.to_be_bytes());
            test_digest_field(&mut digest, source_event_sha256.as_bytes());
        }
        test_sha256_hex(digest)
    }

    #[allow(clippy::too_many_arguments)]
    fn test_worker_completion_sha256(
        record: &StoredJobV1,
        occurred_at_ms: u64,
        job_set_sha256: &str,
        event_count: u64,
        event_set_sha256: &str,
        source_sequence: u64,
        message: &str,
    ) -> String {
        let endpoint = GithubGitEndpoint::parse(&record.provider.execution_repository).unwrap();
        let run = record
            .provider_resume
            .as_ref()
            .unwrap()
            .run
            .as_ref()
            .unwrap();
        let mut digest = Sha256::new();
        digest.update(b"rustferry.github.worker-logs-complete.v1\0");
        test_digest_field(&mut digest, endpoint.repository().owner().as_bytes());
        test_digest_field(&mut digest, endpoint.repository().name().as_bytes());
        digest.update(run.run_id.to_be_bytes());
        digest.update(u16::try_from(run.run_attempt).unwrap().to_be_bytes());
        test_digest_field(&mut digest, run.head_sha.as_bytes());
        digest.update(run.workflow_id.to_be_bytes());
        digest.update(occurred_at_ms.to_be_bytes());
        digest.update(1_u32.to_be_bytes());
        test_digest_field(&mut digest, job_set_sha256.as_bytes());
        digest.update(event_count.to_be_bytes());
        test_digest_field(&mut digest, event_set_sha256.as_bytes());
        digest.update(source_sequence.to_be_bytes());
        test_digest_field(&mut digest, WORKER_LOGS_COMPLETE_CODE.as_bytes());
        test_digest_field(&mut digest, message.as_bytes());
        test_sha256_hex(digest)
    }

    fn test_digest_field(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    fn test_sha256_hex(digest: Sha256) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in digest.finalize() {
            write!(&mut output, "{byte:02x}").expect("write digest");
        }
        output
    }

    fn github_resume(record: &StoredJobV1) -> GithubJobResumeV1 {
        let dispatch_commit = "e".repeat(40);
        let workflow_path = ".github/workflows/rustferry.yml".to_owned();
        let branch = format!("rustferry/goal3/builds/{}", record.operation_id);
        GithubJobResumeV1 {
            schema_version: 1,
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: record.provider.provider_config_sha256.clone(),
            principal: record.provider.principal.clone(),
            execution_repository: record.provider.execution_repository.clone(),
            execution_repository_id: record.provider.execution_repository_id,
            source_repository: record.request.source_repository.clone().unwrap(),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_path: workflow_path.clone(),
            workflow_sha256: "d".repeat(64),
            temporary_ref: format!("refs/heads/{branch}"),
            operation_id: record.operation_id.clone(),
            job_id: record.provider_job_id.clone().unwrap(),
            request: record.request.clone(),
            request_sha256: record.request_sha256.clone(),
            source_revision: record.source.revision.clone().unwrap(),
            git_snapshot: None,
            prepared_dispatch_commit: Some(dispatch_commit.clone()),
            dispatch_commit: Some(dispatch_commit.clone()),
            workflow_dispatch: None,
            run: Some(GithubRunIdentityV1 {
                run_id: 4_242,
                workflow_id: 17,
                workflow_path,
                head_sha: dispatch_commit,
                branch,
                event: GithubRunEventV1::Push,
                run_number: 9,
                run_attempt: 1,
                status: GithubRunStatusV1::Queued,
                conclusion: None::<GithubRunConclusionV1>,
            }),
            created_at_ms: record.created_at_ms,
            publication_started_at_ms: record.created_at_ms,
            publication_quiescence_deadline_ms: record.created_at_ms + 4_500_000,
            state: JobState::Queued,
            publication_intent: true,
            publication_uncertain: false,
            publication_absent: false,
            publication_not_attempted: false,
            publication_process_fenced: true,
            publication_lease_scope_sha256: Some("a".repeat(64)),
            publication_absence_observations: 0,
            publication_absence_first_observed_at_ms: 0,
            cancellation_requested: false,
            cancellation_dispatched: false,
            cleanup_requested: false,
            remove_artifacts_requested: false,
            artifacts_removed: false,
            temporary_ref_deleted: false,
            verification_pending_event: false,
            run_discovery_attempts: 0,
            run_discovery_deadline_ms: record.created_at_ms + 750,
            manifests: Vec::new(),
            compile_evidence: None,
            signed_cleanup_evidence: None,
            events: Vec::new(),
        }
    }

    fn artifact(temporary: &TempDir) -> StoredArtifactV1 {
        let artifact_parent = temporary.path().join("target/ferry");
        std::fs::create_dir_all(&artifact_parent).expect("artifact fixture directory");
        let artifact_path = artifact_parent.join("App-unsigned.xcarchive.zip");
        std::fs::write(&artifact_path, [0_u8; 42]).expect("artifact fixture");
        let artifact_path_string = artifact_path.to_string_lossy().into_owned();
        let download_parent_identity =
            rustferry_core::DirectoryFilesystemIdentity::capture(&artifact_parent)
                .expect("download parent fixture identity")
                .to_string();
        let local_file_identity =
            rustferry_core::RegularFileFilesystemIdentity::capture(&artifact_path)
                .expect("artifact fixture identity")
                .to_string();
        StoredArtifactV1 {
            record: ArtifactRecord {
                artifact_id: "artifact-1".to_owned(),
                kind: ArtifactKind::Xcarchive,
                file_name: "App-unsigned.xcarchive.zip".to_owned(),
                size: 42,
                sha256: "c".repeat(64),
                media_type: Some("application/zip".to_owned()),
            },
            download_destination: Some(artifact_path_string.clone()),
            download_parent_identity: Some(download_parent_identity),
            local_path: Some(artifact_path_string),
            local_file_identity: Some(local_file_identity),
            locally_validated: true,
        }
    }

    fn request() -> IosDeviceBuildRequest {
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-cli-output-1".to_owned(),
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
            source_repository: Some("https://github.com/example/source".to_owned()),
            source_revision: Some(SOURCE_REVISION.to_owned()),
            source: empty_source_manifest(),
            signing: SigningPlan {
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
            },
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        }
    }

    fn empty_source_manifest() -> SourceManifest {
        let mut digest = Sha256::new();
        digest.update(b"rustferry-source-manifest-v1\0");
        digest.update(1_u64.to_be_bytes());
        digest.update(b".");
        digest.update(0_u64.to_be_bytes());
        digest.update(0_u64.to_be_bytes());
        SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries: Vec::new(),
            total_size: 0,
            sha256: lower_hex(digest.finalize()),
        }
    }

    fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let bytes = bytes.as_ref();
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
