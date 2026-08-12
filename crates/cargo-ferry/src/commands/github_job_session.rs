use camino::Utf8PathBuf;
use cargo_ferry::job_store::{
    GithubJobStoreCheckpointSink, JobOperationKind, JobOperationLease, JobStore, JobStoreError,
    LocalJobId, MAX_MANAGED_EVENT_PAGE, ManagedEventAppendReceipt, ManagedEventLevel,
    ManagedEventSource, ManagedJobEventInputV1, RetryLineageBindingV1, RetryLineageOptionsV1,
    RetryParentPolicyV1, RetrySourcePolicyV1, SnapshotOperationVacancyV1, StoredBuildOutcome,
    StoredCancellationStatus, StoredCleanupStatus, StoredJobState, StoredJobV1,
};
use rustferry_github::job_logs::{
    GithubDurableRunAttemptLogIdentity, GithubJobLogPoll, WORKER_LOG_LINE_CODE, WORKER_LOG_PHASE,
    WORKER_LOGS_COMPLETE_CODE,
};
use rustferry_github::provider::{
    GITHUB_PROVIDER_ID, GithubDurableIdentityV1, GithubGitSnapshotExactRetryAuthorizationV1,
    GithubGitSnapshotExactRetryPlanV1, GithubGitSnapshotExactRetryStageV1,
    GithubGitSnapshotKeepaliveReleaseAuthorizationV1, GithubGitSnapshotPhaseV1,
    GithubGitSnapshotSubmissionV1,
};
use rustferry_remote::{
    BuildProvider as _, CancellationRequest, CancellationToken, IosDeviceBuildRequest, JobState,
    SourceMode,
};
use std::time::Instant;

use super::{
    ArtifactFileIdentity, BUILD_TIMEOUT, CANCELLATION_TIMEOUT, CONFIG_RELATIVE_PATH,
    CompletedArtifactDownloads, ConfirmedCurrentSnapshotRetry, CurrentSnapshotRetryOperationGuard,
    ExpectedDownload, GitContext, GithubProvider, ImmediateProviderResult, POLL_INTERVAL,
    ProjectFilesystemBinding, ProviderConfigLock, StagedCurrentSnapshotRetry,
    acquire_build_mutation_lease, build_provider, checked_caller_git_output, cleanup_job_durably,
    complete_submitted_job, decode_stored_config, ensure_config_snapshot_unchanged,
    expected_artifact_downloads, git_context_from_stored, handshake, handshake_with_source_mode,
    load_config_for_build, observe_job_until_terminal, persist_cancellation_uncertain,
    persist_non_cancel_terminal_race, persist_submit_uncertain, poll_provider_once,
    prepare_artifact_destination, provider_failure, read_private_config_snapshot,
    reconcile_post_wait_rebind_failure, reconcile_submit_attempt, release_build_wait_guards,
    remote_error, require_bound_provider_job, sleep_interruptibly, update_stored_job, utf8_line,
};
use crate::error::CliError;
use crate::output::Reporter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationAction {
    TerminalNoop,
    DispatchOnce,
    GetOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryChildCompletionMode {
    Continue,
    RetainLocalSuccess,
    RejectSettled,
}

enum PostWaitRebindFailure {
    LeaseUnavailable(CliError),
    LeaseHeld(CliError),
}

struct GithubOperationPreflight {
    record: Box<StoredJobV1>,
    root: Utf8PathBuf,
    project: ProjectFilesystemBinding,
    operation_lease: JobOperationLease,
}

/// Locally reconstructed GitHub job session. Construction performs no GitHub request.
pub(in crate::commands) struct PreparedGithubJobSession {
    store: JobStore,
    local_job_id: LocalJobId,
    record: Box<StoredJobV1>,
    provider: Box<GithubProvider>,
    git: GitContext,
    project: ProjectFilesystemBinding,
    config_identity: ArtifactFileIdentity,
    config_bytes: Vec<u8>,
    _config_lock: ProviderConfigLock,
    operation_lease: JobOperationLease,
    operation_kind: JobOperationKind,
}

/// Locally reconstructed retry-parent session. Construction performs no GitHub request.
pub(in crate::commands) struct PreparedGithubRetrySession {
    prepared: PreparedGithubJobSession,
}

/// Live-revalidated retry parent, still holding the exact parent Retry lease.
pub(in crate::commands) struct BoundGithubRetrySession {
    prepared: PreparedGithubJobSession,
}

/// Offline-restored snapshot-prune session borrowing one lease from the retained complete set.
pub(in crate::commands) struct GithubPruneSnapshotSession<'lease> {
    store: JobStore,
    record: StoredJobV1,
    provider: Box<GithubProvider>,
    git: GitContext,
    project: ProjectFilesystemBinding,
    config_identity: ArtifactFileIdentity,
    config_bytes: Vec<u8>,
    _config_lock: ProviderConfigLock,
    operation_lease: &'lease JobOperationLease,
}

/// Exact durable checkpoint observed after one snapshot keepalive release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands) struct GithubPruneSnapshotReleaseReceipt {
    pub(in crate::commands) local_job_id: LocalJobId,
    pub(in crate::commands) revision: u64,
    pub(in crate::commands) complete_lineage_authorization_sha256: String,
}

/// Child-scoped session created or recovered from durable reciprocal retry lineage.
pub(in crate::commands) struct GithubRetryChildSession {
    store: JobStore,
    parent_before_lineage: StoredJobV1,
    parent_job_id: LocalJobId,
    parent_revision: u64,
    record: StoredJobV1,
    provider: Box<GithubProvider>,
    git: GitContext,
    project: ProjectFilesystemBinding,
    config_identity: ArtifactFileIdentity,
    config_bytes: Vec<u8>,
    config_lock: Option<ProviderConfigLock>,
    operation_lease: Option<JobOperationLease>,
    snapshot_submission: Option<GithubSnapshotRetrySubmission>,
    disposition: GithubRetryChildDisposition,
}

/// Stage authority retained only until the first exact snapshot-child provider checkpoint.
enum GithubSnapshotRetrySubmission {
    Exact {
        authorization: GithubGitSnapshotExactRetryAuthorizationV1,
        staged: Box<GithubGitSnapshotExactRetryStageV1>,
    },
    CurrentSource(Box<StagedCurrentSnapshotRetry>),
}

/// Whether retry submission resumed an existing child or created new durable lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::commands) enum GithubRetryChildDisposition {
    Existing,
    Created,
}

/// One independently validated local artifact from a completed retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands) struct GithubRetryArtifactReceipt {
    pub(in crate::commands) artifact_id: String,
    pub(in crate::commands) sha256: String,
    pub(in crate::commands) local_path: String,
}

/// Secret-free receipt after exact retry success, artifact validation, and cleanup.
#[derive(Debug)]
pub(in crate::commands) struct GithubRetryCompletionReceipt {
    pub(in crate::commands) parent_job_id: LocalJobId,
    pub(in crate::commands) parent_revision: u64,
    pub(in crate::commands) child_job_id: LocalJobId,
    pub(in crate::commands) child_revision: u64,
    pub(in crate::commands) operation_id: String,
    pub(in crate::commands) request_sha256: String,
    pub(in crate::commands) semantic_retry_sha256: String,
    pub(in crate::commands) source_revision: Option<String>,
    pub(in crate::commands) source_manifest_sha256: String,
    pub(in crate::commands) provider_job_id: String,
    pub(in crate::commands) provider_run_id: Option<String>,
    pub(in crate::commands) state: StoredJobState,
    pub(in crate::commands) terminal_outcome: StoredBuildOutcome,
    pub(in crate::commands) cleanup_status: StoredCleanupStatus,
    pub(in crate::commands) artifacts: Vec<GithubRetryArtifactReceipt>,
    pub(in crate::commands) disposition: GithubRetryChildDisposition,
    _completion: Option<CompletedArtifactDownloads>,
    _project: Option<ProjectFilesystemBinding>,
}

/// Secret-free result of one bounded exact-attempt fetch and durable append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands) struct GithubJobLogIngestReceipt {
    pub(in crate::commands) local_job_id: LocalJobId,
    pub(in crate::commands) revision: u64,
    pub(in crate::commands) provider_fetch_performed: bool,
    pub(in crate::commands) appended: usize,
    pub(in crate::commands) already_present: usize,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(in crate::commands) fn test_retry_completion_receipt(
    disposition: GithubRetryChildDisposition,
    parent_job_id: LocalJobId,
    parent_revision: u64,
    child_job_id: LocalJobId,
    child_revision: u64,
    operation_id: String,
    request_sha256: String,
    semantic_retry_sha256: String,
    source_revision: Option<String>,
    source_manifest_sha256: String,
    provider_job_id: String,
    provider_run_id: Option<String>,
    state: StoredJobState,
    terminal_outcome: StoredBuildOutcome,
    cleanup_status: StoredCleanupStatus,
    artifacts: Vec<(String, String, String)>,
) -> GithubRetryCompletionReceipt {
    GithubRetryCompletionReceipt {
        parent_job_id,
        parent_revision,
        child_job_id,
        child_revision,
        operation_id,
        request_sha256,
        semantic_retry_sha256,
        source_revision,
        source_manifest_sha256,
        provider_job_id,
        provider_run_id,
        state,
        terminal_outcome,
        cleanup_status,
        artifacts: artifacts
            .into_iter()
            .map(
                |(artifact_id, sha256, local_path)| GithubRetryArtifactReceipt {
                    artifact_id,
                    sha256,
                    local_path,
                },
            )
            .collect(),
        disposition,
        _completion: None,
        _project: None,
    }
}

/// Session whose controller-owned cancellation intent is already durable.
pub(in crate::commands) struct DurableGithubCancellationSession {
    prepared: PreparedGithubJobSession,
    action: CancellationAction,
    intent_written_by_this_call: bool,
}

/// Live-revalidated cancellation session. Remote mutation remains method-gated.
pub(in crate::commands) struct BoundGithubJobSession {
    durable: DurableGithubCancellationSession,
}

/// Secret-free result of one bounded cancellation dispatch or GET-only reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands) struct GithubCancellationSessionReceipt {
    pub(in crate::commands) local_job_id: LocalJobId,
    pub(in crate::commands) revision: u64,
    pub(in crate::commands) state: StoredJobState,
    pub(in crate::commands) cancellation_status: StoredCancellationStatus,
    pub(in crate::commands) terminal_outcome: StoredBuildOutcome,
    pub(in crate::commands) cleanup_status: StoredCleanupStatus,
    pub(in crate::commands) provider_state: JobState,
    pub(in crate::commands) provider_cancel_posts: u8,
    pub(in crate::commands) get_only_reconciliation: bool,
    pub(in crate::commands) intent_written_by_this_call: bool,
}

/// Fetch and durably project at most one exact GitHub run attempt.
///
/// The `Logs` operation lease and provider-config lock are acquired and released within this call.
/// No raw response body, redirect URL, credential, or unsanitized line crosses the boundary.
pub(in crate::commands) fn ingest_github_job_logs_once(
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
) -> Result<GithubJobLogIngestReceipt, CliError> {
    let store = JobStore::open_default()?;
    ingest_github_job_logs_once_in_store(&store, local_job_id, cancellation)
}

pub(in crate::commands) fn ingest_github_job_logs_once_in_store(
    store: &JobStore,
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
) -> Result<GithubJobLogIngestReceipt, CliError> {
    let preflight = latest_boxed(store, local_job_id)?;
    if let Some(receipt) = no_provider_log_poll_under_lease(store, local_job_id, &preflight)? {
        return Ok(receipt);
    }

    let prepared =
        PreparedGithubJobSession::prepare_operation(store, local_job_id, JobOperationKind::Logs)?;
    fetch_and_persist_github_job_logs(store, local_job_id, cancellation, prepared)
}

fn fetch_and_persist_github_job_logs(
    store: &JobStore,
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
    mut prepared: PreparedGithubJobSession,
) -> Result<GithubJobLogIngestReceipt, CliError> {
    prepared.require_operation_kind(JobOperationKind::Logs)?;
    prepared.verify_exact_local_record()?;
    let provider_job_id = prepared
        .record
        .provider_job_id
        .as_deref()
        .ok_or_else(|| {
            session_error(
                "provider_job_identity_missing",
                "the durable job has no exact provider job identifier",
                "Preserve the job and recover its complete provider checkpoint.",
            )
        })?
        .to_owned();

    if let Some(identity) = prepared
        .provider
        .restored_terminal_job_log_identity(&provider_job_id)
        .map_err(|error| {
            provider_failure(
                &error,
                "provider_log_identity_invalid",
                "the durable GitHub run could not bind its exact log identity",
            )
        })?
        && exact_worker_log_completion_is_durable(store, local_job_id, &identity)?
    {
        return Ok(GithubJobLogIngestReceipt {
            local_job_id: local_job_id.clone(),
            revision: prepared.record.revision,
            provider_fetch_performed: false,
            appended: 0,
            already_present: 0,
        });
    }

    let Some(poll) = prepared
        .provider
        .fetch_restored_job_logs(&provider_job_id, cancellation)
        .map_err(|error| {
            provider_failure(
                &error,
                "provider_log_fetch_failed",
                "the exact GitHub run-attempt logs could not be fetched safely",
            )
        })?
    else {
        prepared.record = latest_boxed(store, local_job_id)?;
        prepared.verify_local_boundaries()?;
        return Ok(GithubJobLogIngestReceipt {
            local_job_id: local_job_id.clone(),
            revision: prepared.record.revision,
            provider_fetch_performed: false,
            appended: 0,
            already_present: 0,
        });
    };

    prepared.record = latest_boxed(store, local_job_id)?;
    prepared.verify_local_boundaries()?;
    let identity = prepared
        .provider
        .restored_terminal_job_log_identity(&provider_job_id)
        .map_err(|error| {
            provider_failure(
                &error,
                "provider_log_identity_invalid",
                "the fetched GitHub logs lost their exact terminal run identity",
            )
        })?
        .ok_or_else(|| {
            session_error(
                "provider_log_identity_changed",
                "the fetched GitHub logs no longer bind a terminal run attempt",
                "Preserve the durable job and retry only after exact run reconciliation.",
            )
        })?;
    validate_poll_completion(&poll, &identity)?;
    let (appended, already_present) =
        append_worker_log_poll(store, local_job_id, prepared.record.updated_at_ms, &poll)?;
    if !exact_worker_log_completion_is_durable(store, local_job_id, &identity)? {
        return Err(session_error(
            "provider_log_completion_not_durable",
            "the exact Worker log completion marker was not durably observable",
            "Preserve the durable event prefix and retry the bounded log poll.",
        ));
    }
    prepared.record = latest_boxed(store, local_job_id)?;
    prepared.verify_local_boundaries()?;
    Ok(GithubJobLogIngestReceipt {
        local_job_id: local_job_id.clone(),
        revision: prepared.record.revision,
        provider_fetch_performed: true,
        appended,
        already_present,
    })
}

fn no_provider_log_poll_under_lease(
    store: &JobStore,
    local_job_id: &LocalJobId,
    preflight: &StoredJobV1,
) -> Result<Option<GithubJobLogIngestReceipt>, CliError> {
    if preflight.provider_resume.is_some() && preflight.provider_job_id.is_some() {
        return Ok(None);
    }
    let operation_lease =
        store.try_acquire_operation_lease(local_job_id, JobOperationKind::Logs)?;
    let record = store.latest(local_job_id)?;
    if &record != preflight {
        return Err(session_error(
            "job_revision_changed",
            "the durable job changed while its log-ingestion lease was acquired",
            "Retry the bounded log poll from the latest immutable job revision.",
        ));
    }
    if operation_lease.local_job_id() != local_job_id
        || operation_lease.kind() != JobOperationKind::Logs
    {
        return Err(session_error(
            "job_operation_lease_mismatch",
            "the log-ingestion preflight acquired the wrong operation lease",
            "Stop and retry under the exact job Logs lease.",
        ));
    }
    Ok(Some(GithubJobLogIngestReceipt {
        local_job_id: local_job_id.clone(),
        revision: record.revision,
        provider_fetch_performed: false,
        appended: 0,
        already_present: 0,
    }))
}

fn validate_poll_completion(
    poll: &GithubJobLogPoll,
    identity: &GithubDurableRunAttemptLogIdentity,
) -> Result<(), CliError> {
    let marker = poll.completion_marker();
    identity
        .validate_durable_completion_marker(
            poll.events()
                .iter()
                .map(|event| (event.source_sequence(), event.source_event_sha256())),
            marker.occurred_at_ms(),
            marker.source_sequence(),
            marker.source_event_sha256(),
            marker.message(),
        )
        .map_err(|_| {
            session_error(
                "provider_log_completion_invalid",
                "the fetched Worker log completion marker did not bind the exact durable run",
                "Reject the poll and preserve the existing durable journal.",
            )
        })
}

fn append_worker_log_poll(
    store: &JobStore,
    local_job_id: &LocalJobId,
    updated_at_ms: u64,
    poll: &GithubJobLogPoll,
) -> Result<(usize, usize), CliError> {
    let line_batches = poll.event_batches().map(|batch| {
        batch
            .iter()
            .map(|event| ManagedJobEventInputV1 {
                source: ManagedEventSource::Worker,
                source_sequence: Some(event.source_sequence()),
                source_event_sha256: Some(event.source_event_sha256().to_owned()),
                occurred_at_ms: event.occurred_at_ms(),
                phase: Some(WORKER_LOG_PHASE.to_owned()),
                level: ManagedEventLevel::Info,
                code: WORKER_LOG_LINE_CODE.to_owned(),
                message: Some(event.message().to_owned()),
            })
            .collect::<Vec<_>>()
    });
    let marker = poll.completion_marker();
    let marker_input = ManagedJobEventInputV1 {
        source: ManagedEventSource::Worker,
        source_sequence: Some(marker.source_sequence()),
        source_event_sha256: Some(marker.source_event_sha256().to_owned()),
        occurred_at_ms: marker.occurred_at_ms(),
        phase: Some(WORKER_LOG_PHASE.to_owned()),
        level: ManagedEventLevel::Info,
        code: WORKER_LOGS_COMPLETE_CODE.to_owned(),
        message: Some(marker.message().to_owned()),
    };
    append_worker_log_inputs(
        store,
        local_job_id,
        updated_at_ms,
        line_batches,
        &marker_input,
    )
}

fn append_worker_log_inputs(
    store: &JobStore,
    local_job_id: &LocalJobId,
    updated_at_ms: u64,
    line_batches: impl IntoIterator<Item = Vec<ManagedJobEventInputV1>>,
    marker_input: &ManagedJobEventInputV1,
) -> Result<(usize, usize), CliError> {
    let mut appended = 0_usize;
    let mut already_present = 0_usize;
    for inputs in line_batches {
        let receipt = store.append_managed_events(local_job_id, updated_at_ms, &inputs)?;
        verify_managed_append_receipt(local_job_id, &inputs, &receipt)?;
        appended = appended.checked_add(receipt.appended).ok_or_else(|| {
            session_error(
                "provider_log_append_overflow",
                "the durable Worker log append count overflowed",
                "Preserve the journal and inspect its bounded event count.",
            )
        })?;
        already_present = already_present
            .checked_add(receipt.already_present)
            .ok_or_else(|| {
                session_error(
                    "provider_log_append_overflow",
                    "the durable Worker log replay count overflowed",
                    "Preserve the journal and inspect its bounded event count.",
                )
            })?;
    }

    let receipt = store.append_managed_events(
        local_job_id,
        updated_at_ms,
        std::slice::from_ref(marker_input),
    )?;
    verify_managed_append_receipt(local_job_id, std::slice::from_ref(marker_input), &receipt)?;
    appended = appended.checked_add(receipt.appended).ok_or_else(|| {
        session_error(
            "provider_log_append_overflow",
            "the durable Worker log append count overflowed",
            "Preserve the journal and inspect its bounded event count.",
        )
    })?;
    already_present = already_present
        .checked_add(receipt.already_present)
        .ok_or_else(|| {
            session_error(
                "provider_log_append_overflow",
                "the durable Worker log replay count overflowed",
                "Preserve the journal and inspect its bounded event count.",
            )
        })?;
    Ok((appended, already_present))
}

fn verify_managed_append_receipt(
    local_job_id: &LocalJobId,
    inputs: &[ManagedJobEventInputV1],
    receipt: &ManagedEventAppendReceipt,
) -> Result<(), CliError> {
    let exact = &receipt.local_job_id == local_job_id
        && receipt.assigned.len() == inputs.len()
        && receipt.appended.saturating_add(receipt.already_present) == inputs.len()
        && receipt
            .assigned
            .iter()
            .zip(inputs)
            .all(|(assigned, input)| {
                assigned.source == input.source
                    && assigned.source_sequence == input.source_sequence
                    && assigned.source_event_sha256 == input.source_event_sha256
                    && assigned.occurred_at_ms == input.occurred_at_ms
                    && assigned.phase == input.phase
                    && assigned.level == input.level
                    && assigned.code == input.code
                    && assigned.message == input.message
            });
    if exact {
        return Ok(());
    }
    Err(session_error(
        "provider_log_append_receipt_mismatch",
        "the durable Worker log append receipt differed from its sanitized input",
        "Preserve the journal and stop before writing a completion marker.",
    ))
}

fn exact_worker_log_completion_is_durable(
    store: &JobStore,
    local_job_id: &LocalJobId,
    identity: &GithubDurableRunAttemptLogIdentity,
) -> Result<bool, CliError> {
    let expected_sequence = identity.expected_completion_source_sequence();
    let expected_attempt = expected_sequence >> 32;
    let mut cursor = 0_u64;
    let mut worker_events = Vec::new();
    let mut marker = None;
    loop {
        let page = store.read_managed_events(local_job_id, cursor, MAX_MANAGED_EVENT_PAGE)?;
        for event in &page.events {
            if event.source != ManagedEventSource::Worker {
                continue;
            }
            let Some(source_sequence) = event.source_sequence else {
                if matches!(
                    event.code.as_str(),
                    WORKER_LOG_LINE_CODE | WORKER_LOGS_COMPLETE_CODE
                ) {
                    return Err(invalid_durable_log_marker());
                }
                continue;
            };
            if source_sequence >> 32 != expected_attempt {
                continue;
            }
            let Some(source_event_sha256) = event.source_event_sha256.as_deref() else {
                return Err(invalid_durable_log_marker());
            };
            if source_sequence == expected_sequence {
                let Some(message) = event.message.as_deref() else {
                    return Err(invalid_durable_log_marker());
                };
                if marker.is_some()
                    || event.code != WORKER_LOGS_COMPLETE_CODE
                    || event.phase.as_deref() != Some(WORKER_LOG_PHASE)
                    || event.level != ManagedEventLevel::Info
                    || event.occurred_at_ms == 0
                {
                    return Err(invalid_durable_log_marker());
                }
                marker = Some((
                    event.occurred_at_ms,
                    source_event_sha256.to_owned(),
                    message.to_owned(),
                ));
                continue;
            }
            if marker.is_some()
                || event.code != WORKER_LOG_LINE_CODE
                || event.phase.as_deref() != Some(WORKER_LOG_PHASE)
                || event.level != ManagedEventLevel::Info
                || event.occurred_at_ms == 0
                || event.message.is_none()
            {
                return Err(invalid_durable_log_marker());
            }
            worker_events.push((source_sequence, source_event_sha256.to_owned()));
        }
        cursor = page.next_after_sequence;
        if !page.has_more {
            break;
        }
    }
    let Some((occurred_at_ms, source_event_sha256, message)) = marker else {
        return Ok(false);
    };
    identity
        .validate_durable_completion_marker(
            worker_events
                .iter()
                .map(|(sequence, digest)| (*sequence, digest.as_str())),
            occurred_at_ms,
            expected_sequence,
            &source_event_sha256,
            &message,
        )
        .map_err(|_| invalid_durable_log_marker())?;
    Ok(true)
}

fn invalid_durable_log_marker() -> CliError {
    session_error(
        "provider_log_completion_invalid",
        "the durable Worker log completion marker was forged or inconsistent",
        "Preserve the journal and inspect the exact run-attempt identity before refetching.",
    )
}

impl<'lease> GithubPruneSnapshotSession<'lease> {
    /// Restore one exact snapshot job without reacquiring or releasing its retained Prune lease.
    pub(in crate::commands) fn prepare(
        store: &JobStore,
        local_job_id: &LocalJobId,
        operation_lease: &'lease JobOperationLease,
    ) -> Result<Self, CliError> {
        let record = store.latest_under_operation_lease(
            local_job_id,
            JobOperationKind::Prune,
            operation_lease,
        )?;
        let root = Utf8PathBuf::from(record.project.canonical_root.clone());
        let project = ProjectFilesystemBinding::capture(&root)?;
        verify_project_record(&project, &record)?;
        let (stored, config_lock) = load_config_for_build(&root)?;
        let config_path = root.join(CONFIG_RELATIVE_PATH);
        let (config_identity, config_bytes) = read_private_config_snapshot(&root, &config_path)?;
        if decode_stored_config(&config_bytes)? != stored {
            return Err(session_error(
                "provider_config_changed",
                "the GitHub provider config changed while its prune lock was acquired",
                "Retry only after the exact private provider config is stable.",
            ));
        }
        let (git, _) = git_context_from_stored(&root, &stored, &Reporter::new(false, true, false))?;
        let resume = record.provider_resume.clone().ok_or_else(|| {
            session_error(
                "provider_resume_unavailable",
                "the snapshot prune job has no complete durable provider checkpoint",
                "Preserve the job and recover its exact checkpoint before pruning.",
            )
        })?;
        if resume.git_snapshot.is_none()
            || record.provider_job_id.as_deref() != Some(record.operation_id.as_str())
            || resume.job_id != record.operation_id
        {
            return Err(session_error(
                "provider_job_identity_mismatch",
                "the snapshot prune job differs from its exact provider checkpoint",
                "Preserve the job and inspect its immutable revisions before pruning.",
            ));
        }
        let expected = expected_provider_identity(&record);
        let provider = build_provider(&root, &git.root, &stored)?.with_checkpoint_sink(
            GithubJobStoreCheckpointSink::new(store.clone(), local_job_id.clone()),
        );
        provider
            .restore_job_resumes_offline(vec![resume], &expected)
            .map_err(|error| {
                provider_failure(
                    &error,
                    "provider_resume_invalid",
                    "the snapshot prune checkpoint could not be restored locally",
                )
            })?;
        let session = Self {
            store: store.clone(),
            record,
            provider: Box::new(provider),
            git,
            project,
            config_identity,
            config_bytes,
            _config_lock: config_lock,
            operation_lease,
        };
        session.verify_exact_boundaries()?;
        Ok(session)
    }

    /// Durably checkpoint intent, release the exact keepalive, and prove released absence.
    pub(in crate::commands) fn release_git_snapshot_keepalive_for_prune(
        mut self,
        authorization: &GithubGitSnapshotKeepaliveReleaseAuthorizationV1,
        cancellation: &CancellationToken,
    ) -> Result<GithubPruneSnapshotReleaseReceipt, CliError> {
        self.verify_exact_boundaries()?;
        if authorization.job_id() != self.record.operation_id {
            return Err(session_error(
                "snapshot_prune_authorization_mismatch",
                "the snapshot release authority names another provider operation",
                "Stop and recover the durable complete-lineage prune authorization.",
            ));
        }
        self.provider
            .release_git_snapshot_keepalive_for_prune(authorization, cancellation)
            .map_err(|error| {
                provider_failure(
                    &error,
                    "snapshot_keepalive_release_failed",
                    "the exact Git snapshot keepalive could not be released",
                )
            })?;
        self.record = self.store.latest_under_operation_lease(
            &self.record.local_job_id,
            JobOperationKind::Prune,
            self.operation_lease,
        )?;
        let snapshot = self
            .record
            .provider_resume
            .as_ref()
            .and_then(|resume| resume.git_snapshot.as_ref())
            .ok_or_else(|| {
                session_error(
                    "snapshot_release_checkpoint_missing",
                    "the released snapshot lost its durable checkpoint",
                    "Preserve the job store and inspect the exact provider checkpoint.",
                )
            })?;
        if snapshot.phase != GithubGitSnapshotPhaseV1::KeepaliveReleased
            || snapshot.keepalive_release_authorization_sha256.as_deref()
                != Some(authorization.complete_lineage_authorization_sha256())
        {
            return Err(session_error(
                "snapshot_release_checkpoint_missing",
                "the provider returned without durable exact keepalive-release proof",
                "Preserve the job store and resume the same prune authorization.",
            ));
        }
        self.verify_exact_boundaries()?;
        Ok(GithubPruneSnapshotReleaseReceipt {
            local_job_id: self.record.local_job_id.clone(),
            revision: self.record.revision,
            complete_lineage_authorization_sha256: authorization
                .complete_lineage_authorization_sha256()
                .to_owned(),
        })
    }

    fn verify_exact_boundaries(&self) -> Result<(), CliError> {
        let latest = self.store.latest_under_operation_lease(
            &self.record.local_job_id,
            JobOperationKind::Prune,
            self.operation_lease,
        )?;
        if latest != self.record {
            return Err(session_error(
                "job_revision_changed",
                "the snapshot prune job changed outside its retained Prune lease",
                "Stop and replan from the latest durable checkpoint.",
            ));
        }
        self.project.verify()?;
        let observed_revision = checked_caller_git_output(
            self.git.caller_git.head_revision(),
            "revalidate the caller Git revision",
        )?;
        verify_captured_git_revision(&self.git.revision, &observed_revision)?;
        verify_project_record(&self.project, &self.record)?;
        ensure_config_snapshot_unchanged(
            self.project.root(),
            &self.project.root().join(CONFIG_RELATIVE_PATH),
            &self.config_identity,
            &self.config_bytes,
        )
    }
}

impl PreparedGithubJobSession {
    /// Release one snapshot keepalive through the prune-only borrowed-lease typestate.
    pub(in crate::commands) fn release_snapshot_keepalive_for_prune(
        store: &JobStore,
        local_job_id: &LocalJobId,
        operation_lease: &JobOperationLease,
        authorization: &GithubGitSnapshotKeepaliveReleaseAuthorizationV1,
        cancellation: &CancellationToken,
    ) -> Result<(), CliError> {
        GithubPruneSnapshotSession::prepare(store, local_job_id, operation_lease)?
            .release_git_snapshot_keepalive_for_prune(authorization, cancellation)
            .map(|_| ())
    }

    /// Reconstruct one exact cancellation session using only local durable state.
    pub(in crate::commands) fn prepare_cancel(
        store: &JobStore,
        local_job_id: &LocalJobId,
    ) -> Result<Self, CliError> {
        Self::prepare_operation(store, local_job_id, JobOperationKind::Cancel)
    }

    fn prepare_operation(
        store: &JobStore,
        local_job_id: &LocalJobId,
        operation_kind: JobOperationKind,
    ) -> Result<Self, CliError> {
        let preflight = Self::acquire_operation_preflight(store, local_job_id, operation_kind)?;
        Self::restore_operation(store, local_job_id, operation_kind, preflight)
    }

    #[inline(never)]
    fn acquire_operation_preflight(
        store: &JobStore,
        local_job_id: &LocalJobId,
        operation_kind: JobOperationKind,
    ) -> Result<GithubOperationPreflight, CliError> {
        let before_lease = latest_boxed(store, local_job_id)?;
        let operation_lease = store.try_acquire_operation_lease(local_job_id, operation_kind)?;
        let record = latest_boxed(store, local_job_id)?;
        if record != before_lease {
            return Err(session_error(
                "job_revision_changed",
                "the durable job changed while its cancellation lease was acquired",
                "Retry from the latest immutable job revision.",
            ));
        }
        let root = Utf8PathBuf::from(record.project.canonical_root.clone());
        let project = ProjectFilesystemBinding::capture(&root)?;
        verify_project_record(&project, &record)?;

        Ok(GithubOperationPreflight {
            record,
            root,
            project,
            operation_lease,
        })
    }

    fn restore_operation(
        store: &JobStore,
        local_job_id: &LocalJobId,
        operation_kind: JobOperationKind,
        preflight: GithubOperationPreflight,
    ) -> Result<Self, CliError> {
        let GithubOperationPreflight {
            record,
            root,
            project,
            operation_lease,
        } = preflight;

        let (stored, config_lock) = load_config_for_build(&root)?;
        let config_path = root.join(CONFIG_RELATIVE_PATH);
        let (config_identity, config_bytes) = read_private_config_snapshot(&root, &config_path)?;
        let decoded = decode_stored_config(&config_bytes)?;
        if decoded != stored {
            return Err(session_error(
                "provider_config_changed",
                "the GitHub provider config changed while its lock was acquired",
                "Retry only after the exact private provider config is stable.",
            ));
        }
        let (git, _) = git_context_from_stored(&root, &stored, &Reporter::new(false, true, false))?;

        let resume = record.provider_resume.clone().ok_or_else(|| {
            session_error(
                "provider_resume_unavailable",
                "the durable job has no complete GitHub provider checkpoint",
                "Preserve the job and recover its exact provider checkpoint before cancellation.",
            )
        })?;
        if record.provider_job_id.as_deref() != Some(resume.job_id.as_str()) {
            return Err(session_error(
                "provider_job_identity_mismatch",
                "the durable provider job differs from its resume checkpoint",
                "Preserve the job and inspect its immutable revisions before cancellation.",
            ));
        }
        let expected = expected_provider_identity(&record);
        let provider = build_provider(&root, &git.root, &stored)?.with_checkpoint_sink(
            GithubJobStoreCheckpointSink::new(store.clone(), local_job_id.clone()),
        );
        provider
            .restore_job_resumes_offline(vec![resume], &expected)
            .map_err(|error| {
                provider_failure(
                    &error,
                    "provider_resume_invalid",
                    "the durable GitHub provider checkpoint could not be restored locally",
                )
            })?;

        project.verify()?;
        ensure_config_snapshot_unchanged(&root, &config_path, &config_identity, &config_bytes)?;
        if *latest_boxed(store, local_job_id)? != *record {
            return Err(session_error(
                "job_revision_changed",
                "the durable job changed during local provider reconstruction",
                "Retry from the latest immutable job revision.",
            ));
        }
        Ok(Self {
            store: store.clone(),
            local_job_id: local_job_id.clone(),
            record,
            provider: Box::new(provider),
            git,
            project,
            config_identity,
            config_bytes,
            _config_lock: config_lock,
            operation_lease,
            operation_kind,
        })
    }

    /// Persist controller cancellation intent without making a GitHub request.
    pub(in crate::commands) fn persist_cancellation_requested(
        mut self,
    ) -> Result<DurableGithubCancellationSession, CliError> {
        self.require_operation_kind(JobOperationKind::Cancel)?;
        self.verify_exact_local_record()?;
        let terminal = durable_job_is_terminal(&self.record);
        let mut intent_persisted_by_this_call = false;
        if !terminal && self.record.cancellation_status == StoredCancellationStatus::NotRequested {
            let expected = self.record.as_ref().clone();
            update_stored_job(&self.store, &self.local_job_id, |previous, next| {
                if previous != &expected {
                    return Err(JobStoreError::InvalidRecord {
                        reason: "cancellation intent raced a different durable job revision",
                    });
                }
                next.state = StoredJobState::CancellationRequested;
                next.cancellation_status = StoredCancellationStatus::Requested;
                Ok(())
            })?;
            self.record = latest_boxed(&self.store, &self.local_job_id)?;
            intent_persisted_by_this_call = true;
        } else if !terminal
            && matches!(
                self.record.cancellation_status,
                StoredCancellationStatus::Failed | StoredCancellationStatus::Confirmed
            )
        {
            return Err(session_error(
                "cancellation_not_restartable",
                "the durable cancellation is already terminal and cannot be dispatched again",
                "Inspect the exact terminal outcome; do not create another cancellation request.",
            ));
        }
        let resume = self.record.provider_resume.as_ref().ok_or_else(|| {
            session_error(
                "provider_resume_unavailable",
                "the durable job lost its GitHub provider checkpoint",
                "Preserve the job and inspect its latest immutable revision.",
            )
        })?;
        let action = cancellation_action(
            terminal,
            self.record.cancellation_status,
            resume.cancellation_requested,
            intent_persisted_by_this_call,
        );
        self.verify_local_boundaries()?;
        Ok(DurableGithubCancellationSession {
            prepared: self,
            action,
            intent_written_by_this_call: intent_persisted_by_this_call,
        })
    }

    fn verify_exact_local_record(&self) -> Result<(), CliError> {
        self.verify_local_boundaries()?;
        if *latest_boxed(&self.store, &self.local_job_id)? != *self.record {
            return Err(session_error(
                "job_revision_changed",
                "the durable job changed after session preparation",
                "Retry from the latest immutable job revision.",
            ));
        }
        Ok(())
    }

    fn require_operation_kind(&self, expected: JobOperationKind) -> Result<(), CliError> {
        if self.operation_kind != expected {
            return Err(session_error(
                "job_operation_lease_mismatch",
                "the GitHub job session has the wrong operation lease",
                "Stop and reconstruct the session under the required job operation.",
            ));
        }
        Ok(())
    }

    fn verify_local_boundaries(&self) -> Result<(), CliError> {
        if self.operation_lease.local_job_id() != &self.local_job_id
            || self.operation_lease.kind() != self.operation_kind
        {
            return Err(session_error(
                "job_operation_lease_mismatch",
                "the GitHub job session lost its exact operation lease",
                "Stop and reconstruct the session under the correct job lease.",
            ));
        }
        self.project.verify()?;
        let observed_revision = checked_caller_git_output(
            self.git.caller_git.head_revision(),
            "revalidate the caller Git revision",
        )?;
        verify_captured_git_revision(&self.git.revision, &observed_revision)?;
        verify_project_record(&self.project, &self.record)?;
        ensure_config_snapshot_unchanged(
            self.project.root(),
            &self.project.root().join(CONFIG_RELATIVE_PATH),
            &self.config_identity,
            &self.config_bytes,
        )
    }
}

fn verify_captured_git_revision(captured: &str, observed: &[u8]) -> Result<(), CliError> {
    let observed = utf8_line(observed, "Git revision")?;
    if observed.len() != 40
        || !observed
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || observed != captured
    {
        return Err(session_error(
            "caller_repository_revision_changed",
            "the caller Git revision changed during the bounded job operation",
            "Retry from a stable checkout; the historical durable job source remains unchanged.",
        ));
    }
    Ok(())
}

impl DurableGithubCancellationSession {
    /// Perform exact live identity/run GET revalidation after durable intent exists.
    pub(in crate::commands) fn bind_live(
        mut self,
        cancellation: &CancellationToken,
    ) -> Result<BoundGithubJobSession, CliError> {
        self.prepared.verify_exact_local_record()?;
        if let Err(error) = self
            .provider()
            .revalidate_restored_job_live(self.provider_job_id()?, cancellation)
        {
            let _ =
                persist_cancellation_uncertain(&self.prepared.store, &self.prepared.local_job_id);
            return Err(provider_failure(
                &error,
                "provider_live_revalidation_failed",
                "the exact GitHub job could not be revalidated after durable cancellation intent",
            ));
        }
        self.refresh_record()?;
        if durable_job_is_terminal(&self.prepared.record)
            || self
                .prepared
                .record
                .provider_resume
                .as_ref()
                .is_some_and(|resume| resume.state.is_build_terminal())
        {
            self.action = CancellationAction::TerminalNoop;
        }
        self.prepared.verify_local_boundaries()?;
        Ok(BoundGithubJobSession { durable: self })
    }

    fn provider(&self) -> &GithubProvider {
        &self.prepared.provider
    }

    fn provider_job_id(&self) -> Result<&str, CliError> {
        self.prepared
            .record
            .provider_job_id
            .as_deref()
            .ok_or_else(|| {
                session_error(
                    "provider_job_identity_missing",
                    "the durable job has no exact provider job identifier",
                    "Preserve the job and recover its complete provider checkpoint.",
                )
            })
    }

    fn refresh_record(&mut self) -> Result<(), CliError> {
        self.prepared.record = latest_boxed(&self.prepared.store, &self.prepared.local_job_id)?;
        verify_project_record(&self.prepared.project, &self.prepared.record)
    }
}

impl BoundGithubJobSession {
    /// Execute one cancellation dispatch or restart-safe GET-only reconciliation through cleanup.
    #[allow(
        clippy::too_many_lines,
        reason = "dispatch gating, terminal reconciliation, and durable cleanup form one cancellation boundary"
    )]
    pub(in crate::commands) fn cancel_or_reconcile_once(
        mut self,
        reason: &str,
        cancellation: CancellationToken,
    ) -> Result<GithubCancellationSessionReceipt, CliError> {
        self.durable.prepared.verify_exact_local_record()?;
        let action = self.durable.action;
        let job_id = self.durable.provider_job_id()?.to_owned();
        match action {
            CancellationAction::TerminalNoop => {}
            CancellationAction::DispatchOnce => {
                super::provider_call(
                    self.durable.provider().cancel(
                        CancellationRequest {
                            job_id: job_id.clone(),
                            reason: reason.to_owned(),
                        },
                        cancellation.clone(),
                    ),
                    "remote_cancel_failed",
                    "the exact GitHub job could not be cancelled",
                )
                .inspect_err(|_| {
                    self.persist_uncertain();
                })?;
            }
            CancellationAction::GetOnly => {
                let resume = self
                    .durable
                    .prepared
                    .record
                    .provider_resume
                    .as_ref()
                    .ok_or_else(|| {
                        session_error(
                            "provider_resume_unavailable",
                            "the durable job lost its GitHub provider checkpoint",
                            "Preserve the job and inspect its latest immutable revision.",
                        )
                    })?;
                if resume.publication_uncertain {
                    self.durable
                        .provider()
                        .reconcile_restored_job_get_only(&job_id, &cancellation)
                        .inspect_err(|_| self.persist_uncertain())
                        .map_err(|error| {
                            provider_failure(
                                &error,
                                "provider_reconciliation_failed",
                                "the exact GitHub publication could not be reconciled with reads only",
                            )
                        })?;
                }
            }
        }
        self.wait_for_terminal(&job_id, &cancellation)?;
        self.durable.refresh_record()?;
        self.durable.prepared.verify_local_boundaries()?;
        let terminal_outcome = self
            .durable
            .prepared
            .record
            .terminal_outcome
            .ok_or_else(|| {
                session_error(
                    "cancellation_terminal_checkpoint_missing",
                    "the exact GitHub job reached no durable terminal outcome",
                    "Preserve the job and reconcile its provider checkpoint before retrying.",
                )
            })?;
        if terminal_outcome != StoredBuildOutcome::Cancelled {
            persist_non_cancel_terminal_race(
                &self.durable.prepared.store,
                &self.durable.prepared.local_job_id,
            )?;
            self.durable.refresh_record()?;
        }
        let provider_state = self
            .durable
            .prepared
            .record
            .provider_resume
            .as_ref()
            .map(|resume| resume.state)
            .ok_or_else(|| {
                session_error(
                    "provider_resume_unavailable",
                    "the terminal job lost its exact GitHub provider checkpoint",
                    "Preserve the job and inspect its immutable revisions before cleanup.",
                )
            })?;
        let provider_cancel_posts = u8::from(
            action == CancellationAction::DispatchOnce
                && self
                    .durable
                    .prepared
                    .record
                    .provider_resume
                    .as_ref()
                    .is_some_and(|resume| resume.cancellation_dispatched),
        );
        cleanup_job_durably(
            self.durable.provider(),
            &self.durable.prepared.store,
            &self.durable.prepared.local_job_id,
            &job_id,
            &self.durable.prepared.project,
        )?;
        self.durable.refresh_record()?;
        self.durable.prepared.verify_local_boundaries()?;
        if self.durable.prepared.record.cleanup_status != StoredCleanupStatus::Confirmed {
            return Err(session_error(
                "cleanup_checkpoint_missing",
                "the terminal GitHub cancellation lacks exact durable cleanup confirmation",
                "Preserve the job and reconcile its provider-owned temporary ref.",
            ));
        }
        let record = &self.durable.prepared.record;
        let receipt = GithubCancellationSessionReceipt {
            local_job_id: record.local_job_id.clone(),
            revision: record.revision,
            state: record.state,
            cancellation_status: record.cancellation_status,
            terminal_outcome,
            cleanup_status: record.cleanup_status,
            provider_state,
            provider_cancel_posts,
            get_only_reconciliation: action == CancellationAction::GetOnly,
            intent_written_by_this_call: self.durable.intent_written_by_this_call,
        };
        drop(cancellation);
        Ok(receipt)
    }

    fn wait_for_terminal(
        &mut self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), CliError> {
        let deadline = Instant::now() + CANCELLATION_TIMEOUT;
        loop {
            self.durable.refresh_record()?;
            if durable_job_is_terminal(&self.durable.prepared.record) {
                return Ok(());
            }
            if rustferry_core::process_control::interrupt_requested() || Instant::now() >= deadline
            {
                self.persist_uncertain();
                return Err(session_error(
                    "cancellation_reconciliation_incomplete",
                    "the GitHub cancellation did not reach an exact terminal checkpoint in time",
                    "Preserve the job and rerun cancellation to continue GET-only reconciliation.",
                ));
            }
            self.durable.prepared.verify_local_boundaries()?;
            self.durable
                .provider()
                .refresh_restored_job_get_only(job_id, cancellation)
                .inspect_err(|_| self.persist_uncertain())
                .map_err(|error| {
                    provider_failure(
                        &error,
                        "provider_cancel_reconciliation_failed",
                        "the exact GitHub cancellation could not be reconciled with reads only",
                    )
                })?;
            self.durable.refresh_record()?;
            if durable_job_is_terminal(&self.durable.prepared.record) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            sleep_interruptibly(POLL_INTERVAL.min(remaining));
        }
    }

    fn persist_uncertain(&self) {
        let _ = persist_cancellation_uncertain(
            &self.durable.prepared.store,
            &self.durable.prepared.local_job_id,
        );
    }
}

impl PreparedGithubRetrySession {
    /// Reconstruct one exact retry parent using only local durable state.
    pub(in crate::commands) fn prepare_retry(
        store: &JobStore,
        local_job_id: &LocalJobId,
    ) -> Result<Box<Self>, CliError> {
        Ok(Box::new(Self {
            prepared: PreparedGithubJobSession::prepare_operation(
                store,
                local_job_id,
                JobOperationKind::Retry,
            )?,
        }))
    }

    /// Validate retry eligibility from the exact parent revision protected by the Retry lease.
    ///
    /// This boundary is local-only. A rejected parent performs no GitHub request.
    pub(in crate::commands) fn validate_leased_parent(
        self,
        validate: impl FnOnce(&StoredJobV1) -> Result<(), CliError>,
    ) -> Result<Self, CliError> {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        validate(&self.prepared.record)?;
        self.prepared.verify_exact_local_record()?;
        Ok(self)
    }

    /// Revalidate the exact terminal parent before any retry child is allocated.
    pub(in crate::commands) fn bind_live_parent(
        mut self,
        cancellation: &CancellationToken,
    ) -> Result<BoundGithubRetrySession, CliError> {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        let provider_job_id = self
            .prepared
            .record
            .provider_job_id
            .as_deref()
            .ok_or_else(|| {
                session_error(
                    "provider_job_identity_missing",
                    "the retry parent has no exact provider job identifier",
                    "Preserve the parent and recover its complete provider checkpoint.",
                )
            })?;
        self.prepared
            .provider
            .revalidate_restored_job_live(provider_job_id, cancellation)
            .map_err(|error| {
                provider_failure(
                    &error,
                    "retry_parent_revalidation_failed",
                    "the exact GitHub retry parent could not be revalidated",
                )
            })?;
        self.prepared.record = latest_boxed(&self.prepared.store, &self.prepared.local_job_id)?;
        self.prepared.verify_local_boundaries()?;
        if !durable_job_is_terminal(&self.prepared.record) {
            return Err(session_error(
                "retry_parent_not_terminal",
                "the exact GitHub retry parent is not durably terminal",
                "Wait for an exact terminal outcome before creating a retry child.",
            ));
        }
        Ok(BoundGithubRetrySession {
            prepared: self.prepared,
        })
    }
}

impl BoundGithubRetrySession {
    /// Re-run the full retry predicate after the provider's live parent refresh.
    pub(in crate::commands) fn validate_live_parent(
        self,
        validate: impl FnOnce(&StoredJobV1) -> Result<(), CliError>,
    ) -> Result<Self, CliError> {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        validate(&self.prepared.record)?;
        self.prepared.verify_exact_local_record()?;
        Ok(self)
    }

    /// Resume the latest exact in-flight retry child or atomically create the supplied child.
    pub(in crate::commands) fn create_or_resume_child<F>(
        mut self,
        options: &RetryLineageOptionsV1,
        make_child: F,
    ) -> Result<GithubRetryChildSession, CliError>
    where
        F: FnOnce(&StoredJobV1) -> Result<StoredJobV1, CliError>,
    {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        let parent = self.prepared.record.as_ref().clone();
        let existing = parent
            .retry_lineage
            .child_job_ids
            .last()
            .map(|local_job_id| self.prepared.store.latest(local_job_id))
            .transpose()?;
        let (child, child_lease, disposition) = if let Some(existing) = existing {
            let binding = self
                .prepared
                .store
                .retry_lineage_binding(&parent.local_job_id, &existing.local_job_id)?;
            verify_existing_retry_child(&parent, &existing, &binding)?;
            let child_lease = self
                .prepared
                .store
                .try_acquire_operation_lease(&existing.local_job_id, JobOperationKind::Build)?;
            let current = self.prepared.store.latest(&existing.local_job_id)?;
            if current != existing {
                return Err(session_error(
                    "job_revision_changed",
                    "the durable retry child changed while its Build lease was acquired",
                    "Retry from the latest immutable child revision.",
                ));
            }
            (current, child_lease, GithubRetryChildDisposition::Existing)
        } else {
            let candidate = make_child(&parent)?;
            let vacancy = match self
                .prepared
                .store
                .try_acquire_vacant_snapshot_operation_lease(&candidate.operation_id)?
            {
                SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
                SnapshotOperationVacancyV1::Owned(_) => {
                    return Err(session_error(
                        "retry_child_operation_owned",
                        "the retry child operation already belongs to another durable job",
                        "Preserve the owning job and allocate a new retry operation.",
                    ));
                }
            };
            let leased = self
                .prepared
                .store
                .create_retry_lineage_with_operation_lease(
                    &self.prepared.local_job_id,
                    &self.prepared.operation_lease,
                    vacancy,
                    &candidate,
                    options,
                )?;
            if self.prepared.store.revision(&candidate.local_job_id, 1)? != candidate {
                return Err(session_error(
                    "retry_child_initial_revision_mismatch",
                    "the durable retry child differs from its exact initial template",
                    "Preserve the retry lineage and inspect its immutable transaction.",
                ));
            }
            (
                self.prepared.store.latest(&candidate.local_job_id)?,
                leased.operation_lease,
                GithubRetryChildDisposition::Created,
            )
        };
        self.prepared.record = latest_boxed(&self.prepared.store, &self.prepared.local_job_id)?;
        if self.prepared.record.retry_lineage.child_job_ids.last() != Some(&child.local_job_id) {
            return Err(session_error(
                "retry_lineage_changed",
                "the retry parent no longer names the exact selected child",
                "Retry from the latest immutable parent lineage.",
            ));
        }
        self.prepared.verify_local_boundaries()?;
        let parent_job_id = self.prepared.record.local_job_id.clone();
        let parent_revision = self.prepared.record.revision;
        bind_retry_child(
            self.prepared,
            parent,
            parent_job_id,
            parent_revision,
            &child,
            child_lease,
            disposition,
            None,
        )
    }

    /// Resume or create one exact retained-archive Git snapshot retry.
    ///
    /// The no-write provider plan precedes lineage publication. The child Build lease is then
    /// retained continuously through replayable staging and the first provider checkpoint.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the fresh operation identity and snapshot planning, durable lineage, stage authority, and child lease form one ownership boundary"
    )]
    pub(in crate::commands) fn create_or_resume_exact_git_snapshot_child<F>(
        mut self,
        parent_policy: RetryParentPolicyV1,
        new_child_local_job_id: LocalJobId,
        new_child_operation_id: String,
        new_child_source_created_at_ms: u64,
        make_child: F,
        cancellation: &CancellationToken,
    ) -> Result<GithubRetryChildSession, CliError>
    where
        F: FnOnce(
            &StoredJobV1,
            LocalJobId,
            IosDeviceBuildRequest,
            u64,
        ) -> Result<StoredJobV1, CliError>,
    {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        let parent = self.prepared.record.as_ref().clone();
        if parent.request.source_mode != SourceMode::GitSnapshot
            || parent.provider_job_id.as_deref() != Some(parent.operation_id.as_str())
        {
            return Err(session_error(
                "retry_snapshot_parent_invalid",
                "the retry parent is not an exact retained Git snapshot provider job",
                "Preserve the parent and inspect its immutable source and provider checkpoints.",
            ));
        }
        let new_child_source_created_at_ms = new_child_source_created_at_ms
            .max(parent.updated_at_ms)
            .max(1);

        let existing = parent
            .retry_lineage
            .child_job_ids
            .last()
            .map(|local_job_id| self.prepared.store.latest(local_job_id))
            .transpose()?;
        let (child, child_lease, binding, disposition, plan) = if let Some(existing) = existing {
            let binding = self
                .prepared
                .store
                .retry_lineage_binding(&parent.local_job_id, &existing.local_job_id)?;
            verify_existing_retry_child(&parent, &existing, &binding)?;
            if !matches!(
                binding.options.source_policy,
                RetrySourcePolicyV1::ExactGitSnapshot { .. }
            ) {
                return Err(session_error(
                    "retry_child_source_policy_mismatch",
                    "the durable retry child was not authorized as an exact Git snapshot retry",
                    "Resume the child through its persisted retry source policy.",
                ));
            }
            let initial = self.prepared.store.revision(&existing.local_job_id, 1)?;
            let child_lease = self
                .prepared
                .store
                .try_acquire_operation_lease(&existing.local_job_id, JobOperationKind::Build)?;
            let current = self.prepared.store.latest(&existing.local_job_id)?;
            if current != existing {
                return Err(session_error(
                    "job_revision_changed",
                    "the durable retry child changed while its Build lease was acquired",
                    "Retry from the latest immutable child revision.",
                ));
            }
            let plan = if current.provider_resume.is_none() {
                let plan = self
                    .prepared
                    .provider
                    .precompute_exact_git_snapshot_retry(
                        &parent.operation_id,
                        &initial.operation_id,
                        initial.created_at_ms,
                        cancellation,
                    )
                    .map_err(|error| {
                        provider_failure(
                            &error,
                            "snapshot_exact_retry_precompute_failed",
                            "the retained Git snapshot retry plan could not be reconstructed",
                        )
                    })?;
                validate_exact_snapshot_retry_plan(&parent, &initial, &binding, &plan)?;
                Some(plan)
            } else {
                None
            };
            (
                current,
                child_lease,
                binding,
                GithubRetryChildDisposition::Existing,
                plan,
            )
        } else {
            let vacancy = match self
                .prepared
                .store
                .try_acquire_vacant_snapshot_operation_lease(&new_child_operation_id)?
            {
                SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
                SnapshotOperationVacancyV1::Owned(_) => {
                    return Err(session_error(
                        "retry_child_operation_owned",
                        "the proposed snapshot retry operation already belongs to another durable job",
                        "Preserve the owner and allocate a new retry operation.",
                    ));
                }
            };
            let plan = self
                .prepared
                .provider
                .precompute_exact_git_snapshot_retry(
                    &parent.operation_id,
                    &new_child_operation_id,
                    new_child_source_created_at_ms,
                    cancellation,
                )
                .map_err(|error| {
                    provider_failure(
                        &error,
                        "snapshot_exact_retry_precompute_failed",
                        "the retained Git snapshot retry plan could not be derived without writes",
                    )
                })?;
            self.prepared.verify_exact_local_record()?;
            let candidate = make_child(
                &parent,
                new_child_local_job_id,
                plan.request.clone(),
                plan.source_created_at_ms,
            )?;
            let options = RetryLineageOptionsV1 {
                parent_policy,
                source_policy: RetrySourcePolicyV1::ExactGitSnapshot {
                    source_archive_sha256: plan.archive.sha256.clone(),
                },
            };
            let leased = self
                .prepared
                .store
                .create_retry_lineage_with_operation_lease(
                    &parent.local_job_id,
                    &self.prepared.operation_lease,
                    vacancy,
                    &candidate,
                    &options,
                )?;
            if self.prepared.store.revision(&candidate.local_job_id, 1)? != candidate {
                return Err(session_error(
                    "retry_child_initial_revision_mismatch",
                    "the durable snapshot retry child differs from its exact planned request",
                    "Preserve the retry lineage and inspect its immutable transaction.",
                ));
            }
            validate_exact_snapshot_retry_plan(
                &parent,
                &candidate,
                &leased.lineage.binding,
                &plan,
            )?;
            (
                candidate,
                leased.operation_lease,
                leased.lineage.binding,
                GithubRetryChildDisposition::Created,
                Some(plan),
            )
        };

        let snapshot_submission = if let Some(plan) = plan {
            self.prepared.verify_exact_local_record()?;
            let authorization = GithubGitSnapshotExactRetryAuthorizationV1::new(
                parent.operation_id.clone(),
                child.operation_id.clone(),
                plan.source_created_at_ms,
                binding.authorization_sha256.clone(),
            )
            .map_err(|error| {
                provider_failure(
                    &error,
                    "snapshot_exact_retry_authorization_invalid",
                    "the durable retry lineage could not authorize its exact snapshot stage",
                )
            })?;
            let staged = self
                .prepared
                .provider
                .stage_exact_git_snapshot_retry(&authorization, &plan, cancellation)
                .map_err(|error| {
                    provider_failure(
                        &error,
                        "snapshot_exact_retry_stage_failed",
                        "the exact retained snapshot retry stage could not be materialized",
                    )
                })?;
            if staged.request != child.request {
                return Err(session_error(
                    "snapshot_exact_retry_stage_mismatch",
                    "the replayable snapshot stage differs from the durable child request",
                    "Preserve the child lineage and private stage for inspection.",
                ));
            }
            Some(GithubSnapshotRetrySubmission::Exact {
                authorization,
                staged: Box::new(staged),
            })
        } else {
            None
        };

        self.prepared.record = latest_boxed(&self.prepared.store, &parent.local_job_id)?;
        if self.prepared.record.retry_lineage.child_job_ids.last() != Some(&child.local_job_id) {
            return Err(session_error(
                "retry_lineage_changed",
                "the retry parent no longer names the exact selected snapshot child",
                "Retry from the latest immutable parent lineage.",
            ));
        }
        self.prepared.verify_local_boundaries()?;
        let parent_job_id = self.prepared.record.local_job_id.clone();
        let parent_revision = self.prepared.record.revision;
        bind_retry_child(
            self.prepared,
            parent,
            parent_job_id,
            parent_revision,
            &child,
            child_lease,
            disposition,
            snapshot_submission,
        )
    }

    /// Resume or create one freshly consented current-source Git snapshot retry.
    ///
    /// The exact parent Retry lease is already held. A vacancy or existing-child Build lease is
    /// then retained continuously across private staging, durable lineage publication, and the
    /// first specialized provider checkpoint.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "consent, operation authority, private staging, durable lineage, and child binding form one crash boundary"
    )]
    pub(in crate::commands) fn create_or_resume_recaptured_git_snapshot_child<F>(
        mut self,
        parent_policy: RetryParentPolicyV1,
        confirmed: ConfirmedCurrentSnapshotRetry,
        operation_id: &str,
        new_child_local_job_id: LocalJobId,
        make_child: F,
        cancellation: &CancellationToken,
    ) -> Result<GithubRetryChildSession, CliError>
    where
        F: FnOnce(
            &StoredJobV1,
            LocalJobId,
            IosDeviceBuildRequest,
            u64,
        ) -> Result<StoredJobV1, CliError>,
    {
        self.prepared
            .require_operation_kind(JobOperationKind::Retry)?;
        self.prepared.verify_exact_local_record()?;
        let parent = self.prepared.record.as_ref().clone();
        validate_current_snapshot_retry_parent(&parent, &confirmed, operation_id)?;

        let existing = parent
            .retry_lineage
            .child_job_ids
            .last()
            .map(|local_job_id| self.prepared.store.latest(local_job_id))
            .transpose()?;
        let (child, child_lease, staged, disposition) = if let Some(existing) = existing {
            let binding = self
                .prepared
                .store
                .retry_lineage_binding(&parent.local_job_id, &existing.local_job_id)?;
            verify_existing_retry_child(&parent, &existing, &binding)?;
            if !matches!(
                binding.options.source_policy,
                RetrySourcePolicyV1::RecapturedGitSnapshot { .. }
            ) || binding.options.parent_policy != parent_policy
                || existing.operation_id != operation_id
            {
                return Err(session_error(
                    "retry_child_source_policy_mismatch",
                    "the durable retry child differs from the freshly consented current-source transaction",
                    "Resume the child through its persisted retry source policy and exact operation.",
                ));
            }
            let initial = self.prepared.store.revision(&existing.local_job_id, 1)?;
            let child_lease = self
                .prepared
                .store
                .try_acquire_operation_lease(&existing.local_job_id, JobOperationKind::Build)?;
            let current = self.prepared.store.latest(&existing.local_job_id)?;
            if current != existing {
                return Err(session_error(
                    "job_revision_changed",
                    "the durable current-source retry child changed while its Build lease was acquired",
                    "Retry from the latest immutable child revision.",
                ));
            }
            if current.provider_resume.is_some() {
                return Err(session_error(
                    "snapshot_retry_restore_required",
                    "the current-source retry child already has a durable provider checkpoint",
                    "Resume the exact child without fresh stage adoption or source recapture.",
                ));
            }
            let staged = confirmed.stage(
                &self.prepared.operation_lease,
                CurrentSnapshotRetryOperationGuard::ExistingChild(&child_lease),
                cancellation,
            )?;
            if staged.retry_lineage_options(parent_policy, &parent, &initial)? != binding.options {
                return Err(session_error(
                    "retry_snapshot_lineage_mismatch",
                    "the current-source private stage differs from its durable retry lineage",
                    "Preserve the child and stage; reconcile their immutable consent and archive binding.",
                ));
            }
            (
                current,
                child_lease,
                staged,
                GithubRetryChildDisposition::Existing,
            )
        } else {
            let vacancy = match self
                .prepared
                .store
                .try_acquire_vacant_snapshot_operation_lease(operation_id)?
            {
                SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
                SnapshotOperationVacancyV1::Owned(_) => {
                    return Err(session_error(
                        "retry_child_operation_owned",
                        "the consented current-source operation already belongs to another durable job",
                        "Preserve the owner and private stage; do not create a sibling retry.",
                    ));
                }
            };
            let staged = confirmed.stage(
                &self.prepared.operation_lease,
                CurrentSnapshotRetryOperationGuard::Vacant(&vacancy),
                cancellation,
            )?;
            let candidate = make_child(
                &parent,
                new_child_local_job_id,
                staged.request().clone(),
                staged.source_created_at_ms(),
            )?;
            let options = staged.retry_lineage_options(parent_policy, &parent, &candidate)?;
            let leased = self
                .prepared
                .store
                .create_retry_lineage_with_operation_lease(
                    &parent.local_job_id,
                    &self.prepared.operation_lease,
                    vacancy,
                    &candidate,
                    &options,
                )?;
            if self.prepared.store.revision(&candidate.local_job_id, 1)? != candidate {
                return Err(session_error(
                    "retry_child_initial_revision_mismatch",
                    "the durable current-source retry child differs from its consented private stage",
                    "Preserve the retry lineage and stage for exact recovery.",
                ));
            }
            if leased.lineage.binding.options != options {
                return Err(session_error(
                    "retry_snapshot_lineage_mismatch",
                    "the published current-source lineage differs from its exact staged policy",
                    "Preserve the child and stage; inspect the immutable administrative transaction.",
                ));
            }
            (
                candidate,
                leased.operation_lease,
                staged,
                GithubRetryChildDisposition::Created,
            )
        };

        self.prepared.record = latest_boxed(&self.prepared.store, &parent.local_job_id)?;
        if self.prepared.record.retry_lineage.child_job_ids.last() != Some(&child.local_job_id) {
            return Err(session_error(
                "retry_lineage_changed",
                "the retry parent no longer names the exact current-source child",
                "Resume from the latest immutable parent lineage.",
            ));
        }
        self.prepared.verify_local_boundaries()?;
        let parent_job_id = self.prepared.record.local_job_id.clone();
        let parent_revision = self.prepared.record.revision;
        bind_retry_child(
            self.prepared,
            parent,
            parent_job_id,
            parent_revision,
            &child,
            child_lease,
            disposition,
            Some(GithubSnapshotRetrySubmission::CurrentSource(Box::new(
                staged,
            ))),
        )
    }
}

impl GithubRetryChildSession {
    /// Complete one retry through terminal success, validated artifacts, and exact cleanup.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the jobs typestate transfers its one cancellation capability into completion"
    )]
    pub(in crate::commands) fn complete(
        mut self,
        cancellation: CancellationToken,
        reporter: &Reporter,
    ) -> Result<GithubRetryCompletionReceipt, CliError> {
        self.verify_exact_child()?;
        let (expected_downloads, artifact_path) = self.prepare_artifact_destinations()?;
        match retry_child_completion_mode(&self.record) {
            RetryChildCompletionMode::RetainLocalSuccess => {
                let provider_job_id = self.record.provider_job_id.clone().ok_or_else(|| {
                    session_error(
                        "provider_job_identity_missing",
                        "the completed retry child lacks its exact provider job identifier",
                        "Preserve the child and inspect its immutable success checkpoint.",
                    )
                })?;
                let completion = super::retain_completed_artifact_downloads(
                    &self.store,
                    &self.record.local_job_id,
                    &self.project,
                    &expected_downloads,
                    &artifact_path,
                )?;
                return self.completion_receipt(provider_job_id, completion);
            }
            RetryChildCompletionMode::RejectSettled => {
                return Err(session_error(
                    "retry_child_already_settled",
                    "the retry parent already has a settled child that is not an exact local success",
                    "Inspect or retry the existing child job ID; a parent retry never creates a duplicate sibling.",
                ));
            }
            RetryChildCompletionMode::Continue => {}
        }
        self.verify_exact_child()?;
        self.submit_or_reconcile_publication(&cancellation)?;
        self.record = self.store.latest(&self.record.local_job_id)?;
        self.verify_child_boundaries()?;
        let provider_job_id = self.record.provider_job_id.clone().ok_or_else(|| {
            session_error(
                "provider_job_identity_missing",
                "the retry child lost its exact provider job identifier",
                "Preserve the child and reconcile its immutable provider checkpoint.",
            )
        })?;
        self.release_wait_locks();
        let terminal = observe_job_until_terminal(
            &self.provider,
            &self.record.local_job_id,
            &provider_job_id,
            Instant::now() + BUILD_TIMEOUT,
            &cancellation,
            reporter,
        );
        let completion = finish_after_remote_wait(
            &mut self,
            terminal,
            |session| {
                session
                    .reacquire_mutation_locks(&cancellation)
                    .map_err(|error| {
                        if session.operation_lease.is_some() {
                            PostWaitRebindFailure::LeaseHeld(error)
                        } else {
                            PostWaitRebindFailure::LeaseUnavailable(error)
                        }
                    })
            },
            |session, terminal| {
                complete_submitted_job(
                    &session.provider,
                    &session.store,
                    &session.record.local_job_id,
                    &provider_job_id,
                    &session.project,
                    &session.record.request,
                    &expected_downloads,
                    &artifact_path,
                    Instant::now() + BUILD_TIMEOUT,
                    terminal,
                    reporter,
                )
            },
            |session, observation, error| {
                reconcile_post_wait_rebind_failure(
                    &session.provider,
                    &session.store,
                    &session.record.local_job_id,
                    &provider_job_id,
                    &session.project,
                    observation,
                    error,
                )
            },
        )?;
        self.completion_receipt(provider_job_id, completion)
    }

    fn completion_receipt(
        mut self,
        provider_job_id: String,
        completion: CompletedArtifactDownloads,
    ) -> Result<GithubRetryCompletionReceipt, CliError> {
        self.record = self.store.latest(&self.record.local_job_id)?;
        self.verify_child_boundaries()?;
        if self.record.provider_job_id.as_deref() != Some(provider_job_id.as_str())
            || !super::durable_cleanup_is_confirmed(&self.record, &provider_job_id)
            || self.record.state != StoredJobState::Succeeded
            || self.record.terminal_outcome != Some(StoredBuildOutcome::Succeeded)
            || self.record.cleanup_status != StoredCleanupStatus::Confirmed
            || self.record.artifacts.is_empty()
            || self.record.artifacts.iter().any(|artifact| {
                !artifact.locally_validated
                    || artifact.local_path.is_none()
                    || artifact.local_file_identity.is_none()
            })
        {
            return Err(session_error(
                "retry_completion_checkpoint_missing",
                "the retry child lacks exact durable success, artifact, or cleanup evidence",
                "Preserve the child and continue its bounded completion reconciliation.",
            ));
        }
        let artifacts = self
            .record
            .artifacts
            .iter()
            .map(|artifact| GithubRetryArtifactReceipt {
                artifact_id: artifact.record.artifact_id.clone(),
                sha256: artifact.record.sha256.clone(),
                local_path: artifact
                    .local_path
                    .clone()
                    .expect("validated retry artifact path checked above"),
            })
            .collect();
        Ok(GithubRetryCompletionReceipt {
            parent_job_id: self.parent_job_id.clone(),
            parent_revision: self.parent_revision,
            child_job_id: self.record.local_job_id.clone(),
            child_revision: self.record.revision,
            operation_id: self.record.operation_id.clone(),
            request_sha256: self.record.request_sha256.clone(),
            semantic_retry_sha256: self.record.semantic_retry_sha256.clone(),
            source_revision: self.record.source.revision.clone(),
            source_manifest_sha256: self.record.source.manifest_sha256.clone(),
            provider_job_id,
            provider_run_id: self.record.provider_run_id.clone(),
            state: self.record.state,
            terminal_outcome: StoredBuildOutcome::Succeeded,
            cleanup_status: self.record.cleanup_status,
            artifacts,
            disposition: self.disposition,
            _completion: Some(completion),
            _project: Some(self.project),
        })
    }

    fn prepare_artifact_destinations(
        &self,
    ) -> Result<(Vec<ExpectedDownload>, Utf8PathBuf), CliError> {
        let expected = expected_artifact_downloads(
            self.project.root(),
            &self.record.request.product_name,
            self.record.profile == rustferry_remote::BuildProfile::Release,
            self.record.signing_mode,
            &self.record.request.requested_artifacts,
        )?;
        let primary = expected
            .first()
            .ok_or_else(|| {
                session_error(
                    "retry_artifact_plan_empty",
                    "the retry child has no expected local artifact destination",
                    "Preserve the child and inspect its immutable requested artifacts.",
                )
            })?
            .path
            .clone();
        for destination in &expected {
            if let Some(stored) = self
                .record
                .artifacts
                .iter()
                .find(|artifact| artifact.record.kind == destination.kind)
                && let Some(path) = stored.download_destination.as_deref()
            {
                if path != destination.path.as_str() {
                    return Err(session_error(
                        "retry_artifact_destination_mismatch",
                        "the retry child has a different durable artifact destination",
                        "Preserve the child and do not redirect or overwrite its artifacts.",
                    ));
                }
                continue;
            }
            prepare_artifact_destination(self.project.root(), &destination.path)?;
        }
        Ok((expected, primary))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Git, exact snapshot, and recaptured snapshot publication share one reconciliation boundary"
    )]
    fn submit_or_reconcile_publication(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<(), CliError> {
        self.verify_exact_child()?;
        let (provider_job_hint, submit_error) = if self.record.provider_resume.is_some() {
            (self.record.provider_job_id.clone(), None)
        } else if self.record.request.source_mode == SourceMode::GitSnapshot {
            let snapshot = self.snapshot_submission.take().ok_or_else(|| {
                session_error(
                    "snapshot_retry_stage_authority_missing",
                    "the uncheckpointed Git snapshot retry child lacks replayable stage authority",
                    "Reconstruct the exact child from its durable lineage before submission.",
                )
            })?;
            self.verify_exact_child()?;
            let submission = match snapshot {
                GithubSnapshotRetrySubmission::Exact {
                    authorization,
                    staged,
                } => {
                    handshake_with_source_mode(
                        &self.provider,
                        SourceMode::GitSnapshot,
                        self.record.signing_mode,
                        &self.record.request.requested_artifacts,
                    )?;
                    GithubGitSnapshotSubmissionV1::exact_retry_lineage(
                        expected_provider_identity(&self.record),
                        &authorization,
                        *staged,
                    )
                    .map_err(|error| {
                        provider_failure(
                            &error,
                            "snapshot_retry_submission_invalid",
                            "the exact snapshot retry stage differs from its durable child lineage",
                        )
                    })?
                }
                GithubSnapshotRetrySubmission::CurrentSource(staged) => {
                    let child_initial = self.store.revision(&self.record.local_job_id, 1)?;
                    let binding = self.store.retry_lineage_binding(
                        &self.parent_before_lineage.local_job_id,
                        &self.record.local_job_id,
                    )?;
                    staged.into_provider_submission(
                        &self.parent_before_lineage,
                        &child_initial,
                        &binding,
                        expected_provider_identity(&self.record),
                    )?
                }
            };
            match self.provider.submit_git_snapshot(submission, cancellation) {
                Ok(handle) => (Some(handle.job_id), None),
                Err(error) => (None, Some(error)),
            }
        } else {
            handshake(
                &self.provider,
                self.record.signing_mode,
                &self.record.request.requested_artifacts,
            )?;
            self.verify_exact_child()?;
            match poll_provider_once(
                self.provider
                    .submit(self.record.request.clone(), cancellation.clone()),
            ) {
                ImmediateProviderResult::Ready(Ok(handle)) => (Some(handle.job_id), None),
                ImmediateProviderResult::Ready(Err(error)) => (None, Some(error)),
                ImmediateProviderResult::Pending => {
                    persist_submit_uncertain(&self.store, &self.record.local_job_id)?;
                    return Err(session_error(
                        "provider_runtime_required",
                        "the GitHub retry submission requires an asynchronous provider runtime",
                        "Preserve the child job and reconcile its exact publication checkpoint.",
                    ));
                }
            }
        };
        let provider_job_id = reconcile_submit_attempt(
            &self.provider,
            &self.store,
            &self.record.local_job_id,
            &self.project,
            provider_job_hint.as_deref(),
            submit_error.as_ref(),
        )?;
        if let Err(error) = require_bound_provider_job(
            &self.store,
            &self.record.local_job_id,
            &provider_job_id,
            self.provider.workflow_run_trigger(),
        ) {
            persist_submit_uncertain(&self.store, &self.record.local_job_id)?;
            return Err(error);
        }
        self.provider
            .revalidate_restored_job_live(&provider_job_id, cancellation)
            .map_err(|error| {
                provider_failure(
                    &error,
                    "retry_child_revalidation_failed",
                    "the exact GitHub retry child could not be revalidated after publication",
                )
            })?;
        self.record = self.store.latest(&self.record.local_job_id)?;
        self.verify_child_boundaries()?;
        Ok(())
    }

    fn verify_exact_child(&self) -> Result<(), CliError> {
        self.verify_child_boundaries()?;
        if self.store.latest(&self.record.local_job_id)? != self.record {
            return Err(session_error(
                "job_revision_changed",
                "the durable retry child changed after session reconstruction",
                "Retry from the latest immutable child revision.",
            ));
        }
        Ok(())
    }

    fn verify_child_boundaries(&self) -> Result<(), CliError> {
        let operation_lease = self.operation_lease.as_ref().ok_or_else(|| {
            session_error(
                "job_operation_lease_missing",
                "the retry child is outside its bounded Build mutation lease",
                "Reacquire and revalidate the exact child before any local or remote mutation.",
            )
        })?;
        if self.config_lock.is_none()
            || operation_lease.local_job_id() != &self.record.local_job_id
            || operation_lease.kind() != JobOperationKind::Build
        {
            return Err(session_error(
                "job_operation_lease_mismatch",
                "the retry child lost its exact build operation lease",
                "Stop and reconstruct the child under its Build lease.",
            ));
        }
        self.project.verify()?;
        let observed_revision = checked_caller_git_output(
            self.git.caller_git.head_revision(),
            "revalidate the caller Git revision",
        )?;
        verify_captured_git_revision(&self.git.revision, &observed_revision)?;
        verify_project_record(&self.project, &self.record)?;
        ensure_config_snapshot_unchanged(
            self.project.root(),
            &self.project.root().join(CONFIG_RELATIVE_PATH),
            &self.config_identity,
            &self.config_bytes,
        )
    }

    fn release_wait_locks(&mut self) {
        release_build_wait_guards(&mut self.config_lock, &mut self.operation_lease);
    }

    fn reacquire_mutation_locks(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<(), CliError> {
        if self.operation_lease.is_some() || self.config_lock.is_some() {
            return Err(session_error(
                "job_operation_lease_mismatch",
                "the retry child still holds a stale mutation or config lease",
                "Stop and reconstruct the exact child session.",
            ));
        }
        let operation_lease =
            acquire_build_mutation_lease(&self.store, &self.record.local_job_id, cancellation)?;
        self.operation_lease = Some(operation_lease);
        let record = self.store.latest(&self.record.local_job_id)?;
        verify_project_record(&self.project, &record)?;
        let (stored, config_lock) = load_config_for_build(self.project.root())?;
        self.config_lock = Some(config_lock);
        if decode_stored_config(&self.config_bytes)? != stored {
            return Err(session_error(
                "provider_config_changed",
                "the GitHub provider config changed while the retry waited remotely",
                "Restore the exact private provider config before resuming artifact mutation.",
            ));
        }
        ensure_config_snapshot_unchanged(
            self.project.root(),
            &self.project.root().join(CONFIG_RELATIVE_PATH),
            &self.config_identity,
            &self.config_bytes,
        )?;
        self.record = record;
        self.verify_child_boundaries()
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the child typestate receives every retained parent, lease, config, and stage authority explicitly"
)]
fn bind_retry_child(
    prepared: PreparedGithubJobSession,
    parent_before_lineage: StoredJobV1,
    parent_job_id: LocalJobId,
    parent_revision: u64,
    child: &StoredJobV1,
    child_lease: JobOperationLease,
    disposition: GithubRetryChildDisposition,
    snapshot_submission: Option<GithubSnapshotRetrySubmission>,
) -> Result<GithubRetryChildSession, CliError> {
    let PreparedGithubJobSession {
        store,
        provider,
        git,
        project,
        config_identity,
        config_bytes,
        _config_lock: config_lock,
        operation_lease,
        ..
    } = prepared;
    drop(provider);
    drop(operation_lease);
    let record = store.latest(&child.local_job_id)?;
    if &record != child {
        return Err(session_error(
            "job_revision_changed",
            "the durable retry child changed after its Build lease was acquired",
            "Retry from the latest immutable child revision.",
        ));
    }
    verify_project_record(&project, &record)?;
    let stored = decode_stored_config(&config_bytes)?;
    let provider = build_provider(project.root(), &git.root, &stored)?.with_checkpoint_sink(
        GithubJobStoreCheckpointSink::new(store.clone(), record.local_job_id.clone()),
    );
    if let Some(resume) = record.provider_resume.clone() {
        if record.provider_job_id.as_deref() != Some(resume.job_id.as_str()) {
            return Err(session_error(
                "provider_job_identity_mismatch",
                "the durable retry child differs from its resume checkpoint",
                "Preserve the child and inspect its immutable revisions.",
            ));
        }
        provider
            .restore_job_resumes_offline(vec![resume], &expected_provider_identity(&record))
            .map_err(|error| {
                provider_failure(
                    &error,
                    "provider_resume_invalid",
                    "the retry child's GitHub checkpoint could not be restored locally",
                )
            })?;
    }
    let session = GithubRetryChildSession {
        store,
        parent_before_lineage,
        parent_job_id,
        parent_revision,
        record,
        provider: Box::new(provider),
        git,
        project,
        config_identity,
        config_bytes,
        config_lock: Some(config_lock),
        operation_lease: Some(child_lease),
        snapshot_submission,
        disposition,
    };
    session.verify_exact_child()?;
    Ok(session)
}

fn verify_existing_retry_child(
    parent: &StoredJobV1,
    existing: &StoredJobV1,
    binding: &RetryLineageBindingV1,
) -> Result<(), CliError> {
    let expected_attempt = parent.retry_lineage.attempt.checked_add(1).ok_or_else(|| {
        session_error(
            "retry_attempt_overflow",
            "the retry attempt cannot advance beyond the supported range",
            "Preserve the retry lineage and start a new independent build.",
        )
    })?;
    if !parent
        .retry_lineage
        .child_job_ids
        .contains(&existing.local_job_id)
        || existing.retry_lineage.parent_job_id.as_ref() != Some(&parent.local_job_id)
        || existing.retry_lineage.attempt != expected_attempt
        || existing.project != parent.project
        || existing.provider != parent.provider
        || existing.target != parent.target
        || existing.profile != parent.profile
        || existing.signing_mode != parent.signing_mode
        || binding.child_job_id != existing.local_job_id
        || binding.child_operation_id != existing.operation_id
        || binding.parent_next_revision > parent.revision
        || (parent.terminal_outcome == Some(StoredBuildOutcome::Succeeded)
            && binding.options.parent_policy != RetryParentPolicyV1::AllowSuccessful)
    {
        return Err(session_error(
            "retry_child_identity_mismatch",
            "the latest in-flight retry child differs from the requested exact retry template",
            "Resume the existing exact child or preserve the lineage for manual inspection.",
        ));
    }
    Ok(())
}

fn validate_exact_snapshot_retry_plan(
    parent: &StoredJobV1,
    child_initial: &StoredJobV1,
    binding: &RetryLineageBindingV1,
    plan: &GithubGitSnapshotExactRetryPlanV1,
) -> Result<(), CliError> {
    let archive_matches = matches!(
        &binding.options.source_policy,
        RetrySourcePolicyV1::ExactGitSnapshot {
            source_archive_sha256
        } if source_archive_sha256 == &plan.archive.sha256
    );
    if parent.request.source_mode != SourceMode::GitSnapshot
        || child_initial.request.source_mode != SourceMode::GitSnapshot
        || binding.child_job_id != child_initial.local_job_id
        || binding.child_operation_id != child_initial.operation_id
        || child_initial.request != plan.request
        || child_initial.created_at_ms != plan.source_created_at_ms
        || child_initial.source.revision != plan.request.source_revision
        || child_initial.source.manifest_sha256 != plan.manifest_sha256
        || plan.request.source.sha256 != plan.manifest_sha256
        || plan.request.source_repository != parent.request.source_repository
        || plan.request.source != parent.request.source
        || !archive_matches
    {
        return Err(session_error(
            "snapshot_exact_retry_plan_mismatch",
            "the reconstructed retained snapshot plan differs from durable retry lineage",
            "Preserve the parent, child, lineage journal, and private stage for inspection.",
        ));
    }
    Ok(())
}

fn validate_current_snapshot_retry_parent(
    parent: &StoredJobV1,
    confirmed: &ConfirmedCurrentSnapshotRetry,
    operation_id: &str,
) -> Result<(), CliError> {
    if confirmed.parent_job_id() != &parent.local_job_id
        || confirmed.parent_revision() != parent.revision
        || confirmed.operation_id() != operation_id
    {
        return Err(session_error(
            "retry_snapshot_parent_changed",
            "the freshly consented current-source preview differs from the leased retry parent",
            "Review and consent to a new zero-write preview from the latest durable parent.",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn select_existing_retry_child(
    existing: Option<StoredJobV1>,
    create: impl FnOnce() -> Result<StoredJobV1, CliError>,
) -> Result<(StoredJobV1, GithubRetryChildDisposition), CliError> {
    if let Some(existing) = existing {
        Ok((existing, GithubRetryChildDisposition::Existing))
    } else {
        Ok((create()?, GithubRetryChildDisposition::Created))
    }
}

fn finish_after_remote_wait<C, T, U>(
    context: &mut C,
    observation: Result<T, CliError>,
    reacquire: impl FnOnce(&mut C) -> Result<(), PostWaitRebindFailure>,
    finish: impl FnOnce(&mut C, Result<T, CliError>) -> Result<U, CliError>,
    reconcile_rebind_failure: impl FnOnce(&mut C, &Result<T, CliError>, &CliError) -> CliError,
) -> Result<U, CliError> {
    match reacquire(context) {
        Ok(()) => finish(context, observation),
        Err(PostWaitRebindFailure::LeaseUnavailable(error)) => Err(error),
        Err(PostWaitRebindFailure::LeaseHeld(error)) => {
            Err(reconcile_rebind_failure(context, &observation, &error))
        }
    }
}

fn expected_provider_identity(record: &StoredJobV1) -> GithubDurableIdentityV1 {
    GithubDurableIdentityV1 {
        provider: record.provider.provider.clone(),
        provider_config_sha256: record.provider.provider_config_sha256.clone(),
        principal: record.provider.principal.clone(),
        execution_repository: record.provider.execution_repository.clone(),
        execution_repository_id: record.provider.execution_repository_id,
    }
}

fn durable_job_is_terminal(record: &StoredJobV1) -> bool {
    record.terminal_outcome.is_some()
        || record.failure.is_some()
        || record.cancellation_status == StoredCancellationStatus::Confirmed
        || matches!(
            record.state,
            StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
}

fn retry_child_is_settled(record: &StoredJobV1) -> bool {
    retry_child_state_is_settled(
        record.state,
        record.terminal_outcome,
        record.cleanup_status,
        record.cancellation_status,
    )
}

fn retry_child_completion_mode(record: &StoredJobV1) -> RetryChildCompletionMode {
    if !retry_child_is_settled(record) {
        RetryChildCompletionMode::Continue
    } else if record.state == StoredJobState::Succeeded
        && record.terminal_outcome == Some(StoredBuildOutcome::Succeeded)
        && record.cleanup_status == StoredCleanupStatus::Confirmed
        && record.failure.is_none()
    {
        RetryChildCompletionMode::RetainLocalSuccess
    } else {
        RetryChildCompletionMode::RejectSettled
    }
}

fn retry_child_state_is_settled(
    state: StoredJobState,
    terminal_outcome: Option<StoredBuildOutcome>,
    cleanup_status: StoredCleanupStatus,
    cancellation_status: StoredCancellationStatus,
) -> bool {
    terminal_outcome.is_some()
        && matches!(
            state,
            StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
        && matches!(
            cleanup_status,
            StoredCleanupStatus::NotStarted | StoredCleanupStatus::Confirmed
        )
        && cancellation_status != StoredCancellationStatus::Uncertain
}

fn cancellation_action(
    terminal: bool,
    status: StoredCancellationStatus,
    provider_intent_checkpointed: bool,
    intent_persisted_by_this_call: bool,
) -> CancellationAction {
    if terminal {
        CancellationAction::TerminalNoop
    } else if intent_persisted_by_this_call
        && status == StoredCancellationStatus::Requested
        && !provider_intent_checkpointed
    {
        CancellationAction::DispatchOnce
    } else {
        CancellationAction::GetOnly
    }
}

fn verify_project_record(
    project: &ProjectFilesystemBinding,
    record: &StoredJobV1,
) -> Result<(), CliError> {
    project.verify()?;
    if project.root().as_str() != record.project.canonical_root
        || project.identity.to_string() != record.project.filesystem_identity
        || record.provider.provider != GITHUB_PROVIDER_ID
    {
        return Err(session_error(
            "durable_job_identity_mismatch",
            "the durable project or provider identity no longer matches the live session",
            "Restore the exact project and private provider config before retrying.",
        ));
    }
    Ok(())
}

fn session_error(code: &'static str, message: &'static str, help: &'static str) -> CliError {
    remote_error(code, message, help)
}

#[inline(never)]
fn latest_boxed(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<Box<StoredJobV1>, JobStoreError> {
    store.latest(local_job_id).map(Box::new)
}

#[cfg(test)]
mod tests {
    use rustferry_github::transport::{CommitSha, Repository, RunId, WorkflowId};
    use sha2::{Digest, Sha256};

    use super::super::acquire_build_mutation_lease_until;
    use super::super::tests::{durable_controller_record, provider_config_fixture};
    use super::*;

    fn one_line_log_projection() -> (
        Vec<Vec<ManagedJobEventInputV1>>,
        ManagedJobEventInputV1,
        GithubDurableRunAttemptLogIdentity,
    ) {
        let owner = "owner";
        let name = "repo";
        let run_id = 42_u64;
        let attempt = 2_u16;
        let workflow_id = 7_u64;
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let identity = GithubDurableRunAttemptLogIdentity::new(
            Repository::new(owner, name).expect("repository"),
            RunId::new(run_id).expect("run ID"),
            u64::from(attempt),
            CommitSha::new(head_sha).expect("head SHA"),
            WorkflowId::new(workflow_id).expect("workflow ID"),
        )
        .expect("durable log identity");
        let line_sequence = u64::from(attempt) << 32 | 1;
        let line_digest = "a".repeat(64);
        let line = ManagedJobEventInputV1 {
            source: ManagedEventSource::Worker,
            source_sequence: Some(line_sequence),
            source_event_sha256: Some(line_digest.clone()),
            occurred_at_ms: 1_579_539_879_123,
            phase: Some(WORKER_LOG_PHASE.to_owned()),
            level: ManagedEventLevel::Info,
            code: WORKER_LOG_LINE_CODE.to_owned(),
            message: Some("safe worker line".to_owned()),
        };
        let event_set_sha256 = test_event_set_sha256(line_sequence, &line_digest);
        let job_set_sha256 = "b".repeat(64);
        let marker_sequence = identity.expected_completion_source_sequence();
        let marker_message = format!(
            "run_id={run_id} run_attempt={attempt} head_sha={head_sha} workflow_id={workflow_id} job_count=1 job_set_sha256={job_set_sha256} event_count=1 event_set_sha256={event_set_sha256}"
        );
        let marker_time = 1_579_539_879_124;
        let marker_digest = test_completion_sha256(
            owner,
            name,
            run_id,
            attempt,
            head_sha,
            workflow_id,
            marker_time,
            &job_set_sha256,
            &event_set_sha256,
            marker_sequence,
            &marker_message,
        );
        let marker = ManagedJobEventInputV1 {
            source: ManagedEventSource::Worker,
            source_sequence: Some(marker_sequence),
            source_event_sha256: Some(marker_digest),
            occurred_at_ms: marker_time,
            phase: Some(WORKER_LOG_PHASE.to_owned()),
            level: ManagedEventLevel::Info,
            code: WORKER_LOGS_COMPLETE_CODE.to_owned(),
            message: Some(marker_message),
        };
        (vec![vec![line]], marker, identity)
    }

    fn test_event_set_sha256(source_sequence: u64, source_event_sha256: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"rustferry.github.worker-log-event-set.v1\0");
        digest.update(1_u64.to_be_bytes());
        digest.update(source_sequence.to_be_bytes());
        test_digest_field(&mut digest, source_event_sha256.as_bytes());
        test_sha256_hex(digest)
    }

    #[allow(clippy::too_many_arguments)]
    fn test_completion_sha256(
        owner: &str,
        name: &str,
        run_id: u64,
        attempt: u16,
        head_sha: &str,
        workflow_id: u64,
        occurred_at_ms: u64,
        job_set_sha256: &str,
        event_set_sha256: &str,
        source_sequence: u64,
        message: &str,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(b"rustferry.github.worker-logs-complete.v1\0");
        test_digest_field(&mut digest, owner.as_bytes());
        test_digest_field(&mut digest, name.as_bytes());
        digest.update(run_id.to_be_bytes());
        digest.update(attempt.to_be_bytes());
        test_digest_field(&mut digest, head_sha.as_bytes());
        digest.update(workflow_id.to_be_bytes());
        digest.update(occurred_at_ms.to_be_bytes());
        digest.update(1_u32.to_be_bytes());
        test_digest_field(&mut digest, job_set_sha256.as_bytes());
        digest.update(1_u64.to_be_bytes());
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

    #[test]
    fn operation_preflight_and_prepared_session_have_bounded_inline_size() {
        assert_eq!(
            std::mem::size_of::<Box<StoredJobV1>>(),
            std::mem::size_of::<usize>()
        );
        assert!(std::mem::size_of::<GithubOperationPreflight>() <= 1_024);
        assert!(std::mem::size_of::<PreparedGithubJobSession>() <= 4_096);
    }

    #[test]
    fn cancellation_dispatch_is_limited_to_the_same_call_that_persisted_intent() {
        assert_eq!(
            cancellation_action(false, StoredCancellationStatus::Requested, false, true),
            CancellationAction::DispatchOnce
        );
        assert_eq!(
            cancellation_action(false, StoredCancellationStatus::Requested, false, false),
            CancellationAction::GetOnly
        );
        assert_eq!(
            cancellation_action(false, StoredCancellationStatus::Requested, true, true),
            CancellationAction::GetOnly
        );
    }

    #[test]
    fn terminal_cancellation_never_dispatches() {
        assert_eq!(
            cancellation_action(true, StoredCancellationStatus::Requested, false, true),
            CancellationAction::TerminalNoop
        );
    }

    #[test]
    fn snapshot_prune_session_rejects_wrong_kind_and_foreign_store_leases_first() {
        let left = tempfile::tempdir().expect("left prune fixture");
        let right = tempfile::tempdir().expect("right prune fixture");
        let left_store = JobStore::open_at(left.path().join("jobs")).expect("left job store");
        let right_store = JobStore::open_at(right.path().join("jobs")).expect("right job store");
        let left_record = durable_controller_record(&left, None);
        let right_record = durable_controller_record(&right, None);
        assert_eq!(left_record.local_job_id, right_record.local_job_id);
        left_store.create(&left_record).expect("left durable job");
        right_store
            .create(&right_record)
            .expect("right durable job");

        let wrong_kind = left_store
            .try_acquire_operation_lease(&left_record.local_job_id, JobOperationKind::Build)
            .expect("wrong-kind lease fixture");
        let error = GithubPruneSnapshotSession::prepare(
            &left_store,
            &left_record.local_job_id,
            &wrong_kind,
        )
        .err()
        .expect("wrong-kind lease must fail before config or provider access");
        assert_eq!(error.code(), "invalid_job_record");
        drop(wrong_kind);

        let foreign = right_store
            .try_acquire_operation_lease(&right_record.local_job_id, JobOperationKind::Prune)
            .expect("foreign Prune lease fixture");
        let error =
            GithubPruneSnapshotSession::prepare(&left_store, &left_record.local_job_id, &foreign)
                .err()
                .expect("foreign-store lease must fail before config or provider access");
        assert_eq!(error.code(), "invalid_job_record");
    }

    #[test]
    fn retained_prune_lease_excludes_build_and_cancel_mutation() {
        let temporary = tempfile::tempdir().expect("Prune lease fixture");
        let store = JobStore::open_at(temporary.path().join("jobs")).expect("job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("durable job");
        let prune = store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Prune)
            .expect("retained Prune lease");
        assert!(matches!(
            store.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build),
            Err(JobStoreError::JobBusy { .. })
        ));
        assert!(matches!(
            store.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel),
            Err(JobStoreError::JobBusy { .. })
        ));
        drop(prune);
        store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel)
            .expect("Cancel becomes available only after Prune is released");
    }

    #[test]
    fn job_session_accepts_a_prior_checkout_advance_but_rejects_mid_poll_drift() {
        let historical_job_revision = "a".repeat(40);
        let captured_session_revision = "b".repeat(40);
        assert_ne!(historical_job_revision, captured_session_revision);
        verify_captured_git_revision(
            &captured_session_revision,
            format!("{captured_session_revision}\n").as_bytes(),
        )
        .expect("a checkout advanced before session capture remains manageable");

        let changed_during_poll = "c".repeat(40);
        let error = verify_captured_git_revision(
            &captured_session_revision,
            format!("{changed_during_poll}\n").as_bytes(),
        )
        .expect_err("a revision change during one bounded poll must fail closed");
        assert_eq!(error.code(), "caller_repository_revision_changed");
    }

    #[test]
    fn log_preflight_never_returns_not_applicable_for_a_raced_revision() {
        let temporary = tempfile::tempdir().expect("log preflight fixture");
        let store = JobStore::open_at(temporary.path().join("jobs")).expect("private job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("durable job");
        let stale = store.latest(&record.local_job_id).expect("preflight job");
        store
            .append_managed_events(
                &record.local_job_id,
                record.updated_at_ms,
                &[ManagedJobEventInputV1 {
                    source: ManagedEventSource::Controller,
                    source_sequence: None,
                    source_event_sha256: None,
                    occurred_at_ms: 1,
                    phase: Some("test".to_owned()),
                    level: ManagedEventLevel::Info,
                    code: "test.log_race".to_owned(),
                    message: Some("durable revision raced log preflight".to_owned()),
                }],
            )
            .expect("racing durable revision");

        let error = no_provider_log_poll_under_lease(&store, &record.local_job_id, &stale)
            .expect_err("stale preflight cannot report no provider fetch");
        assert_eq!(error.code(), "job_revision_changed");

        let latest = store.latest(&record.local_job_id).expect("latest job");
        let receipt = no_provider_log_poll_under_lease(&store, &record.local_job_id, &latest)
            .expect("stable leased preflight")
            .expect("job still has no provider obligation");
        assert_eq!(receipt.revision, latest.revision);
        assert!(!receipt.provider_fetch_performed);
    }

    #[test]
    fn worker_logs_append_marker_last_and_replay_from_structural_proof() {
        let temporary = tempfile::tempdir().expect("Worker log fixture");
        let store = JobStore::open_at(temporary.path().join("jobs")).expect("private job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("durable job");
        let (batches, marker, identity) = one_line_log_projection();
        assert!(
            !exact_worker_log_completion_is_durable(&store, &record.local_job_id, &identity,)
                .expect("missing marker is incomplete")
        );

        let first = append_worker_log_inputs(
            &store,
            &record.local_job_id,
            record.updated_at_ms,
            batches.clone(),
            &marker,
        )
        .expect("append sanitized lines and marker");
        assert_eq!(first, (2, 0));
        let page = store
            .read_managed_events(&record.local_job_id, 0, MAX_MANAGED_EVENT_PAGE)
            .expect("durable Worker journal");
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].code, WORKER_LOG_LINE_CODE);
        assert_eq!(page.events[1].code, WORKER_LOGS_COMPLETE_CODE);
        assert!(
            exact_worker_log_completion_is_durable(&store, &record.local_job_id, &identity,)
                .expect("exact event-set proof")
        );

        let replay = append_worker_log_inputs(
            &store,
            &record.local_job_id,
            record.updated_at_ms,
            batches,
            &marker,
        )
        .expect("restart-safe replay");
        assert_eq!(replay, (0, 2));
        assert_eq!(
            store
                .read_managed_events(&record.local_job_id, 0, MAX_MANAGED_EVENT_PAGE)
                .expect("deduplicated Worker journal")
                .events
                .len(),
            2
        );

        let malformed = ManagedJobEventInputV1 {
            source: ManagedEventSource::Worker,
            source_sequence: None,
            source_event_sha256: None,
            occurred_at_ms: marker.occurred_at_ms + 1,
            phase: Some(WORKER_LOG_PHASE.to_owned()),
            level: ManagedEventLevel::Info,
            code: WORKER_LOG_LINE_CODE.to_owned(),
            message: Some("unsequenced Worker line".to_owned()),
        };
        store
            .append_managed_events(
                &record.local_job_id,
                record.updated_at_ms,
                std::slice::from_ref(&malformed),
            )
            .expect("unsequenced public-store misuse fixture");
        let error = exact_worker_log_completion_is_durable(&store, &record.local_job_id, &identity)
            .expect_err("unsequenced Worker log codes invalidate the completion proof");
        assert_eq!(error.code(), "provider_log_completion_invalid");
    }

    #[test]
    fn worker_log_proof_rejects_partial_and_marker_only_journals() {
        let partial = tempfile::tempdir().expect("partial Worker log fixture");
        let partial_store =
            JobStore::open_at(partial.path().join("jobs")).expect("partial job store");
        let partial_record = durable_controller_record(&partial, None);
        partial_store
            .create(&partial_record)
            .expect("partial durable job");
        let (batches, marker, identity) = one_line_log_projection();
        partial_store
            .append_managed_events(
                &partial_record.local_job_id,
                partial_record.updated_at_ms,
                &batches[0],
            )
            .expect("durable line prefix");
        assert!(
            !exact_worker_log_completion_is_durable(
                &partial_store,
                &partial_record.local_job_id,
                &identity,
            )
            .expect("line prefix remains incomplete")
        );

        let marker_only = tempfile::tempdir().expect("marker-only Worker log fixture");
        let marker_store =
            JobStore::open_at(marker_only.path().join("jobs")).expect("marker-only job store");
        let marker_record = durable_controller_record(&marker_only, None);
        marker_store
            .create(&marker_record)
            .expect("marker-only durable job");
        marker_store
            .append_managed_events(
                &marker_record.local_job_id,
                marker_record.updated_at_ms,
                std::slice::from_ref(&marker),
            )
            .expect("forged marker-only journal");
        let error = exact_worker_log_completion_is_durable(
            &marker_store,
            &marker_record.local_job_id,
            &identity,
        )
        .expect_err("marker cannot prove absent lines");
        assert_eq!(error.code(), "provider_log_completion_invalid");
    }

    #[test]
    fn retry_child_converges_until_local_success_and_cleanup_are_complete() {
        assert!(!retry_child_state_is_settled(
            StoredJobState::ArtifactReady,
            Some(StoredBuildOutcome::Succeeded),
            StoredCleanupStatus::NotStarted,
            StoredCancellationStatus::NotRequested,
        ));
        assert!(!retry_child_state_is_settled(
            StoredJobState::Succeeded,
            Some(StoredBuildOutcome::Succeeded),
            StoredCleanupStatus::Pending,
            StoredCancellationStatus::NotRequested,
        ));
        assert!(retry_child_state_is_settled(
            StoredJobState::Succeeded,
            Some(StoredBuildOutcome::Succeeded),
            StoredCleanupStatus::Confirmed,
            StoredCancellationStatus::NotRequested,
        ));
        let mut success = durable_controller_record(
            &tempfile::tempdir().expect("settled retry fixture"),
            Some(b"validated retry artifact"),
        );
        success.state = StoredJobState::Succeeded;
        success.terminal_outcome = Some(StoredBuildOutcome::Succeeded);
        success.cleanup_status = StoredCleanupStatus::Confirmed;
        assert_eq!(
            retry_child_completion_mode(&success),
            RetryChildCompletionMode::RetainLocalSuccess
        );
        success.state = StoredJobState::Failed;
        success.terminal_outcome = Some(StoredBuildOutcome::Failed);
        assert_eq!(
            retry_child_completion_mode(&success),
            RetryChildCompletionMode::RejectSettled
        );
        let selected = success.clone();
        let (reused, disposition) = select_existing_retry_child(Some(selected.clone()), || {
            panic!("a settled child must prevent allocating a paid sibling retry")
        })
        .expect("settled child reuse");
        assert_eq!(reused, selected);
        assert_eq!(disposition, GithubRetryChildDisposition::Existing);
    }

    #[test]
    fn original_and_retry_wait_release_build_then_rebind_artifact_mutation() {
        let (temporary, root, _paths, _stored) = provider_config_fixture();
        let store = JobStore::open_at(temporary.path().join("jobs")).expect("private job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("durable retry child");
        let mut build_lease = Some(
            store
                .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build)
                .expect("initial bounded Build lease"),
        );
        let (_, initial_config_lock) = load_config_for_build(&root).expect("initial config lock");
        let mut config_lock = Some(initial_config_lock);

        release_build_wait_guards(&mut config_lock, &mut build_lease);
        let (_, wait_config_lock) = load_config_for_build(&root)
            .expect("the provider config lock is released during remote wait");
        drop(wait_config_lock);
        let cancel = store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel)
            .expect("Cancel may interleave while the retry waits remotely");
        drop(cancel);
        let logs = store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Logs)
            .expect("one bounded log poll may interleave while the retry waits");
        assert!(matches!(
            store.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build),
            Err(JobStoreError::JobBusy { .. })
        ));
        let release_logs = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(logs);
        });
        build_lease = Some(
            acquire_build_mutation_lease_until(
                &store,
                &record.local_job_id,
                &CancellationToken::new(),
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .expect("artifact mutation waits for a bounded Logs poll and reacquires Build"),
        );
        release_logs.join().expect("bounded Logs release thread");
        assert_eq!(
            build_lease.as_ref().map(JobOperationLease::kind),
            Some(JobOperationKind::Build)
        );
        assert!(matches!(
            store.try_acquire_operation_lease(
                &record.local_job_id,
                JobOperationKind::ArtifactRemoval,
            ),
            Err(JobStoreError::JobBusy { .. })
        ));
        drop(build_lease.take());
        let cancel = store
            .try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Cancel)
            .expect("persistent conflicting cancellation lease");
        let before = store
            .latest(&record.local_job_id)
            .expect("job before busy rebind");
        let error = acquire_build_mutation_lease_until(
            &store,
            &record.local_job_id,
            &CancellationToken::new(),
            Instant::now() + std::time::Duration::from_millis(75),
        )
        .expect_err("persistent conflict must fail with a resumable busy error");
        assert_eq!(error.code(), "job_build_reacquire_busy");
        assert_eq!(
            store
                .latest(&record.local_job_id)
                .expect("job after busy rebind"),
            before
        );
        drop(cancel);
    }

    #[test]
    fn retry_wait_errors_and_post_lease_rebind_failures_converge_through_cleanup() {
        #[derive(Default)]
        struct Trace {
            steps: Vec<&'static str>,
        }

        let mut observation_error = Trace::default();
        let error = finish_after_remote_wait(
            &mut observation_error,
            Err::<(), _>(session_error(
                "test_observation_failed",
                "test observation failed",
                "test only",
            )),
            |trace| {
                trace.steps.push("rebound");
                Ok(())
            },
            |trace, observation| {
                trace.steps.push("finish");
                assert!(observation.is_err());
                trace.steps.push("cleanup");
                trace.steps.push("checkpoint");
                Err::<(), _>(session_error(
                    "test_tracking_cleanup",
                    "test tracking cleanup",
                    "test only",
                ))
            },
            |_trace, _observation, _error| {
                panic!("successful rebind must route the observation error through completion")
            },
        )
        .expect_err("observation failure remains an error after durable cleanup");
        assert_eq!(error.code(), "test_tracking_cleanup");
        assert_eq!(
            observation_error.steps,
            ["rebound", "finish", "cleanup", "checkpoint"]
        );

        let mut rebind_error = Trace::default();
        let error = finish_after_remote_wait(
            &mut rebind_error,
            Ok(()),
            |trace| {
                trace.steps.push("rebound");
                Err(PostWaitRebindFailure::LeaseHeld(session_error(
                    "test_config_drift",
                    "test config drift",
                    "test only",
                )))
            },
            |_trace, _observation| -> Result<(), CliError> {
                panic!("artifact completion must not run after exact config rebind failure")
            },
            |trace, observation, error| {
                assert!(observation.is_ok());
                assert_eq!(error.code(), "test_config_drift");
                trace.steps.push("cleanup");
                trace.steps.push("checkpoint");
                session_error("test_rebind_cleanup", "test rebind cleanup", "test only")
            },
        )
        .expect_err("post-lease rebind failure remains an error after cleanup");
        assert_eq!(error.code(), "test_rebind_cleanup");
        assert_eq!(rebind_error.steps, ["rebound", "cleanup", "checkpoint"]);
    }
}
