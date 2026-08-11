//! Shared IDE-facing services built on the existing Rust project model.

use std::fs;
use std::ops::Range;

use camino::Utf8Path;
use cargo_ferry::job_store::{JobStore, LocalJobId};
use rustferry_core::RetainedDirectoryIdentity;
use serde_json::Value;

use super::protocol::{
    ArtifactActionEligibility, BuildMetadata, Diagnostic, DiagnosticSeverity, FeatureFlags,
    HandshakeResponse, HostInfo, JobActionEligibility, JobArtifact, JobDetails, JobFailure,
    JobListItem, JobLogEvent, JobLogsResponse, JobPrincipal, JobProviderIdentity, JobRetryLineage,
    JobShowResponse, JobsListResponse, LegacyJobLogEvent, PROTOCOL_VERSION, Position, ProjectModel,
    ProjectResponse, ProtocolErrorResponse, RuntimeDependencyStatus, SUPPORTED_EVENT_TYPES,
    SUPPORTED_PROTOCOL_VERSIONS, SigningTeam, SigningTeamsResponse, SourceRange, TemplateMetadata,
    ToolInfo, ValidationResponse, protocol_error,
};
use crate::commands::jobs;
use crate::commands::jobs::{
    IdeJobArtifactV1, IdeJobListItemV1, IdeJobLogEventV1, IdeJobPrincipalIdentityV1,
    ProjectJobDetailsV1,
};
use crate::error::CliError;
use crate::project::{capture_project_directory_identity, find_project_root};

/// Build a deterministic protocol handshake from compiled capabilities.
pub fn handshake() -> HandshakeResponse {
    HandshakeResponse {
        protocol_version: PROTOCOL_VERSION,
        tool: ToolInfo {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        host: HostInfo {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        },
        supported_protocol_versions: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
        supported_platforms: vec![
            "android".to_owned(),
            "ios-simulator".to_owned(),
            "ios-device".to_owned(),
        ],
        supported_commands: vec![
            "handshake".to_owned(),
            "project".to_owned(),
            "validate".to_owned(),
            "doctor".to_owned(),
            "devices".to_owned(),
            "signing-teams".to_owned(),
            "jobs-list".to_owned(),
            "jobs-show".to_owned(),
            "jobs-artifacts".to_owned(),
            "jobs-logs".to_owned(),
            "jobs-logs-page".to_owned(),
            "jobs-cancel".to_owned(),
            "jobs-retry".to_owned(),
            "jobs-artifact-verify".to_owned(),
            "jobs-artifact-reveal".to_owned(),
            "jobs-artifact-remove".to_owned(),
            "remote-build-preview".to_owned(),
            "remote-build-submit".to_owned(),
            "signing-readiness".to_owned(),
            "check".to_owned(),
            "build".to_owned(),
            "install".to_owned(),
            "run".to_owned(),
            "logs".to_owned(),
            "schema".to_owned(),
        ],
        supported_event_types: SUPPORTED_EVENT_TYPES
            .iter()
            .map(ToString::to_string)
            .collect(),
        features: FeatureFlags {
            android_build: true,
            ios_simulator_build: cfg!(target_os = "macos"),
            devices: true,
            install: true,
            run: true,
            logs: true,
            physical_ios: cfg!(target_os = "macos"),
            cancellation: true,
        },
        build: BuildMetadata {
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_owned(),
            target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            development: cfg!(debug_assertions),
            git_commit: option_env!("RUSTFERRY_GIT_COMMIT").map(ToOwned::to_owned),
        },
        runtime_dependency: runtime_dependency_status(),
        templates: templates(),
    }
}

/// List durable jobs owned by the exact canonical workspace and filesystem object.
pub fn jobs_list(workspace: &Utf8Path, limit: usize) -> Result<JobsListResponse, CliError> {
    let binding = IdeJobWorkspaceBinding::capture(workspace)?;
    let store = JobStore::open_default_read_only()?;
    let result = jobs::list_for_project(
        &store,
        binding.root.as_str(),
        binding.filesystem_identity.as_str(),
        limit,
    )?;
    binding.verify()?;
    let jobs = result
        .jobs
        .into_iter()
        .map(|item| {
            let local_job_id = LocalJobId::new(item.local_job_id.clone()).map_err(|_| {
                ide_contract_error(
                    "ide_job_identity_invalid",
                    "the durable job has an invalid local identifier".to_owned(),
                    "Preserve the durable state and reconcile the job identity before exposing it to an editor.",
                )
            })?;
            let eligibility = job_action_eligibility_for_project(
                &store,
                &local_job_id,
                &binding,
                item.revision,
            )?;
            job_list_item(item, eligibility)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if result.limit != limit || result.returned != jobs.len() || result.returned > result.limit {
        return Err(ide_contract_error(
            "job_list_binding_invalid",
            "the durable job list does not bind the exact requested limit and returned records"
                .to_owned(),
            "Retry the exact workspace and bounded list request.",
        ));
    }
    binding.verify()?;
    Ok(JobsListResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested,
        limit: result.limit,
        returned: result.returned,
        jobs,
    })
}

/// Show one durable job only when the exact workspace owns it.
pub fn job_show(
    workspace: &Utf8Path,
    local_job_id: &LocalJobId,
) -> Result<JobShowResponse, CliError> {
    let binding = IdeJobWorkspaceBinding::capture(workspace)?;
    let store = JobStore::open_default_read_only()?;
    let job = jobs::show_for_project(
        &store,
        local_job_id,
        binding.root.as_str(),
        binding.filesystem_identity.as_str(),
    )?;
    if job.local_job_id != local_job_id.as_str() {
        return Err(ide_contract_error(
            "job_selection_binding_invalid",
            "the durable job details do not bind the exact requested job".to_owned(),
            "Retry the exact workspace and job selector.",
        ));
    }
    let eligibility =
        job_action_eligibility_for_project(&store, local_job_id, &binding, job.revision)?;
    binding.verify()?;
    Ok(JobShowResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested,
        job: job_details(job, eligibility)?,
    })
}

/// Read sanitized lifecycle events only when the exact workspace owns the selected job.
pub fn job_logs(
    workspace: &Utf8Path,
    local_job_id: &LocalJobId,
    since_ms: u64,
    phase: Option<&str>,
) -> Result<JobLogsResponse, CliError> {
    let binding = IdeJobWorkspaceBinding::capture(workspace)?;
    let store = JobStore::open_default_read_only()?;
    let result = jobs::logs_for_project(
        &store,
        local_job_id,
        binding.root.as_str(),
        binding.filesystem_identity.as_str(),
        since_ms,
        phase,
    )?;
    if result.local_job_id != local_job_id.as_str()
        || result.since_ms != since_ms
        || result.phase.as_deref() != phase
        || result.returned != result.events.len()
    {
        return Err(ide_contract_error(
            "job_log_binding_invalid",
            "the durable job logs do not bind the exact request and returned events".to_owned(),
            "Retry the exact workspace, job, timestamp, and phase selector.",
        ));
    }
    binding.verify()?;
    let events = result
        .events
        .into_iter()
        .map(legacy_job_log_event)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JobLogsResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested,
        local_job_id: result.local_job_id,
        log_scope: result.log_scope,
        provider_full_logs: false,
        since_ms: safe_number(result.since_ms, "job log timestamp")?,
        phase: result.phase,
        returned: result.returned,
        next_sequence: safe_number(result.next_sequence, "legacy job log cursor")?,
        terminal: result.terminal,
        events,
    })
}

pub(crate) struct IdeJobWorkspaceBinding {
    requested: String,
    root: camino::Utf8PathBuf,
    filesystem_identity: String,
    retained: RetainedDirectoryIdentity,
}

impl IdeJobWorkspaceBinding {
    pub(crate) fn capture(workspace: &Utf8Path) -> Result<Self, CliError> {
        let requested = workspace.to_string();
        if !valid_protocol_path(&requested) {
            return Err(ide_contract_error(
                "ide_workspace_path_invalid",
                "the requested workspace is not a bounded protocol path".to_owned(),
                "Use a local workspace path without control characters.",
            ));
        }
        let root = find_project_root(Some(workspace))?;
        let captured = capture_project_directory_identity(&root).map_err(|_| {
            project_identity_error("could not capture the project directory identity")
        })?;
        let retained = RetainedDirectoryIdentity::open(root.as_std_path()).map_err(|_| {
            project_identity_error("could not retain the project directory identity")
        })?;
        if retained.identity() != &captured {
            return Err(project_identity_error(
                "the project directory changed while its identity was captured",
            ));
        }
        retained
            .verify_path(root.as_std_path())
            .map_err(|_| project_identity_error("the project directory identity changed"))?;
        Ok(Self {
            requested,
            root,
            filesystem_identity: captured.to_string(),
            retained,
        })
    }

    pub(crate) fn verify(&self) -> Result<(), CliError> {
        self.retained
            .verify_path(self.root.as_std_path())
            .map_err(|_| project_identity_error("the project directory identity changed"))
    }

    pub(crate) fn requested(&self) -> &str {
        &self.requested
    }

    pub(crate) fn canonical_root(&self) -> &str {
        self.root.as_str()
    }

    pub(crate) fn filesystem_identity(&self) -> &str {
        &self.filesystem_identity
    }
}

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(crate) fn safe_number(value: u64, field: &'static str) -> Result<u64, CliError> {
    if value <= JAVASCRIPT_MAX_SAFE_INTEGER {
        Ok(value)
    } else {
        Err(ide_contract_error(
            "ide_safe_number_overflow",
            format!("{field} exceeds the IDE protocol safe-number range"),
            "Preserve the durable state and use a newer protocol that represents this field as a decimal string.",
        ))
    }
}

fn optional_safe_number(value: Option<u64>, field: &'static str) -> Result<Option<u64>, CliError> {
    value.map(|value| safe_number(value, field)).transpose()
}

fn canonical_decimal(value: &str, field: &'static str) -> Result<String, CliError> {
    let canonical = !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok();
    if canonical {
        Ok(value.to_owned())
    } else {
        Err(ide_contract_error(
            "ide_decimal_identity_invalid",
            format!("{field} is not a canonical unsigned decimal identifier"),
            "Preserve the durable job and reconcile its provider identity before exposing it to an editor.",
        ))
    }
}

fn optional_canonical_decimal(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, CliError> {
    value
        .map(|value| canonical_decimal(&value, field))
        .transpose()
}

fn job_list_item(
    item: IdeJobListItemV1,
    eligibility: JobActionEligibility,
) -> Result<JobListItem, CliError> {
    Ok(JobListItem {
        local_job_id: item.local_job_id,
        revision: safe_number(item.revision, "job revision")?,
        provider: item.provider,
        provider_job_id: optional_canonical_decimal(item.provider_job_id, "provider job ID")?,
        provider_run_id: optional_canonical_decimal(item.provider_run_id, "provider run ID")?,
        operation_id: item.operation_id,
        app_label: item.app_label,
        application_identifier: item.application_identifier,
        target: item.target,
        profile: item.profile,
        signing_mode: item.signing_mode,
        created_at_ms: safe_number(item.created_at_ms, "job creation timestamp")?,
        submitted_at_ms: optional_safe_number(item.submitted_at_ms, "job submission timestamp")?,
        updated_at_ms: safe_number(item.updated_at_ms, "job update timestamp")?,
        state: item.state,
        last_confirmed_state: item.last_confirmed_state,
        terminal_outcome: item.terminal_outcome,
        cleanup_status: item.cleanup_status,
        cancellation_status: item.cancellation_status,
        eligibility,
    })
}

pub(crate) fn job_details(
    job: ProjectJobDetailsV1,
    eligibility: JobActionEligibility,
) -> Result<JobDetails, CliError> {
    let principal = match job.provider.principal {
        IdeJobPrincipalIdentityV1::User { id, login } => JobPrincipal::User {
            id: id.to_string(),
            login,
        },
        IdeJobPrincipalIdentityV1::RepositoryCredential => JobPrincipal::RepositoryCredential,
    };
    Ok(JobDetails {
        local_job_id: job.local_job_id,
        revision: safe_number(job.revision, "job revision")?,
        provider: JobProviderIdentity {
            name: job.provider.name,
            config_sha256: job.provider.config_sha256,
            principal,
            execution_repository_id: job.provider.execution_repository_id.to_string(),
        },
        provider_job_id: optional_canonical_decimal(job.provider_job_id, "provider job ID")?,
        provider_run_id: optional_canonical_decimal(job.provider_run_id, "provider run ID")?,
        operation_id: job.operation_id,
        request_sha256: job.request_sha256,
        semantic_retry_sha256: job.semantic_retry_sha256,
        application_identifier: job.application_identifier,
        source_revision: job.source_revision,
        source_manifest_sha256: job.source_manifest_sha256,
        target: job.target,
        profile: job.profile,
        signing_mode: job.signing_mode,
        created_at_ms: safe_number(job.created_at_ms, "job creation timestamp")?,
        submitted_at_ms: optional_safe_number(job.submitted_at_ms, "job submission timestamp")?,
        updated_at_ms: safe_number(job.updated_at_ms, "job update timestamp")?,
        state: job.state,
        last_confirmed_state: job.last_confirmed_state,
        terminal_outcome: job.terminal_outcome,
        cleanup_status: job.cleanup_status,
        cancellation_status: job.cancellation_status,
        retry: JobRetryLineage {
            attempt: job.retry.attempt,
            parent_job_id: job.retry.parent_job_id,
            child_job_ids: job.retry.child_job_ids,
        },
        failure: job.failure.map(|failure| JobFailure {
            code: failure.code,
            retryable: failure.retryable,
        }),
        artifact_count: safe_artifact_count(job.artifact_count)?,
        event_journal_bound: job.event_journal_bound,
        provider_resume_available: job.provider_resume_available,
        eligibility,
    })
}

fn safe_artifact_count(value: usize) -> Result<u64, CliError> {
    let value = u64::try_from(value).map_err(|_| {
        ide_contract_error(
            "ide_safe_number_overflow",
            "artifact count exceeds the IDE protocol integer range".to_owned(),
            "Preserve the durable state and use a newer protocol that represents this field without loss.",
        )
    })?;
    safe_number(value, "artifact count")
}

pub(crate) fn job_action_eligibility_for_project(
    store: &JobStore,
    local_job_id: &LocalJobId,
    binding: &IdeJobWorkspaceBinding,
    expected_revision: u64,
) -> Result<JobActionEligibility, CliError> {
    let eligibility = jobs::eligibility_for_project(
        store,
        local_job_id,
        binding.canonical_root(),
        binding.filesystem_identity(),
    )?;
    if eligibility.local_job_id != local_job_id.as_str()
        || eligibility.revision != expected_revision
    {
        return Err(ide_contract_error(
            "job_eligibility_revision_changed",
            "the selected job changed while its action eligibility was inspected".to_owned(),
            "Retry the exact workspace and job selector to read one stable job revision.",
        ));
    }
    Ok(JobActionEligibility {
        can_cancel: eligibility.can_cancel,
        cancel_reason_code: eligibility_reason(
            eligibility.can_cancel,
            eligibility.cancel_reason_code,
            "job cancel eligibility",
        )?,
        can_retry: eligibility.can_retry,
        retry_reason_code: eligibility_reason(
            eligibility.can_retry,
            eligibility.retry_reason_code,
            "job retry eligibility",
        )?,
    })
}

pub(crate) fn job_artifact(
    artifact: IdeJobArtifactV1,
    eligibility: ArtifactActionEligibility,
) -> Result<JobArtifact, CliError> {
    let download_destination = optional_protocol_display_path(
        artifact.download_destination,
        "artifact download destination",
    )?;
    let local_path = optional_protocol_display_path(artifact.local_path, "artifact local path")?;
    Ok(JobArtifact {
        artifact_id: artifact.artifact_id,
        kind: artifact.kind,
        file_name: artifact.file_name,
        size: safe_number(artifact.size, "artifact size")?,
        sha256: artifact.sha256,
        media_type: artifact.media_type,
        download_destination,
        download_parent_identity: artifact.download_parent_identity,
        local_path,
        local_file_identity: artifact.local_file_identity,
        locally_validated: artifact.locally_validated,
        current_status: artifact.current_status,
        eligibility,
    })
}

pub(crate) fn artifact_action_eligibility(
    can_verify: bool,
    verify_reason_code: Option<String>,
    can_reveal: bool,
    reveal_reason_code: Option<String>,
    can_remove: bool,
    remove_reason_code: Option<String>,
) -> Result<ArtifactActionEligibility, CliError> {
    Ok(ArtifactActionEligibility {
        can_verify,
        verify_reason_code: eligibility_reason(
            can_verify,
            verify_reason_code,
            "artifact verify eligibility",
        )?,
        can_reveal,
        reveal_reason_code: eligibility_reason(
            can_reveal,
            reveal_reason_code,
            "artifact reveal eligibility",
        )?,
        can_remove,
        remove_reason_code: eligibility_reason(
            can_remove,
            remove_reason_code,
            "artifact remove eligibility",
        )?,
    })
}

pub(crate) fn eligibility_reason(
    allowed: bool,
    reason_code: Option<String>,
    action: &'static str,
) -> Result<Option<String>, CliError> {
    match (allowed, reason_code) {
        (true, None) => Ok(None),
        (false, Some(code)) => protocol_reason_code(code, action).map(Some),
        _ => Err(ide_contract_error(
            "ide_action_eligibility_invalid",
            format!("{action} returned an incomplete or invalid action eligibility contract"),
            "Preserve the durable record and retry with a server that emits complete bounded action eligibility.",
        )),
    }
}

pub(crate) fn protocol_reason_code(code: String, field: &'static str) -> Result<String, CliError> {
    let mut bytes = code.bytes();
    let valid = code.len() <= 128
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.try_fold(false, |previous_separator, byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
                Some(false)
            } else if matches!(byte, b'.' | b'_' | b'-') && !previous_separator {
                Some(true)
            } else {
                None
            }
        }) == Some(false);
    if valid {
        Ok(code)
    } else {
        Err(ide_contract_error(
            "ide_reason_code_invalid",
            format!("{field} is not a bounded lowercase reason code"),
            "Preserve the durable record and retry with a server that emits bounded stable reason codes.",
        ))
    }
}

pub(crate) fn job_log_event(event: IdeJobLogEventV1) -> Result<JobLogEvent, CliError> {
    if event.record_kind != "sanitized_lifecycle_event" {
        return Err(event_contract_error(
            "job_log_record_kind_invalid",
            "job log record kind",
        ));
    }
    if event.sequence == 0 {
        return Err(event_contract_error(
            "job_log_sequence_invalid",
            "job log sequence",
        ));
    }
    if !matches!(event.source.as_str(), "controller" | "provider" | "worker") {
        return Err(event_contract_error(
            "job_log_source_invalid",
            "job log source",
        ));
    }
    if !matches!(event.level.as_str(), "info" | "warning" | "error") {
        return Err(event_contract_error(
            "job_log_level_invalid",
            "job log level",
        ));
    }
    let source_identity = match (event.source_sequence, event.source_event_sha256) {
        (None, None) if event.source != "worker" => (None, None),
        (Some(sequence), Some(sha256)) if sequence > 0 && valid_sha256(&sha256) => {
            (Some(sequence.to_string()), Some(sha256))
        }
        _ => {
            return Err(event_contract_error(
                "job_log_source_identity_invalid",
                "job log source identity",
            ));
        }
    };
    let phase = event
        .phase
        .map(|phase| bounded_protocol_text(phase, 4_096, "job log phase"))
        .transpose()?;
    let code = bounded_protocol_text(event.code, 4_096, "job log code")?;
    let message = event
        .message
        .map(|message| bounded_protocol_text(message, 16_384, "job log message"))
        .transpose()?;
    Ok(JobLogEvent {
        record_kind: event.record_kind,
        sequence: event.sequence.to_string(),
        occurred_at_ms: safe_number(event.occurred_at_ms, "job log timestamp")?,
        phase,
        source: event.source,
        source_sequence: source_identity.0,
        source_event_sha256: source_identity.1,
        level: event.level,
        code,
        message,
    })
}

fn bounded_protocol_text(
    value: String,
    max_bytes: usize,
    field: &'static str,
) -> Result<String, CliError> {
    if valid_bounded_protocol_text(&value, max_bytes) {
        Ok(value)
    } else {
        Err(event_contract_error("job_log_text_invalid", field))
    }
}

pub(crate) fn valid_bounded_protocol_text(value: &str, max_bytes: usize) -> bool {
    let contains_terminal_control = value.chars().any(|character| {
        let code = character as u32;
        (code < 32 && !matches!(code, 9 | 10 | 13)) || code == 127
    });
    !value.is_empty() && value.len() <= max_bytes && !contains_terminal_control
}

pub(crate) fn valid_protocol_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32_768
        && !value.chars().any(|character| {
            let code = character as u32;
            code < 32 || code == 127
        })
}

fn optional_protocol_display_path(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, CliError> {
    value
        .map(|path| {
            let path = protocol_display_path(Utf8Path::new(&path));
            if valid_protocol_path(&path) {
                Ok(path)
            } else {
                Err(ide_contract_error(
                    "ide_artifact_path_invalid",
                    format!("{field} is not a bounded protocol path"),
                    "Preserve the durable artifact and reconcile its retained path before exposing it to an editor.",
                ))
            }
        })
        .transpose()
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn event_contract_error(code: &'static str, field: &'static str) -> CliError {
    ide_contract_error(
        code,
        format!("{field} does not satisfy the frozen IDE protocol contract"),
        "Preserve the durable journal and reconcile its sanitized event fields before exposing them to an editor.",
    )
}

fn legacy_job_log_event(event: IdeJobLogEventV1) -> Result<LegacyJobLogEvent, CliError> {
    let sequence = event.sequence;
    let source_sequence = event.source_sequence;
    let event = job_log_event(event)?;
    Ok(LegacyJobLogEvent {
        record_kind: event.record_kind,
        sequence: safe_number(sequence, "legacy job log sequence")?,
        occurred_at_ms: event.occurred_at_ms,
        phase: event.phase,
        source: event.source,
        source_sequence: optional_safe_number(source_sequence, "legacy source sequence")?,
        source_event_sha256: event.source_event_sha256,
        level: event.level,
        code: event.code,
        message: event.message,
    })
}

fn ide_contract_error(code: &'static str, message: String, help: &'static str) -> CliError {
    CliError::JobsLifecycle {
        code,
        message,
        help: help.to_owned(),
        details: Vec::new(),
    }
}

fn project_identity_error(message: &str) -> CliError {
    CliError::JobsLifecycle {
        code: "job_workspace_identity_unavailable",
        message: message.to_owned(),
        help: "Keep the project at one canonical local path with stable filesystem identity, then retry."
            .to_owned(),
        details: Vec::new(),
    }
}

/// Discover Apple Development identities without exposing credentials or private keys.
pub fn signing_teams(workspace: &Utf8Path) -> Result<SigningTeamsResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let teams = cargo_ferry::deployment::SigningService::for_team_discovery(
        cargo_ferry::deployment::SystemExecutor,
    )?
    .teams(&root)?
    .into_iter()
    .map(|team| SigningTeam {
        team_id: team.team_id,
        identity: team.identity,
        certificate_fingerprint: team.certificate_fingerprint,
    })
    .collect();
    Ok(SigningTeamsResponse {
        protocol_version: PROTOCOL_VERSION,
        teams,
    })
}

/// Resolve project identity and configuration without parsing human CLI output.
pub fn project(workspace: &Utf8Path) -> Result<ProjectResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    let config = rustferry_core::FerryConfig::load(&config_path)?;
    let targets = crate::commands::platform_build::read_cargo_targets(&root)?;
    let platforms = config
        .platforms
        .iter()
        .map(|platform| match platform {
            rustferry_core::TargetPlatform::Android => "android".to_owned(),
            rustferry_core::TargetPlatform::Ios => "ios".to_owned(),
        })
        .collect();
    Ok(ProjectResponse {
        protocol_version: PROTOCOL_VERSION,
        project: ProjectModel {
            root: protocol_display_path(&root),
            config_path: protocol_display_path(&config_path),
            target_directory: protocol_display_path(&root.join("target/ferry")),
            display_name: config.app.name.clone(),
            crate_name: targets.package,
            identifier: config.app.identifier.clone(),
            version: config.app.version.to_string(),
            display_version: config.app.display_version.clone(),
            platforms,
            capabilities: enabled_capabilities(&config),
            android: serde_json::to_value(&config.android).unwrap_or(Value::Null),
            ios: serde_json::to_value(&config.ios).unwrap_or(Value::Null),
        },
        templates: templates(),
    })
}

/// Validate a project configuration and always return every available diagnostic.
pub fn validate(workspace: &Utf8Path) -> Result<ValidationResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    let source = fs::read_to_string(&config_path).map_err(|source| CliError::Io {
        action: "read configuration for IDE validation",
        path: config_path.clone(),
        source,
    })?;
    validate_resolved_source(&root, &config_path, &source)
}

/// Validate exact editor-owned source while retaining the resolved manifest identity.
pub fn validate_source(workspace: &Utf8Path, source: &str) -> Result<ValidationResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    validate_resolved_source(&root, &config_path, source)
}

fn validate_resolved_source(
    root: &Utf8Path,
    config_path: &Utf8Path,
    source: &str,
) -> Result<ValidationResponse, CliError> {
    let diagnostic_file = protocol_display_path(config_path);
    let mut diagnostics = match rustferry_core::FerryConfig::parse(source) {
        Ok(config) => config
            .validate()
            .into_iter()
            .map(|issue| {
                let range = find_field_range(source, &issue.field);
                Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: format!("ferry.config.{}", issue.field.replace(['.', '_'], "-")),
                    message: issue.message,
                    file: diagnostic_file.clone(),
                    range,
                    help: Some(issue.help),
                    documentation: Some(
                        "https://shiroksh.github.io/rustferry/configuration.html".to_owned(),
                    ),
                    fixes: Vec::new(),
                }
            })
            .collect::<Vec<_>>(),
        Err(rustferry_core::ConfigError::Parse(error)) => vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "ferry.config.parse".to_owned(),
            message: error.message().to_owned(),
            file: diagnostic_file,
            range: span_range(source, error.span()),
            help: Some(
                "Fix the TOML syntax or remove fields not present in the Ferry schema.".to_owned(),
            ),
            documentation: Some(
                "https://shiroksh.github.io/rustferry/configuration.html".to_owned(),
            ),
            fixes: Vec::new(),
        }],
        Err(error) => return Err(CliError::Config(error)),
    };
    diagnostics.sort_by(|left, right| {
        (
            &left.file,
            left.range.start.line,
            left.range.start.character,
            &left.code,
            &left.message,
        )
            .cmp(&(
                &right.file,
                right.range.start.line,
                right.range.start.character,
                &right.code,
                &right.message,
            ))
    });
    Ok(ValidationResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: protocol_display_path(root),
        valid: !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        diagnostics,
    })
}

/// Render an absolute protocol path without Windows' internal verbatim prefix.
pub(crate) fn protocol_display_path(path: &Utf8Path) -> String {
    let value = path.as_str();
    #[cfg(windows)]
    {
        if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(local) = value.strip_prefix(r"\\?\") {
            return local.to_owned();
        }
    }
    value.to_owned()
}

/// Convert a CLI error to a unary protocol response.
pub fn error_response(error: &CliError) -> ProtocolErrorResponse {
    ProtocolErrorResponse {
        protocol_version: PROTOCOL_VERSION,
        error: protocol_error(error),
    }
}

/// Generator-owned template list shared with the project wizard.
pub fn templates() -> Vec<TemplateMetadata> {
    [
        ("starter", "First-hour UI and core APIs"),
        ("minimal", "Smallest real Slint application"),
        ("counter", "State and persistence"),
        ("network", "Offline UI and explicit probes"),
        ("notifications", "Permission and local notification flow"),
        ("widget", "Shared widget snapshot"),
        ("live-activity", "Activity state and Android fallback"),
        ("kitchen-sink", "Capability regression application"),
    ]
    .into_iter()
    .map(|(id, description)| TemplateMetadata {
        id: id.to_owned(),
        description: description.to_owned(),
    })
    .collect()
}

fn enabled_capabilities(config: &rustferry_core::FerryConfig) -> Vec<String> {
    let mut values = Vec::new();
    if config.capabilities.network.mode != rustferry_core::NetworkMode::None {
        values.push("network".to_owned());
    }
    if config.capabilities.notifications.local {
        values.push("notifications".to_owned());
    }
    if config.capabilities.storage.enabled {
        values.push("storage".to_owned());
    }
    if config.capabilities.haptics.enabled {
        values.push("haptics".to_owned());
    }
    if config.capabilities.clipboard.enabled {
        values.push("clipboard".to_owned());
    }
    if !config.capabilities.deep_links.schemes.is_empty() {
        values.push("deep-links".to_owned());
    }
    if config.capabilities.share.enabled {
        values.push("share".to_owned());
    }
    if config.extensions.widget.enabled {
        values.push("widget".to_owned());
    }
    if config.extensions.live_activity.enabled {
        values.push("live-activity".to_owned());
    }
    values
}

fn runtime_dependency_status() -> RuntimeDependencyStatus {
    let Some(raw) = std::env::var_os("CARGO_FERRY_RUNTIME_PATH") else {
        return RuntimeDependencyStatus {
            usable: env!("RUSTFERRY_PACKAGED_SOURCE") == "1"
                && rustferry_runtime_contract::VERSION == env!("CARGO_PKG_VERSION"),
            source: "registry".to_owned(),
        };
    };
    let path = camino::Utf8PathBuf::from_path_buf(raw.into()).ok();
    RuntimeDependencyStatus {
        usable: path.as_ref().is_some_and(|path| {
            path.is_absolute() && path.is_dir() && path.join("Cargo.toml").is_file()
        }),
        source: "path".to_owned(),
    }
}

fn find_field_range(source: &str, field: &str) -> SourceRange {
    let key = field.rsplit('.').next().unwrap_or(field);
    let mut byte_offset = 0;
    for line in source.split_inclusive('\n') {
        let indentation = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key)
            && rest.trim_start().starts_with('=')
        {
            let start = byte_offset + indentation;
            return span_range(source, Some(start..start + key.len()));
        }
        byte_offset += line.len();
    }
    span_range(source, None)
}

fn span_range(source: &str, span: Option<Range<usize>>) -> SourceRange {
    let span = span.unwrap_or(0..0);
    SourceRange {
        start: position_at(source, span.start),
        end: position_at(source, span.end),
    }
}

fn position_at(source: &str, byte_offset: usize) -> Position {
    let offset = byte_offset.min(source.len());
    let offset = (0..=offset)
        .rev()
        .find(|candidate| source.is_char_boundary(*candidate))
        .unwrap_or(0);
    let mut line = 0_u32;
    let mut character = 0_u32;
    for value in source[..offset].chars() {
        if value == '\n' {
            line = line.saturating_add(1);
            character = 0;
        } else {
            character = character.saturating_add(value.len_utf16().try_into().unwrap_or(u32::MAX));
        }
    }
    Position { line, character }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_ranges_are_zero_based_utf16() {
        let source = "[app]\nname = \"🚢\"\nidentifier = \"bad\"\n";
        assert_eq!(
            find_field_range(source, "app.identifier"),
            SourceRange {
                start: Position {
                    line: 2,
                    character: 0,
                },
                end: Position {
                    line: 2,
                    character: 10,
                },
            }
        );
    }

    #[test]
    fn handshake_lists_are_deterministic() {
        let first = serde_json::to_string(&handshake()).unwrap();
        let second = serde_json::to_string(&handshake()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn handshake_co_advertises_the_complete_goal3_command_set() {
        let handshake = handshake();
        for command in [
            "jobs-list",
            "jobs-show",
            "jobs-artifacts",
            "jobs-logs",
            "jobs-logs-page",
            "jobs-cancel",
            "jobs-retry",
            "jobs-artifact-verify",
            "jobs-artifact-reveal",
            "jobs-artifact-remove",
            "remote-build-preview",
            "remote-build-submit",
            "signing-readiness",
        ] {
            assert!(
                handshake
                    .supported_commands
                    .iter()
                    .any(|supported| supported == command),
                "missing {command}"
            );
        }
        assert_eq!(
            handshake
                .supported_commands
                .iter()
                .filter(|command| command.starts_with("remote-build-"))
                .count(),
            2
        );
    }

    #[cfg(windows)]
    #[test]
    fn protocol_paths_hide_windows_verbatim_prefixes() {
        assert_eq!(
            protocol_display_path(Utf8Path::new(r"\\?\C:\workspace\ferry.toml")),
            r"C:\workspace\ferry.toml"
        );
        assert_eq!(
            protocol_display_path(Utf8Path::new(r"\\?\UNC\server\share\ferry.toml")),
            r"\\server\share\ferry.toml"
        );

        let artifact = job_artifact(
            IdeJobArtifactV1 {
                artifact_id: "artifact:1".to_owned(),
                kind: "ipa".to_owned(),
                file_name: "App.ipa".to_owned(),
                size: 1,
                sha256: "a".repeat(64),
                media_type: None,
                download_destination: Some(r"\\?\C:\workspace\App.ipa".to_owned()),
                download_parent_identity: None,
                local_path: Some(r"\\?\UNC\server\share\App.ipa".to_owned()),
                local_file_identity: None,
                locally_validated: true,
                current_status: "retained".to_owned(),
            },
            ArtifactActionEligibility {
                can_verify: false,
                verify_reason_code: Some("unavailable".to_owned()),
                can_reveal: false,
                reveal_reason_code: Some("unavailable".to_owned()),
                can_remove: false,
                remove_reason_code: Some("unavailable".to_owned()),
            },
        )
        .expect("valid artifact wire mapping");
        assert_eq!(
            artifact.download_destination.as_deref(),
            Some(r"C:\workspace\App.ipa")
        );
        assert_eq!(
            artifact.local_path.as_deref(),
            Some(r"\\server\share\App.ipa")
        );
        assert!(!valid_protocol_path("C:\\workspace\ninvalid\npath"));
        assert!(!valid_protocol_path(&"x".repeat(32_769)));
    }

    #[test]
    fn job_log_adapters_reject_incomplete_worker_identity_and_invalid_literals() {
        let worker_without_identity = IdeJobLogEventV1 {
            record_kind: "sanitized_lifecycle_event".to_owned(),
            sequence: 1,
            occurred_at_ms: 1,
            phase: None,
            source: "worker".to_owned(),
            source_sequence: None,
            source_event_sha256: None,
            level: "info".to_owned(),
            code: "worker_started".to_owned(),
            message: None,
        };
        assert_eq!(
            job_log_event(worker_without_identity.clone())
                .expect_err("worker identity must be complete")
                .code(),
            "job_log_source_identity_invalid"
        );
        assert_eq!(
            legacy_job_log_event(worker_without_identity)
                .expect_err("legacy worker identity must be complete")
                .code(),
            "job_log_source_identity_invalid"
        );

        let invalid_source = IdeJobLogEventV1 {
            record_kind: "provider_payload".to_owned(),
            source: "network".to_owned(),
            ..valid_worker_event()
        };
        assert_eq!(
            job_log_event(invalid_source)
                .expect_err("raw provider literals must not escape")
                .code(),
            "job_log_record_kind_invalid"
        );
    }

    #[test]
    fn eligibility_and_safe_numbers_fail_closed() {
        assert!(eligibility_reason(true, None, "cancel").is_ok());
        assert!(eligibility_reason(false, Some("job_terminal".to_owned()), "cancel").is_ok());
        assert_eq!(
            eligibility_reason(true, Some("unexpected".to_owned()), "cancel")
                .expect_err("allowed action reason must be absent")
                .code(),
            "ide_action_eligibility_invalid"
        );
        assert_eq!(
            eligibility_reason(false, None, "cancel")
                .expect_err("unavailable action reason must be present")
                .code(),
            "ide_action_eligibility_invalid"
        );
        assert_eq!(
            safe_number(JAVASCRIPT_MAX_SAFE_INTEGER + 1, "revision")
                .expect_err("unsafe JSON integer must fail")
                .code(),
            "ide_safe_number_overflow"
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            safe_artifact_count(
                usize::try_from(JAVASCRIPT_MAX_SAFE_INTEGER + 1)
                    .expect("64-bit usize holds the negative fixture"),
            )
            .expect_err("unsafe artifact count must fail")
            .code(),
            "ide_safe_number_overflow"
        );
    }

    fn valid_worker_event() -> IdeJobLogEventV1 {
        IdeJobLogEventV1 {
            record_kind: "sanitized_lifecycle_event".to_owned(),
            sequence: 1,
            occurred_at_ms: 1,
            phase: Some("compile".to_owned()),
            source: "worker".to_owned(),
            source_sequence: Some(1),
            source_event_sha256: Some("a".repeat(64)),
            level: "info".to_owned(),
            code: "worker_started".to_owned(),
            message: None,
        }
    }
}
