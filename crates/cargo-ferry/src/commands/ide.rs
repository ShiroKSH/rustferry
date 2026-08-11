//! Machine-only IDE command handlers.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use cargo_ferry::job_store::{JobStore, LocalJobId};
use rustferry_remote::{BuildProfile as RemoteBuildProfile, CancellationToken};

use crate::cli::{
    AndroidBuildArgs, BuildArgs, BuildPlatform, DoctorArgs, IdeArgs, IdeBuildArgs, IdeCheckArgs,
    IdeCommand, IdeDeploymentArgs, IdeDevicePlatform, IdeDevicesArgs, IdeJobArgs,
    IdeJobArtifactArgs, IdeJobArtifactRemoveArgs, IdeJobLogsArgs, IdeJobLogsPageArgs, IdePlatform,
    IdeProfile, IdeSigningReadinessArgs, IosBuildArgs,
};
use crate::commands::artifact::{
    IdeArtifactContainerReceipt, IdeArtifactEvidenceLevel, IdeArtifactProductKind,
    IdeArtifactProductReceipt, IdeArtifactRemoveResult, IdeArtifactSelectionReceipt,
    IdeArtifactVerifyOutcome,
};
use crate::error::CliError;
use crate::ide::protocol::{
    Artifact, Device, DeviceCapabilities, DeviceDiscoveryWarning, DeviceKind, DevicePlatform,
    DeviceSnapshotResponse, DeviceState, DevicectlCapabilities, Diagnostic, DiagnosticSeverity,
    DoctorResponse, EventBody, EventEmitter, PROTOCOL_VERSION, Position, ProtocolError,
    ProtocolErrorResponse, SourceRange, protocol_error, redact_text, schema_value, write_compact,
};
use crate::ide::service;
use crate::output::Reporter;
use crate::project::find_project_root;

pub fn run(arguments: IdeArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        IdeCommand::Handshake => unary(Ok(service::handshake())),
        IdeCommand::Project(arguments) => unary(service::project(&arguments.workspace)),
        IdeCommand::Validate(arguments) => unary(if arguments.manifest_stdin {
            read_manifest_stdin()
                .and_then(|source| service::validate_source(&arguments.workspace, &source))
        } else {
            service::validate(&arguments.workspace)
        }),
        IdeCommand::Doctor(arguments) => {
            let doctor = crate::commands::doctor::inspect(
                &DoctorArgs {
                    all: arguments.all,
                    fix: false,
                },
                dry_run,
                arguments.workspace.as_deref(),
            )
            .and_then(|report| {
                serde_json::to_value(report)
                    .map(|report| DoctorResponse {
                        protocol_version: PROTOCOL_VERSION,
                        report,
                    })
                    .map_err(|source| CliError::Io {
                        action: "serialize IDE doctor response",
                        path: camino::Utf8PathBuf::from("<stdout>"),
                        source: std::io::Error::other(source),
                    })
            });
            unary(doctor)
        }
        IdeCommand::Devices(arguments) if arguments.watch => watch_devices(arguments),
        IdeCommand::Devices(arguments) => unary(discover_devices(arguments.platform)),
        IdeCommand::SigningTeams(arguments) => unary(service::signing_teams(&arguments.workspace)),
        IdeCommand::JobsList(arguments) => {
            unary(service::jobs_list(&arguments.workspace, arguments.limit))
        }
        IdeCommand::JobsShow(arguments) => {
            unary(service::job_show(&arguments.workspace, &arguments.job))
        }
        IdeCommand::JobsArtifacts(arguments) => direct_unary(|| job_artifacts(&arguments)),
        IdeCommand::JobsLogs(arguments) => direct_unary(|| job_logs(&arguments)),
        IdeCommand::JobsLogsPage(arguments) => direct_unary(|| job_logs_page(&arguments)),
        IdeCommand::JobsCancel(arguments) => direct_unary(|| job_cancel(&arguments)),
        IdeCommand::JobsRetry(arguments) => direct_unary(|| job_retry(&arguments)),
        IdeCommand::JobsArtifactVerify(arguments) => direct_unary(|| artifact_verify(&arguments)),
        IdeCommand::JobsArtifactReveal(arguments) => direct_unary(|| artifact_reveal(&arguments)),
        IdeCommand::JobsArtifactRemove(arguments) => direct_unary(|| artifact_remove(&arguments)),
        IdeCommand::RemoteBuildPreview(arguments) => {
            direct_unary(|| remote_build_preview(&arguments))
        }
        IdeCommand::RemoteBuildSubmit(arguments) => {
            direct_unary(|| remote_build_submit(&arguments))
        }
        IdeCommand::SigningReadiness(arguments) => direct_unary(|| signing_readiness(&arguments)),
        IdeCommand::Check(arguments) => check(arguments, dry_run, reporter),
        IdeCommand::Build(arguments) => build(arguments, dry_run, reporter),
        IdeCommand::Install(arguments) => install(&arguments, dry_run, reporter),
        IdeCommand::Run(arguments) => run_application(&arguments, dry_run, reporter),
        IdeCommand::Logs(arguments) => logs(&arguments, dry_run),
        IdeCommand::Schema => {
            let schema = schema_value().map_err(|source| CliError::Io {
                action: "generate IDE protocol schema",
                path: camino::Utf8PathBuf::from("schemas/ide-protocol-v1.schema.json"),
                source: std::io::Error::other(source),
            });
            unary(schema)
        }
    }
}

fn job_logs_page(arguments: &IdeJobLogsPageArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let store = JobStore::open_default_read_only()?;
    let cancellation = ProcessCancellation::new()?;
    let page = super::jobs::logs_page_for_project(
        &store,
        &arguments.job,
        binding.canonical_root(),
        binding.filesystem_identity(),
        arguments.after_sequence,
        arguments.limit,
        arguments.phase.as_deref(),
        arguments.refresh,
        arguments.wait,
        cancellation.token(),
    )?;
    if page.local_job_id != arguments.job.as_str()
        || page.after_sequence != arguments.after_sequence
        || page.limit != arguments.limit
        || page.phase != arguments.phase
        || page.returned != page.events.len()
        || page.returned > page.limit
        || !matches!(
            page.log_scope.as_str(),
            "durable_sanitized_lifecycle_events" | "durable_sanitized_job_events"
        )
        || (page.log_scope == "durable_sanitized_lifecycle_events" && page.provider_full_logs)
    {
        return Err(ide_jobs_contract_error(
            "job_log_page_binding_invalid",
            "the bounded job log page does not bind the exact request and journal scope",
        ));
    }
    let mut previous = arguments.after_sequence;
    let mut events = Vec::with_capacity(page.events.len());
    for event in page.events {
        if event.sequence <= previous {
            return Err(ide_jobs_contract_error(
                "job_log_page_sequence_invalid",
                "job log event sequences do not strictly advance after the request cursor",
            ));
        }
        previous = event.sequence;
        events.push(service::job_log_event(event)?);
    }
    if page.next_after_sequence != previous || (page.has_more && events.is_empty()) {
        return Err(ide_jobs_contract_error(
            "job_log_page_cursor_invalid",
            "the bounded job log page returned an inconsistent next cursor",
        ));
    }
    binding.verify()?;
    unary(Ok(crate::ide::protocol::JobLogsPageResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        local_job_id: page.local_job_id,
        log_scope: page.log_scope,
        provider_full_logs: page.provider_full_logs,
        after_sequence: page.after_sequence.to_string(),
        phase: page.phase,
        limit: page.limit,
        returned: events.len(),
        next_after_sequence: page.next_after_sequence.to_string(),
        has_more: page.has_more,
        terminal: page.terminal,
        events,
    }))
}

fn job_cancel(arguments: &IdeJobArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let store = JobStore::open_default()?;
    let cancellation = ProcessCancellation::new()?;
    let result = super::jobs::cancel_for_project(
        &store,
        &arguments.job,
        binding.canonical_root(),
        binding.filesystem_identity(),
        cancellation.token().clone(),
    )?;
    if !result.durable || result.parent.local_job_id != arguments.job.as_str() {
        return Err(ide_jobs_contract_error(
            "job_cancellation_receipt_invalid",
            "the cancellation result does not bind one durable exact-parent mutation",
        ));
    }
    let eligibility = service::job_action_eligibility_for_project(
        &store,
        &arguments.job,
        &binding,
        result.parent.revision,
    )?;
    binding.verify()?;
    let parent = service::job_details(result.parent, eligibility)?;
    unary(Ok(crate::ide::protocol::JobCancelResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        receipt: crate::ide::protocol::JobCancellationReceipt {
            kind: "cancellation_requested".to_owned(),
            parent_local_job_id: parent.local_job_id.clone(),
            durable: true,
            revision: parent.revision,
        },
        parent,
    }))
}

fn job_retry(arguments: &IdeJobArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let store = JobStore::open_default()?;
    let cancellation = ProcessCancellation::new()?;
    let result = super::jobs::retry_for_project(
        &store,
        &arguments.job,
        binding.canonical_root(),
        binding.filesystem_identity(),
        cancellation.token().clone(),
    )?;
    let parent_attempt = result.parent.retry.attempt;
    let child_attempt = result.child.retry.attempt;
    if !result.durable
        || result.parent.local_job_id != arguments.job.as_str()
        || result.parent.local_job_id == result.child.local_job_id
        || result.parent.revision != result.parent_revision
        || result.child.revision != result.child_revision
        || result.child.retry.parent_job_id.as_deref() != Some(result.parent.local_job_id.as_str())
        || !retry_attempt_advances(parent_attempt, child_attempt)
        || result.parent.semantic_retry_sha256 != result.child.semantic_retry_sha256
        || result.parent.source_manifest_sha256 != result.child.source_manifest_sha256
        || !result
            .parent
            .retry
            .child_job_ids
            .contains(&result.child.local_job_id)
        || result.child_created == result.resumed_existing_child
    {
        return Err(ide_jobs_contract_error(
            "job_retry_receipt_invalid",
            "the retry result does not bind one distinct exact parent/child lineage",
        ));
    }
    let child_local_job_id = LocalJobId::new(result.child.local_job_id.clone()).map_err(|_| {
        ide_jobs_contract_error(
            "job_retry_child_identity_invalid",
            "the durable retry returned an invalid child job identity",
        )
    })?;
    let parent_eligibility = service::job_action_eligibility_for_project(
        &store,
        &arguments.job,
        &binding,
        result.parent.revision,
    )?;
    let child_eligibility = service::job_action_eligibility_for_project(
        &store,
        &child_local_job_id,
        &binding,
        result.child.revision,
    )?;
    binding.verify()?;
    let parent = service::job_details(result.parent, parent_eligibility)?;
    let child = service::job_details(result.child, child_eligibility)?;
    let disposition = if result.child_created {
        "created"
    } else {
        "resumed_existing"
    };
    unary(Ok(crate::ide::protocol::JobRetryResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        lineage: crate::ide::protocol::JobRetryBinding {
            parent_local_job_id: parent.local_job_id.clone(),
            child_local_job_id: child.local_job_id.clone(),
            attempt: child.retry.attempt,
        },
        receipt: crate::ide::protocol::JobRetryReceipt {
            kind: "retry_created".to_owned(),
            durable: true,
            disposition: disposition.to_owned(),
        },
        parent,
        child,
    }))
}

const fn retry_attempt_advances(parent_attempt: u32, child_attempt: u32) -> bool {
    matches!(parent_attempt.checked_add(1), Some(expected) if expected == child_attempt)
}

fn ide_jobs_contract_error(code: &'static str, message: &'static str) -> CliError {
    CliError::JobsLifecycle {
        code,
        message: message.to_owned(),
        help: "Preserve the durable job state and retry the exact workspace-bound operation."
            .to_owned(),
        details: Vec::new(),
    }
}

fn signing_readiness(arguments: &IdeSigningReadinessArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let readiness = super::platform_build::ide_signing_readiness(camino::Utf8Path::new(
        binding.canonical_root(),
    ))?;
    if readiness.checks.is_empty() || readiness.checks.len() > 64 {
        return Err(CliError::JobsLifecycle {
            code: "signing_readiness_checks_invalid",
            message: "signing readiness returned an invalid number of sanitized checks".to_owned(),
            help: "Keep the project configuration stable and retry with a compatible server."
                .to_owned(),
            details: Vec::new(),
        });
    }
    let checks = readiness
        .checks
        .into_iter()
        .map(|check| {
            Ok(crate::ide::protocol::SigningReadinessCheck {
                code: service::protocol_reason_code(check.code, "signing readiness check code")?,
                required: check.required,
                ready: check.ready,
                reason_code: service::eligibility_reason(
                    check.ready,
                    check.reason_code.map(ToOwned::to_owned),
                    "signing readiness check",
                )?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let computed_ready = checks.iter().all(|check| !check.required || check.ready);
    if readiness.ready != computed_ready {
        return Err(CliError::JobsLifecycle {
            code: "signing_readiness_summary_invalid",
            message: "signing readiness does not match its required sanitized checks".to_owned(),
            help: "Keep the project configuration stable and retry with a compatible server."
                .to_owned(),
            details: Vec::new(),
        });
    }
    binding.verify()?;
    unary(Ok(crate::ide::protocol::SigningReadinessResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        provider: "github".to_owned(),
        target: "ios-device".to_owned(),
        mode: "github_actions_ios_signing".to_owned(),
        ready: readiness.ready,
        checks,
    }))
}

fn job_artifacts(arguments: &IdeJobArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let store = JobStore::open_default_read_only()?;
    let result = super::jobs::artifacts_for_project(
        &store,
        &arguments.job,
        binding.canonical_root(),
        binding.filesystem_identity(),
    )?;
    if result.local_job_id != arguments.job.as_str() {
        return Err(ide_jobs_contract_error(
            "artifact_job_binding_invalid",
            "the artifact list does not bind the exact requested job",
        ));
    }
    let mut artifacts = Vec::with_capacity(result.artifacts.len());
    for artifact in result.artifacts {
        let eligibility = super::artifact::ide_artifact_eligibility_for_project(
            binding.canonical_root(),
            binding.filesystem_identity(),
            &arguments.job,
            &artifact.artifact_id,
        )?;
        let eligibility = service::artifact_action_eligibility(
            eligibility.can_verify,
            eligibility.verify_reason_code,
            eligibility.can_reveal,
            eligibility.reveal_reason_code,
            eligibility.can_remove,
            eligibility.remove_reason_code,
        )?;
        artifacts.push(service::job_artifact(artifact, eligibility)?);
    }
    let latest = super::jobs::show_for_project(
        &store,
        &arguments.job,
        binding.canonical_root(),
        binding.filesystem_identity(),
    )?;
    if latest.local_job_id != arguments.job.as_str() || latest.revision != result.revision {
        return Err(CliError::JobsLifecycle {
            code: "artifact_job_revision_changed",
            message: "the selected job changed while artifact eligibility was inspected".to_owned(),
            help:
                "Retry the exact workspace and job selector to read one stable artifact snapshot."
                    .to_owned(),
            details: Vec::new(),
        });
    }
    binding.verify()?;
    unary(Ok(crate::ide::protocol::JobArtifactsResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        local_job_id: result.local_job_id,
        revision: service::safe_number(result.revision, "job revision")?,
        artifacts,
    }))
}

fn remote_build_preview(arguments: &crate::cli::IdeRemoteBuildPreviewArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let profile = remote_build_profile(arguments.profile);
    let preview = super::platform_build::ide_snapshot_preview(
        camino::Utf8Path::new(binding.canonical_root()),
        profile,
    )?;
    let valid_token = (32..=512).contains(&preview.consent_token.len())
        && preview
            .consent_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_token
        || !service::valid_sha256(&preview.preview_sha256)
        || !service::valid_sha256(&preview.source_manifest_sha256)
        || preview.effects.is_empty()
        || preview.effects.len() > 64
        || preview
            .effects
            .iter()
            .any(|effect| !service::valid_bounded_protocol_text(effect, 4_096))
    {
        return Err(ide_consent_error(
            "remote_build_preview_invalid",
            "the zero-write preview does not satisfy the frozen IDE contract",
        ));
    }
    binding.verify()?;
    unary(Ok(crate::ide::protocol::RemoteBuildPreviewResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        provider: "github".to_owned(),
        target: "ios-device".to_owned(),
        profile: remote_build_profile_name(profile).to_owned(),
        signing_mode: "unsigned".to_owned(),
        source_mode: "snapshot".to_owned(),
        preview_sha256: preview.preview_sha256,
        consent_token: preview.consent_token,
        source: crate::ide::protocol::RemoteBuildPreviewSource {
            manifest_sha256: preview.source_manifest_sha256,
            file_count: preview.file_count.to_string(),
            total_bytes: preview.total_bytes.to_string(),
        },
        effects: preview.effects,
        consent_required: true,
    }))
}

fn remote_build_submit(arguments: &crate::cli::IdeRemoteBuildSubmitArgs) -> Result<(), CliError> {
    let consent = read_remote_build_consent()?;
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let cancellation = ProcessCancellation::new()?;
    let submission = super::platform_build::ide_snapshot_submit(
        camino::Utf8Path::new(binding.canonical_root()),
        &super::platform_build::IdeSnapshotConsent {
            token: consent.consent_token,
            preview_sha256: consent.preview_sha256.clone(),
            approved: consent.approved,
        },
        cancellation.token(),
    )?;
    binding.verify()?;
    if submission.preview_sha256 != consent.preview_sha256 {
        return Err(ide_consent_error(
            "remote_build_consent_mismatch",
            "the durable snapshot submission does not bind the approved preview digest",
        ));
    }
    let local_job_id = LocalJobId::new(submission.local_job_id.clone()).map_err(|_| {
        ide_consent_error(
            "remote_build_job_identity_invalid",
            "the durable snapshot submission returned an invalid local job identity",
        )
    })?;
    let store = JobStore::open_default_read_only()?;
    let job = super::jobs::show_for_project(
        &store,
        &local_job_id,
        binding.canonical_root(),
        binding.filesystem_identity(),
    )?;
    let eligibility =
        service::job_action_eligibility_for_project(&store, &local_job_id, &binding, job.revision)?;
    binding.verify()?;
    if job.local_job_id != submission.local_job_id
        || job.revision != submission.revision
        || job.source_manifest_sha256 != submission.source_manifest_sha256
        || job.profile != remote_build_profile_name(submission.profile)
    {
        return Err(ide_consent_error(
            "remote_build_job_identity_mismatch",
            "the durable snapshot job changed before its IDE receipt was bound",
        ));
    }
    let job = service::job_details(job, eligibility)?;
    if job.provider.name != "github"
        || job.target != "iphone"
        || job.signing_mode != "unsigned-compile-only"
    {
        return Err(ide_consent_error(
            "remote_build_job_identity_mismatch",
            "the durable snapshot job does not match the approved provider, target, and signing mode",
        ));
    }
    unary(Ok(crate::ide::protocol::RemoteBuildSubmissionResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        job,
        receipt: crate::ide::protocol::RemoteBuildSubmissionReceipt {
            kind: "remote_build_submitted".to_owned(),
            durable: true,
            source_mode: "snapshot".to_owned(),
            preview_sha256: submission.preview_sha256,
        },
    }))
}

const fn remote_build_profile(profile: IdeProfile) -> RemoteBuildProfile {
    match profile {
        IdeProfile::Debug => RemoteBuildProfile::Debug,
        IdeProfile::Release => RemoteBuildProfile::Release,
    }
}

const fn remote_build_profile_name(profile: RemoteBuildProfile) -> &'static str {
    match profile {
        RemoteBuildProfile::Debug => "debug",
        RemoteBuildProfile::Release => "release",
    }
}

struct ProcessCancellation {
    token: CancellationToken,
    stopped: Arc<AtomicBool>,
    monitor: Option<JoinHandle<()>>,
}

impl ProcessCancellation {
    fn new() -> Result<Self, CliError> {
        let token = CancellationToken::new();
        if rustferry_core::process_control::interrupt_requested() {
            token.cancel();
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let monitor_token = token.clone();
        let monitor_stopped = Arc::clone(&stopped);
        let monitor = std::thread::Builder::new()
            .name("rustferry-ide-cancellation".to_owned())
            .spawn(move || {
                while !monitor_stopped.load(Ordering::Acquire) {
                    if rustferry_core::process_control::interrupt_requested() {
                        monitor_token.cancel();
                        break;
                    }
                    std::thread::park_timeout(Duration::from_millis(25));
                }
            })
            .map_err(|source| CliError::Io {
                action: "start IDE cancellation monitor",
                path: camino::Utf8PathBuf::from("<process>"),
                source,
            })?;
        Ok(Self {
            token,
            stopped,
            monitor: Some(monitor),
        })
    }

    const fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for ProcessCancellation {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(monitor) = self.monitor.take() {
            monitor.thread().unpark();
            let _ = monitor.join();
        }
    }
}

fn artifact_verify(arguments: &IdeJobArtifactArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let receipt = super::artifact::ide_verify_for_project(
        binding.canonical_root(),
        binding.filesystem_identity(),
        &arguments.job,
        &arguments.artifact,
    )?;
    validate_artifact_selection(&receipt.artifact, &arguments.job, &arguments.artifact)?;
    let product_evidence_unavailable = matches!(
        &receipt.product,
        IdeArtifactProductReceipt::EvidenceUnavailable { .. }
    );
    if matches!(
        receipt.outcome,
        IdeArtifactVerifyOutcome::EvidenceUnavailable
    ) != product_evidence_unavailable
        || !service::valid_sha256(&receipt.integrity.sha256)
        || !service::valid_bounded_protocol_text(&receipt.integrity.filesystem_identity, 4_096)
        || receipt
            .validation_levels
            .iter()
            .any(|level| !service::valid_bounded_protocol_text(level, 4_096))
    {
        return Err(ide_artifact_contract_error(
            "artifact verification evidence does not satisfy the frozen IDE contract",
        ));
    }
    binding.verify()?;
    let identity = crate::ide::protocol::ArtifactActionIdentity {
        protocol_version: PROTOCOL_VERSION,
        workspace: binding.requested().to_owned(),
        local_job_id: receipt.artifact.local_job_id,
        artifact_id: receipt.artifact.artifact_id,
        revision: service::safe_number(receipt.artifact.revision, "artifact job revision")?,
    };
    let outcome = match receipt.outcome {
        IdeArtifactVerifyOutcome::Verified => "verified",
        IdeArtifactVerifyOutcome::EvidenceUnavailable => "evidence_unavailable",
    }
    .to_owned();
    let evidence_level = match receipt.evidence_level {
        IdeArtifactEvidenceLevel::Integrity => "integrity",
        IdeArtifactEvidenceLevel::ArchiveSafety => "archive_safety",
        IdeArtifactEvidenceLevel::Product => "product",
        IdeArtifactEvidenceLevel::CrossValidated => "cross_validated",
    }
    .to_owned();
    let container = match receipt.integrity.container {
        IdeArtifactContainerReceipt::Opaque => {
            crate::ide::protocol::ArtifactContainerEvidence::Opaque
        }
        IdeArtifactContainerReceipt::Zip {
            entry_count,
            expanded_size,
        } => crate::ide::protocol::ArtifactContainerEvidence::Zip {
            entry_count: entry_count.to_string(),
            expanded_size: expanded_size.to_string(),
        },
    };
    let product = match receipt.product {
        IdeArtifactProductReceipt::Verified { kind } => {
            crate::ide::protocol::ArtifactProductEvidence::Verified {
                kind: match kind {
                    IdeArtifactProductKind::UnsignedXcarchive => "unsigned_xcarchive",
                    IdeArtifactProductKind::Ipa => "ipa",
                    IdeArtifactProductKind::SignedArtifactSet => "signed_artifact_set",
                }
                .to_owned(),
            }
        }
        IdeArtifactProductReceipt::NotApplicable => {
            crate::ide::protocol::ArtifactProductEvidence::NotApplicable
        }
        IdeArtifactProductReceipt::EvidenceUnavailable { reason_code } => {
            crate::ide::protocol::ArtifactProductEvidence::EvidenceUnavailable {
                reason_code: service::protocol_reason_code(
                    reason_code.to_owned(),
                    "artifact evidence reason",
                )?,
            }
        }
    };
    unary(Ok(crate::ide::protocol::ArtifactVerifyResponse {
        identity,
        status: outcome.clone(),
        outcome,
        evidence_level,
        integrity: crate::ide::protocol::ArtifactIntegrityEvidence {
            size: receipt.integrity.size.to_string(),
            sha256: receipt.integrity.sha256,
            filesystem_identity: receipt.integrity.filesystem_identity,
            container,
        },
        product,
        validation_levels: receipt.validation_levels,
        signed_cleanup_evidence_bound: receipt.signed_cleanup_evidence_bound,
    }))
}

fn artifact_reveal(arguments: &IdeJobArtifactArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let receipt = super::artifact::ide_reveal_for_project(
        binding.canonical_root(),
        binding.filesystem_identity(),
        &arguments.job,
        &arguments.artifact,
    )?;
    validate_artifact_selection(&receipt.artifact, &arguments.job, &arguments.artifact)?;
    if receipt.environment_policy != "fixed_no_inheritance"
        || !receipt.launch_requested
        || receipt.post_launch_revalidation != "passed"
        || !service::valid_bounded_protocol_text(&receipt.launcher, 4_096)
    {
        return Err(ide_artifact_contract_error(
            "artifact reveal receipt does not satisfy the frozen IDE contract",
        ));
    }
    binding.verify()?;
    unary(Ok(crate::ide::protocol::ArtifactRevealResponse {
        identity: crate::ide::protocol::ArtifactActionIdentity {
            protocol_version: PROTOCOL_VERSION,
            workspace: binding.requested().to_owned(),
            local_job_id: receipt.artifact.local_job_id,
            artifact_id: receipt.artifact.artifact_id,
            revision: service::safe_number(receipt.artifact.revision, "artifact job revision")?,
        },
        receipt: crate::ide::protocol::ArtifactRevealReceipt {
            launcher: receipt.launcher,
            environment_policy: receipt.environment_policy.to_owned(),
            launch_requested: receipt.launch_requested,
            exact_path_bound_during_launch: receipt.exact_path_bound_during_launch,
            post_launch_revalidation: receipt.post_launch_revalidation.to_owned(),
        },
        status: "revealed".to_owned(),
    }))
}

fn artifact_remove(arguments: &IdeJobArtifactRemoveArgs) -> Result<(), CliError> {
    let binding = service::IdeJobWorkspaceBinding::capture(&arguments.workspace)?;
    let receipt = super::artifact::ide_remove_for_project(
        binding.canonical_root(),
        binding.filesystem_identity(),
        &arguments.job,
        &arguments.artifact,
        arguments.yes,
    )?;
    validate_artifact_selection(&receipt.artifact, &arguments.job, &arguments.artifact)?;
    let consistent = match receipt.result_state {
        IdeArtifactRemoveResult::Removed => {
            receipt.executed && !receipt.already_complete && !receipt.replacement_preserved
        }
        IdeArtifactRemoveResult::AlreadyRemoved => {
            !receipt.executed && receipt.already_complete && !receipt.replacement_preserved
        }
        IdeArtifactRemoveResult::ReplacementPreserved => {
            !receipt.executed && !receipt.already_complete && receipt.replacement_preserved
        }
    };
    if !receipt.confirmation_provided || !consistent {
        return Err(ide_artifact_contract_error(
            "artifact removal receipt does not satisfy the frozen IDE contract",
        ));
    }
    binding.verify()?;
    let status = match receipt.result_state {
        IdeArtifactRemoveResult::Removed => "removed",
        IdeArtifactRemoveResult::AlreadyRemoved => "already_removed",
        IdeArtifactRemoveResult::ReplacementPreserved => "replacement_preserved",
    }
    .to_owned();
    unary(Ok(crate::ide::protocol::ArtifactRemoveResponse {
        identity: crate::ide::protocol::ArtifactActionIdentity {
            protocol_version: PROTOCOL_VERSION,
            workspace: binding.requested().to_owned(),
            local_job_id: receipt.artifact.local_job_id,
            artifact_id: receipt.artifact.artifact_id,
            revision: service::safe_number(receipt.artifact.revision, "artifact job revision")?,
        },
        receipt: crate::ide::protocol::ArtifactRemoveReceipt {
            confirmation_provided: receipt.confirmation_provided,
            executed: receipt.executed,
            result_state: status.clone(),
            already_complete: receipt.already_complete,
            replacement_preserved: receipt.replacement_preserved,
        },
        status,
        replacement_preserved: receipt.replacement_preserved,
    }))
}

fn validate_artifact_selection(
    selection: &IdeArtifactSelectionReceipt,
    local_job_id: &LocalJobId,
    artifact_id: &str,
) -> Result<(), CliError> {
    if selection.local_job_id == local_job_id.as_str() && selection.artifact_id == artifact_id {
        Ok(())
    } else {
        Err(ide_artifact_contract_error(
            "artifact action receipt does not bind the exact job and artifact selector",
        ))
    }
}

fn ide_artifact_contract_error(message: &'static str) -> CliError {
    CliError::JobsLifecycle {
        code: "artifact_action_receipt_invalid",
        message: message.to_owned(),
        help: "Preserve the retained artifact and retry the exact workspace, job, and artifact selector."
            .to_owned(),
        details: Vec::new(),
    }
}

fn job_logs(arguments: &IdeJobLogsArgs) -> Result<(), CliError> {
    unary(service::job_logs(
        &arguments.workspace,
        &arguments.job,
        arguments.since,
        arguments.phase.as_deref(),
    ))
}

const IDE_MANIFEST_STDIN_LIMIT: usize = 1024 * 1024;
const IDE_CONSENT_STDIN_LIMIT: usize = 16 * 1024;

fn read_manifest_stdin() -> Result<String, CliError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((IDE_MANIFEST_STDIN_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read IDE manifest input",
            path: camino::Utf8PathBuf::from("<stdin>"),
            source,
        })?;
    if bytes.len() > IDE_MANIFEST_STDIN_LIMIT {
        return Err(CliError::IdeManifestInputTooLarge {
            limit_bytes: IDE_MANIFEST_STDIN_LIMIT,
        });
    }
    String::from_utf8(bytes).map_err(|_| CliError::IdeManifestInputInvalidUtf8)
}

fn read_remote_build_consent() -> Result<crate::ide::protocol::RemoteBuildConsent, CliError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((IDE_CONSENT_STDIN_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read IDE remote-build consent",
            path: camino::Utf8PathBuf::from("<stdin>"),
            source,
        })?;
    if bytes.len() > IDE_CONSENT_STDIN_LIMIT {
        return Err(ide_consent_error(
            "remote_build_consent_too_large",
            "the IDE remote-build consent exceeds the bounded input size",
        ));
    }
    let consent = serde_json::from_slice::<crate::ide::protocol::RemoteBuildConsent>(&bytes)
        .map_err(|_| {
            ide_consent_error(
                "remote_build_consent_invalid",
                "the IDE remote-build consent is not the exact versioned JSON object",
            )
        })?;
    let valid_token = (32..=512).contains(&consent.consent_token.len())
        && consent
            .consent_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    let valid_sha = consent.preview_sha256.len() == 64
        && consent
            .preview_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !consent.approved || !valid_token || !valid_sha {
        return Err(ide_consent_error(
            "remote_build_consent_invalid",
            "the IDE remote-build consent is missing its exact approval, token, or preview digest",
        ));
    }
    Ok(consent)
}

fn ide_consent_error(code: &'static str, message: &'static str) -> CliError {
    CliError::JobsLifecycle {
        code,
        message: message.to_owned(),
        help: "Request a new zero-write preview and approve only its exact current consent object."
            .to_owned(),
        details: Vec::new(),
    }
}

fn discover_devices(platform: IdeDevicePlatform) -> Result<DeviceSnapshotResponse, CliError> {
    let current_directory = current_directory()?;
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        current_directory,
    )
    .discover(device_filter(platform));
    Ok(snapshot_response(snapshot))
}

fn watch_devices(arguments: IdeDevicesArgs) -> Result<(), CliError> {
    let emitter = match EventEmitter::new(arguments.operation_id, arguments.parent_operation_id) {
        Ok(emitter) => emitter,
        Err(error) => {
            write_compact(&ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            })
            .map_err(stdout_error)?;
            return Err(CliError::AlreadyReported { exit_code: 2 });
        }
    };
    let current_directory = current_directory()?;
    let service = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        current_directory,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "devices.watch".to_owned(),
            workspace: None,
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Discovering connected devices".to_owned()),
        },
    )?;
    let filter = device_filter(arguments.platform);
    let mut previous = service.discover(filter);
    emit_snapshot(&emitter, &previous)?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    let interval = std::time::Duration::from_millis(arguments.interval_ms.clamp(500, 60_000));
    loop {
        if sleep_until_refresh(interval) {
            emit(
                &emitter,
                EventBody::OperationCancelled {
                    reason: "requested".to_owned(),
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            return Err(CliError::AlreadyReported { exit_code: 130 });
        }
        let current = service.discover(filter);
        for delta in current.changes_since(&previous) {
            match delta.kind {
                cargo_ferry::deployment::DeviceDeltaKind::Added
                | cargo_ferry::deployment::DeviceDeltaKind::Changed => emit(
                    &emitter,
                    EventBody::Device {
                        device: protocol_device(delta.device),
                    },
                )?,
                cargo_ferry::deployment::DeviceDeltaKind::Removed => emit(
                    &emitter,
                    EventBody::DeviceRemoved {
                        device_id: delta.device.id,
                    },
                )?,
            }
        }
        if current.warnings != previous.warnings {
            emit_warnings(&emitter, &current.warnings)?;
        }
        previous = current;
    }
}

fn emit_snapshot(
    emitter: &EventEmitter,
    snapshot: &cargo_ferry::deployment::DeviceSnapshot,
) -> Result<(), CliError> {
    for device in snapshot.devices.iter().cloned() {
        emit(
            emitter,
            EventBody::Device {
                device: protocol_device(device),
            },
        )?;
    }
    emit_warnings(emitter, &snapshot.warnings)
}

fn emit_warnings(
    emitter: &EventEmitter,
    warnings: &[cargo_ferry::deployment::DiscoveryWarning],
) -> Result<(), CliError> {
    for warning in warnings {
        emit(
            emitter,
            EventBody::Warning {
                code: warning.code.clone(),
                message: format!("{}: {}", warning.source, warning.message),
                help: None,
            },
        )?;
    }
    Ok(())
}

fn sleep_until_refresh(interval: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < interval {
        if rustferry_core::process_control::interrupt_requested() {
            return true;
        }
        std::thread::sleep(
            interval
                .saturating_sub(started.elapsed())
                .min(std::time::Duration::from_millis(100)),
        );
    }
    rustferry_core::process_control::interrupt_requested()
}

const fn device_filter(platform: IdeDevicePlatform) -> cargo_ferry::deployment::DeviceFilter {
    match platform {
        IdeDevicePlatform::All => cargo_ferry::deployment::DeviceFilter::All,
        IdeDevicePlatform::Android => cargo_ferry::deployment::DeviceFilter::Android,
        IdeDevicePlatform::Ios => cargo_ferry::deployment::DeviceFilter::Ios,
    }
}

fn snapshot_response(snapshot: cargo_ferry::deployment::DeviceSnapshot) -> DeviceSnapshotResponse {
    DeviceSnapshotResponse {
        protocol_version: PROTOCOL_VERSION,
        devices: snapshot.devices.into_iter().map(protocol_device).collect(),
        warnings: snapshot
            .warnings
            .into_iter()
            .map(|warning| DeviceDiscoveryWarning {
                code: warning.code,
                source: warning.source,
                message: warning.message,
            })
            .collect(),
        devicectl: DevicectlCapabilities {
            available: snapshot.devicectl.available,
            json_output: snapshot.devicectl.json_output,
            install: snapshot.devicectl.install,
            launch: snapshot.devicectl.launch,
            logs: snapshot.devicectl.logs,
        },
    }
}

pub(crate) fn protocol_device(device: cargo_ferry::deployment::Device) -> Device {
    Device {
        id: device.id,
        name: device.name,
        platform: match device.platform {
            cargo_ferry::deployment::DevicePlatform::Android => DevicePlatform::Android,
            cargo_ferry::deployment::DevicePlatform::Ios => DevicePlatform::Ios,
        },
        kind: match device.kind {
            cargo_ferry::deployment::DeviceKind::AndroidPhysical => DeviceKind::AndroidPhysical,
            cargo_ferry::deployment::DeviceKind::AndroidEmulator => DeviceKind::AndroidEmulator,
            cargo_ferry::deployment::DeviceKind::IosSimulator => DeviceKind::IosSimulator,
            cargo_ferry::deployment::DeviceKind::IosPhysical => DeviceKind::IosPhysical,
        },
        state: match device.state {
            cargo_ferry::deployment::DeviceState::Online => DeviceState::Online,
            cargo_ferry::deployment::DeviceState::Booted => DeviceState::Booted,
            cargo_ferry::deployment::DeviceState::Shutdown => DeviceState::Shutdown,
            cargo_ferry::deployment::DeviceState::Offline => DeviceState::Offline,
            cargo_ferry::deployment::DeviceState::Unauthorized => DeviceState::Unauthorized,
            cargo_ferry::deployment::DeviceState::Unavailable => DeviceState::Unavailable,
            cargo_ferry::deployment::DeviceState::Disconnected => DeviceState::Disconnected,
            cargo_ferry::deployment::DeviceState::Unknown => DeviceState::Unknown,
        },
        os_version: device.os_version,
        architecture: device.architecture,
        transport: device.transport,
        paired: device.paired,
        trusted: device.trusted,
        capabilities: DeviceCapabilities {
            build: device.capabilities.build,
            install: device.capabilities.install,
            launch: device.capabilities.launch,
            logs: device.capabilities.logs,
        },
        details: device.details,
    }
}

fn current_directory() -> Result<camino::Utf8PathBuf, CliError> {
    camino::Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| CliError::Io {
        action: "read current directory for device discovery",
        path: camino::Utf8PathBuf::from("."),
        source,
    })?)
    .map_err(CliError::NonUtf8Path)
}

/// Write a bootstrap argument error before Clap can construct an IDE command.
pub fn write_argument_error(message: &str) -> std::io::Result<()> {
    write_compact(&ProtocolErrorResponse {
        protocol_version: PROTOCOL_VERSION,
        error: ProtocolError {
            code: "invalid_arguments".to_owned(),
            message: crate::ide::protocol::redact_text(message),
            help: Some("Run `cargo ferry ide --help` for valid arguments.".to_owned()),
            details: Vec::new(),
        },
    })
}

fn unary<T: serde::Serialize>(result: Result<T, CliError>) -> Result<(), CliError> {
    match result {
        Ok(value) => write_compact(&value).map_err(stdout_error),
        Err(error) => {
            let exit_code = error.exit_code();
            write_compact(&service::error_response(&error)).map_err(stdout_error)?;
            Err(CliError::AlreadyReported { exit_code })
        }
    }
}

fn direct_unary(operation: impl FnOnce() -> Result<(), CliError>) -> Result<(), CliError> {
    match operation() {
        Err(error) if !error.is_already_reported() => unary::<serde_json::Value>(Err(error)),
        result => result,
    }
}

fn check(arguments: IdeCheckArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let emitter = stream_emitter(arguments.operation_id, arguments.parent_operation_id)?;
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "check".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "rust_check".to_owned(),
            message: Some(
                if dry_run {
                    "Planning Rust source validation"
                } else {
                    "Checking Rust sources and collecting diagnostics"
                }
                .to_owned(),
            ),
        },
    )?;
    if !dry_run {
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: "cargo".to_owned(),
                arguments: vec![
                    "check".to_owned(),
                    "--all-targets".to_owned(),
                    "--message-format=json".to_owned(),
                ],
            },
        )?;
    }
    match crate::commands::check::check_project_structured(&root, dry_run, reporter) {
        Ok(outcome) => {
            for diagnostic in outcome.diagnostics {
                emit(&emitter, EventBody::Diagnostic { diagnostic })?;
            }
            emit(
                &emitter,
                EventBody::PhaseFinished {
                    phase: "rust_check".to_owned(),
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            emit(
                &emitter,
                EventBody::OperationFinished {
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                    error: None,
                },
            )?;
            Ok(())
        }
        Err(failure) => {
            let has_structured_diagnostics = !failure.diagnostics.is_empty();
            for diagnostic in failure.diagnostics {
                emit(&emitter, EventBody::Diagnostic { diagnostic })?;
            }
            let failure = (*failure.error).into();
            if has_structured_diagnostics {
                finish_failure_after_diagnostics(&emitter, Some("rust_check"), failure)
            } else {
                finish_failure(
                    &emitter,
                    root.join("ferry.toml").as_str(),
                    Some("rust_check"),
                    failure,
                )
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn build(arguments: IdeBuildArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let emitter = match EventEmitter::new(arguments.operation_id, arguments.parent_operation_id) {
        Ok(emitter) => emitter,
        Err(error) => {
            let response = ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            };
            write_compact(&response).map_err(stdout_error)?;
            return Err(CliError::AlreadyReported { exit_code: 2 });
        }
    };
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "build".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "build".to_owned(),
            message: Some("Building and validating mobile artifact".to_owned()),
        },
    )?;
    if !dry_run {
        emit(
            &emitter,
            EventBody::PhaseStarted {
                phase: "rust_check".to_owned(),
                message: Some("Checking Rust sources and collecting diagnostics".to_owned()),
            },
        )?;
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: "cargo".to_owned(),
                arguments: vec![
                    "check".to_owned(),
                    "--all-targets".to_owned(),
                    "--message-format=json".to_owned(),
                ],
            },
        )?;
        match crate::commands::check::check_project_structured(&root, false, reporter) {
            Ok(outcome) => {
                for diagnostic in outcome.diagnostics {
                    emit(&emitter, EventBody::Diagnostic { diagnostic })?;
                }
                emit(
                    &emitter,
                    EventBody::PhaseFinished {
                        phase: "rust_check".to_owned(),
                        success: true,
                        duration_ms: emitter.elapsed_ms(),
                    },
                )?;
            }
            Err(failure) => {
                let has_structured_diagnostics = !failure.diagnostics.is_empty();
                for diagnostic in failure.diagnostics {
                    emit(&emitter, EventBody::Diagnostic { diagnostic })?;
                }
                emit(
                    &emitter,
                    EventBody::PhaseFinished {
                        phase: "rust_check".to_owned(),
                        success: false,
                        duration_ms: emitter.elapsed_ms(),
                    },
                )?;
                let failure = (*failure.error).into();
                return if has_structured_diagnostics {
                    finish_failure_after_diagnostics(&emitter, Some("build"), failure)
                } else {
                    finish_failure(
                        &emitter,
                        root.join("ferry.toml").as_str(),
                        Some("build"),
                        failure,
                    )
                };
            }
        }
    }
    emit(
        &emitter,
        EventBody::Progress {
            phase: "build".to_owned(),
            message: "Preparing platform build".to_owned(),
            current: Some(0),
            total: Some(1),
        },
    )?;
    let (platform, build_platform) = match arguments.platform {
        IdePlatform::Android => (
            "android",
            BuildPlatform::Android(AndroidBuildArgs {
                keystore: None,
                key_alias: None,
            }),
        ),
        IdePlatform::IosSimulator => (
            "ios-simulator",
            BuildPlatform::Ios(IosBuildArgs {
                simulator: true,
                device: false,
                team: None,
                allow_provisioning_updates: false,
                provisioning_profile: None,
            }),
        ),
        IdePlatform::IosDevice => {
            let Some(team) = arguments.team.clone() else {
                return finish_build_error(
                    &emitter,
                    &root,
                    CliError::Unsupported {
                        message: "physical iOS IDE builds require an explicit Apple Development Team".to_owned(),
                        help: "Run `cargo ferry ide signing-teams --workspace PATH --json`, then pass `--team TEAM_ID`.".to_owned(),
                    },
                );
            };
            (
                "ios-device",
                BuildPlatform::Ios(IosBuildArgs {
                    simulator: false,
                    device: true,
                    team: Some(team),
                    allow_provisioning_updates: arguments.allow_provisioning_updates,
                    provisioning_profile: arguments.provisioning_profile.clone(),
                }),
            )
        }
    };
    let profile = match arguments.profile {
        IdeProfile::Debug => "debug",
        IdeProfile::Release => "release",
    };
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: "cargo-ferry".to_owned(),
            arguments: vec![
                "build".to_owned(),
                platform.to_owned(),
                format!("--profile={profile}"),
                "--project-dir".to_owned(),
                root.to_string(),
            ],
        },
    )?;
    let output = crate::commands::platform_build::execute(
        BuildArgs {
            platform: build_platform,
            release: matches!(arguments.profile, IdeProfile::Release),
            remote: None,
            config_dir: None,
            unsigned: false,
            snapshot: false,
            yes: false,
            artifact: None,
            include_dsym: false,
            project_dir: Some(root.clone()),
        },
        dry_run,
        reporter,
    );
    match output {
        Ok(output) => {
            emit(
                &emitter,
                EventBody::Progress {
                    phase: "build".to_owned(),
                    message: if dry_run {
                        "Build plan completed"
                    } else {
                        "Artifact validation completed"
                    }
                    .to_owned(),
                    current: Some(1),
                    total: Some(1),
                },
            )?;
            if let Some(path) = output.artifact {
                let config = match rustferry_core::FerryConfig::load(&root.join("ferry.toml")) {
                    Ok(config) => config,
                    Err(error) => return finish_build_error(&emitter, &root, error.into()),
                };
                let architectures = artifact_architectures(&config, arguments.platform);
                let mut validation = BTreeMap::new();
                validation.insert(
                    "artifact".to_owned(),
                    if output.validated {
                        "verified"
                    } else {
                        "unverified"
                    }
                    .to_owned(),
                );
                emit(
                    &emitter,
                    EventBody::Artifact {
                        artifact: Artifact {
                            platform: output.platform.to_owned(),
                            kind: if matches!(arguments.platform, IdePlatform::Android) {
                                "apk"
                            } else {
                                "app"
                            }
                            .to_owned(),
                            path,
                            package_identifier: config.app.identifier,
                            architectures,
                            profile: output.profile.to_owned(),
                            validation,
                        },
                    },
                )?;
            }
            emit(
                &emitter,
                EventBody::PhaseFinished {
                    phase: "build".to_owned(),
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            emit(
                &emitter,
                EventBody::OperationFinished {
                    success: true,
                    duration_ms: emitter.elapsed_ms(),
                    error: None,
                },
            )?;
            Ok(())
        }
        Err(_) if rustferry_core::process_control::interrupt_requested() => {
            emit(
                &emitter,
                EventBody::OperationCancelled {
                    reason: "requested".to_owned(),
                    duration_ms: emitter.elapsed_ms(),
                },
            )?;
            Err(CliError::AlreadyReported { exit_code: 130 })
        }
        Err(error) => finish_build_error(&emitter, &root, error),
    }
}

fn install(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    deploy_application(arguments, dry_run, reporter, false)
}

fn run_application(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    deploy_application(arguments, dry_run, reporter, true)
}

#[allow(clippy::too_many_lines)]
fn deploy_application(
    arguments: &IdeDeploymentArgs,
    dry_run: bool,
    reporter: &Reporter,
    launch: bool,
) -> Result<(), CliError> {
    let emitter = stream_emitter(
        arguments.operation_id.clone(),
        arguments.parent_operation_id.clone(),
    )?;
    let command = if launch { "run" } else { "install" };
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: command.to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    let diagnostic_file = root.join("ferry.toml").to_string();
    if dry_run {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "dry_run_unsupported",
                "IDE deployment operations do not report simulated success",
                "Run `cargo ferry ide build` for a non-mutating build plan, or omit `--dry-run` to deploy.",
            ),
        );
    }
    if arguments.artifact.is_some() {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "artifact_validation_metadata_required",
                "an explicit artifact path has no persisted independent validation metadata",
                "Omit `--artifact` so cargo-ferry builds, validates, and structurally rechecks the artifact before deployment.",
            ),
        );
    }

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "build".to_owned(),
            message: Some("Building and validating deployment artifact".to_owned()),
        },
    )?;
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: "cargo-ferry".to_owned(),
            arguments: vec![
                "build".to_owned(),
                platform_label(arguments.platform).to_owned(),
                "--profile=debug".to_owned(),
                "--project-dir".to_owned(),
                root.to_string(),
            ],
        },
    )?;
    let built = match build_deployment_artifact(&root, arguments, reporter) {
        Ok(built) => built,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("build"), error);
        }
    };
    emit(
        &emitter,
        EventBody::Artifact {
            artifact: built.protocol.clone(),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "build".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Resolving the explicit deployment device".to_owned()),
        },
    )?;
    let selected = match selected_device(
        &root,
        arguments.platform,
        &arguments.device,
        "install application",
        true,
    ) {
        Ok(selected) => selected,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("device_discovery"), error);
        }
    };
    emit_warnings(&emitter, &selected.warnings)?;
    emit(
        &emitter,
        EventBody::Device {
            device: protocol_device(selected.device.clone()),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "install".to_owned(),
            message: Some("Installing validated artifact".to_owned()),
        },
    )?;
    let (tool, command_arguments) = install_command(
        arguments.platform,
        &selected.device.id,
        built.deployment.path(),
    );
    emit(
        &emitter,
        EventBody::CommandStarted {
            tool: tool.to_owned(),
            arguments: command_arguments,
        },
    )?;
    let install_request = cargo_ferry::deployment::InstallRequest::new(
        selected.device.clone(),
        built.deployment.clone(),
    );
    let installer = cargo_ferry::deployment::Installer::new(
        cargo_ferry::deployment::SystemExecutor,
        root.clone(),
    );
    if let Err(error) = installer.install(&install_request) {
        return finish_failure(&emitter, &diagnostic_file, Some("install"), error.into());
    }
    emit(
        &emitter,
        EventBody::Progress {
            phase: "install".to_owned(),
            message: "Application installation confirmed".to_owned(),
            current: Some(1),
            total: Some(1),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "install".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    if launch {
        emit(
            &emitter,
            EventBody::PhaseStarted {
                phase: "launch".to_owned(),
                message: Some("Launching installed application".to_owned()),
            },
        )?;
        let (tool, command_arguments) =
            launch_command(arguments.platform, &selected.device.id, &built.deployment);
        emit(
            &emitter,
            EventBody::CommandStarted {
                tool: tool.to_owned(),
                arguments: command_arguments,
            },
        )?;
        let launch_request =
            cargo_ferry::deployment::LaunchRequest::new(selected.device, built.deployment.clone());
        let launcher = cargo_ferry::deployment::Launcher::new(
            cargo_ferry::deployment::SystemExecutor,
            root.clone(),
        );
        let outcome = match launcher.launch(&launch_request) {
            Ok(outcome) => outcome,
            Err(error) => {
                return finish_failure(&emitter, &diagnostic_file, Some("launch"), error.into());
            }
        };
        emit(
            &emitter,
            EventBody::ApplicationStarted {
                platform: platform_label(arguments.platform).to_owned(),
                device_id: outcome.device_id,
                identifier: outcome.application_id,
                process_id: outcome.process_id,
            },
        )?;
        emit(
            &emitter,
            EventBody::PhaseFinished {
                phase: "launch".to_owned(),
                success: true,
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    }

    emit(
        &emitter,
        EventBody::OperationFinished {
            success: true,
            duration_ms: emitter.elapsed_ms(),
            error: None,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn logs(arguments: &IdeDeploymentArgs, dry_run: bool) -> Result<(), CliError> {
    let emitter = stream_emitter(
        arguments.operation_id.clone(),
        arguments.parent_operation_id.clone(),
    )?;
    let root = find_project_root(Some(&arguments.workspace));
    let workspace = root.as_ref().map_or_else(
        |_| absolute_display_path(&arguments.workspace),
        ToString::to_string,
    );
    emit(
        &emitter,
        EventBody::OperationStarted {
            command: "logs".to_owned(),
            workspace: Some(workspace.clone()),
        },
    )?;
    let root = match root {
        Ok(root) => root,
        Err(error) => return finish_error(&emitter, &workspace, error),
    };
    let diagnostic_file = root.join("ferry.toml").to_string();
    if dry_run {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "dry_run_unsupported",
                "IDE log collection cannot be simulated",
                "Omit `--dry-run` to stream bounded, application-filtered logs until cancellation or tool exit.",
            ),
        );
    }
    if arguments.artifact.is_some() {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "artifact_not_supported_for_logs",
                "log filtering uses the validated project identity, not an unvalidated artifact path",
                "Omit `--artifact`; cargo-ferry reads the exact application identifier and process target from the project.",
            ),
        );
    }
    let config = match rustferry_core::FerryConfig::load(&root.join("ferry.toml")) {
        Ok(config) => config,
        Err(error) => {
            return finish_failure(
                &emitter,
                &diagnostic_file,
                None,
                OperationFailure::from(CliError::from(error)),
            );
        }
    };
    if !project_supports_platform(&config, arguments.platform) {
        return finish_failure(
            &emitter,
            &diagnostic_file,
            None,
            OperationFailure::unsupported(
                "platform_not_enabled",
                &format!(
                    "the project does not enable `{}`",
                    platform_label(arguments.platform)
                ),
                "Enable the platform in the top-level `platforms` array in ferry.toml.",
            ),
        );
    }
    let targets = match crate::commands::platform_build::read_cargo_targets(&root) {
        Ok(targets) => targets,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, None, error.into());
        }
    };

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "device_discovery".to_owned(),
            message: Some("Resolving the explicit logging device".to_owned()),
        },
    )?;
    let selected = match selected_device(
        &root,
        arguments.platform,
        &arguments.device,
        "collect application logs",
        false,
    ) {
        Ok(selected) => selected,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("device_discovery"), error);
        }
    };
    emit_warnings(&emitter, &selected.warnings)?;
    emit(
        &emitter,
        EventBody::Device {
            device: protocol_device(selected.device.clone()),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "device_discovery".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;

    emit(
        &emitter,
        EventBody::PhaseStarted {
            phase: "logs".to_owned(),
            message: Some("Streaming bounded, application-filtered logs".to_owned()),
        },
    )?;
    let request = cargo_ferry::deployment::LogRequest::new(
        selected.device,
        config.app.identifier,
        targets.binary,
    );
    let service = cargo_ferry::deployment::LogService::new(
        cargo_ferry::deployment::SystemExecutor,
        root.clone(),
    );
    let outcome = match service.stream(&request, |entry| {
        emitter
            .emit(EventBody::Log {
                source_timestamp: (!entry.timestamp.is_empty())
                    .then(|| redact_text(&entry.timestamp)),
                level: log_level(entry.level).to_owned(),
                target: redact_text(&entry.target),
                message: redact_text(&entry.message),
            })
            .map_err(|source| cargo_ferry::deployment::DeploymentError::Io {
                action: "write streamed IDE log event",
                path: camino::Utf8PathBuf::from("<stdout>"),
                source,
            })
    }) {
        Ok(outcome) => outcome,
        Err(error) => {
            return finish_failure(&emitter, &diagnostic_file, Some("logs"), error.into());
        }
    };
    emit(
        &emitter,
        EventBody::Progress {
            phase: "logs".to_owned(),
            message: "Application-log stream ended after the platform tool exited".to_owned(),
            current: Some(outcome.entries),
            total: Some(outcome.entries),
        },
    )?;
    emit(
        &emitter,
        EventBody::PhaseFinished {
            phase: "logs".to_owned(),
            success: true,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    emit(
        &emitter,
        EventBody::OperationFinished {
            success: true,
            duration_ms: emitter.elapsed_ms(),
            error: None,
        },
    )
}

#[derive(Debug)]
struct BuiltDeploymentArtifact {
    deployment: cargo_ferry::deployment::ValidatedArtifact,
    protocol: Artifact,
}

fn build_deployment_artifact(
    root: &camino::Utf8Path,
    arguments: &IdeDeploymentArgs,
    reporter: &Reporter,
) -> Result<BuiltDeploymentArtifact, OperationFailure> {
    let build_platform = match arguments.platform {
        IdePlatform::Android => BuildPlatform::Android(AndroidBuildArgs {
            keystore: None,
            key_alias: None,
        }),
        IdePlatform::IosSimulator => BuildPlatform::Ios(IosBuildArgs {
            simulator: true,
            device: false,
            team: None,
            allow_provisioning_updates: false,
            provisioning_profile: None,
        }),
        IdePlatform::IosDevice => BuildPlatform::Ios(IosBuildArgs {
            simulator: false,
            device: true,
            team: Some(arguments.team.clone().ok_or_else(|| {
                OperationFailure::unsupported(
                    "physical_ios_team_required",
                    "physical iOS deployment requires an explicit Apple Development Team",
                    "Select a team in VS Code or pass `--team TEAM_ID`; credentials and private keys are never accepted.",
                )
            })?),
            allow_provisioning_updates: arguments.allow_provisioning_updates,
            provisioning_profile: arguments.provisioning_profile.clone(),
        }),
    };
    let output = crate::commands::platform_build::execute(
        BuildArgs {
            platform: build_platform,
            release: false,
            remote: None,
            config_dir: None,
            unsigned: false,
            snapshot: false,
            yes: false,
            artifact: None,
            include_dsym: false,
            project_dir: Some(root.to_owned()),
        },
        false,
        reporter,
    )
    .map_err(OperationFailure::from)?;
    validated_build_output(output, arguments.platform)
}

fn validated_build_output(
    output: crate::commands::platform_build::BuildOutput,
    platform: IdePlatform,
) -> Result<BuiltDeploymentArtifact, OperationFailure> {
    if !output.validated {
        return Err(OperationFailure::invalid_build_metadata(
            "the build did not report completed independent artifact validation",
        ));
    }
    let deployment = output.deployment_artifact.ok_or_else(|| {
        OperationFailure::invalid_build_metadata(
            "the validated build returned no typed deployment artifact",
        )
    })?;
    let validation = output.validation.ok_or_else(|| {
        OperationFailure::invalid_build_metadata(
            "the validated build returned no validation record",
        )
    })?;
    let (expected_kind, architectures, kind, team_id) = match platform {
        IdePlatform::Android => {
            let validation: rustferry_android::ApkValidation = serde_json::from_value(validation)
                .map_err(|error| {
                OperationFailure::invalid_build_metadata(&format!(
                    "Android validation metadata was malformed: {error}"
                ))
            })?;
            (
                cargo_ferry::deployment::ArtifactKind::AndroidApk,
                validation.native_abis,
                "apk",
                None,
            )
        }
        IdePlatform::IosSimulator => {
            let validation: rustferry_apple::IosArtifactValidation =
                serde_json::from_value(validation).map_err(|error| {
                    OperationFailure::invalid_build_metadata(&format!(
                        "iOS validation metadata was malformed: {error}"
                    ))
                })?;
            (
                cargo_ferry::deployment::ArtifactKind::IosSimulatorApp,
                validation.architectures,
                "app",
                None,
            )
        }
        IdePlatform::IosDevice => {
            let validation: cargo_ferry::deployment::PhysicalIosValidation =
                serde_json::from_value(validation).map_err(|error| {
                    OperationFailure::invalid_build_metadata(&format!(
                        "physical iOS validation metadata was malformed: {error}"
                    ))
                })?;
            (
                cargo_ferry::deployment::ArtifactKind::IosPhysicalApp,
                validation.architectures,
                "app",
                Some(validation.team_id),
            )
        }
    };
    if deployment.kind() != expected_kind {
        return Err(OperationFailure::invalid_build_metadata(&format!(
            "validated artifact platform mismatch: expected {}, found {}",
            expected_kind.label(),
            deployment.kind().label()
        )));
    }
    let mut validation_status = BTreeMap::new();
    validation_status.insert("artifact".to_owned(), "verified".to_owned());
    if let Some(team_id) = team_id {
        validation_status.insert("team_id".to_owned(), team_id);
    }
    let protocol = Artifact {
        platform: output.platform.to_owned(),
        kind: kind.to_owned(),
        path: deployment.path().to_string(),
        package_identifier: deployment.application_id().to_owned(),
        architectures,
        profile: output.profile.to_owned(),
        validation: validation_status,
    };
    Ok(BuiltDeploymentArtifact {
        deployment,
        protocol,
    })
}

#[derive(Debug)]
struct SelectedDevice {
    device: cargo_ferry::deployment::Device,
    warnings: Vec<cargo_ferry::deployment::DiscoveryWarning>,
}

fn selected_device(
    root: &camino::Utf8Path,
    platform: IdePlatform,
    requested_id: &str,
    operation: &'static str,
    requires_install: bool,
) -> Result<SelectedDevice, OperationFailure> {
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        root.to_owned(),
    )
    .discover(match platform {
        IdePlatform::Android => cargo_ferry::deployment::DeviceFilter::Android,
        IdePlatform::IosSimulator | IdePlatform::IosDevice => {
            cargo_ferry::deployment::DeviceFilter::Ios
        }
    });
    let candidate = snapshot
        .devices
        .iter()
        .find(|device| device.id == requested_id)
        .ok_or_else(
            || cargo_ferry::deployment::DeploymentError::DeviceNotFound {
                id: requested_id.to_owned(),
            },
        )?;
    let expected = match platform {
        IdePlatform::Android
            if matches!(
                candidate.kind,
                cargo_ferry::deployment::DeviceKind::AndroidPhysical
                    | cargo_ferry::deployment::DeviceKind::AndroidEmulator
            ) =>
        {
            candidate.kind
        }
        IdePlatform::IosSimulator
            if candidate.kind == cargo_ferry::deployment::DeviceKind::IosSimulator =>
        {
            cargo_ferry::deployment::DeviceKind::IosSimulator
        }
        IdePlatform::IosDevice
            if candidate.kind == cargo_ferry::deployment::DeviceKind::IosPhysical =>
        {
            cargo_ferry::deployment::DeviceKind::IosPhysical
        }
        IdePlatform::Android => cargo_ferry::deployment::DeviceKind::AndroidPhysical,
        IdePlatform::IosSimulator => cargo_ferry::deployment::DeviceKind::IosSimulator,
        IdePlatform::IosDevice => cargo_ferry::deployment::DeviceKind::IosPhysical,
    };
    if candidate.kind != expected {
        return Err(
            cargo_ferry::deployment::DeploymentError::DeviceKindMismatch {
                id: requested_id.to_owned(),
                expected,
                actual: candidate.kind,
            }
            .into(),
        );
    }
    let device = if requires_install {
        cargo_ferry::deployment::select_device(
            &snapshot.devices,
            expected,
            Some(requested_id),
            operation,
        )?
    } else {
        candidate.clone()
    };
    Ok(SelectedDevice {
        device,
        warnings: snapshot.warnings,
    })
}

fn install_command(
    platform: IdePlatform,
    device_id: &str,
    artifact: &camino::Utf8Path,
) -> (&'static str, Vec<String>) {
    match platform {
        IdePlatform::Android => (
            "adb",
            vec![
                "-s".to_owned(),
                device_id.to_owned(),
                "install".to_owned(),
                artifact.to_string(),
            ],
        ),
        IdePlatform::IosSimulator => (
            "xcrun",
            vec![
                "simctl".to_owned(),
                "install".to_owned(),
                device_id.to_owned(),
                artifact.to_string(),
            ],
        ),
        IdePlatform::IosDevice => (
            "xcrun",
            vec![
                "devicectl".to_owned(),
                "device".to_owned(),
                "install".to_owned(),
                "app".to_owned(),
                "--device".to_owned(),
                device_id.to_owned(),
                artifact.to_string(),
            ],
        ),
    }
}

fn launch_command(
    platform: IdePlatform,
    device_id: &str,
    artifact: &cargo_ferry::deployment::ValidatedArtifact,
) -> (&'static str, Vec<String>) {
    match platform {
        IdePlatform::Android => (
            "adb",
            vec![
                "-s".to_owned(),
                device_id.to_owned(),
                "shell".to_owned(),
                "am".to_owned(),
                "start".to_owned(),
                "-W".to_owned(),
                "-n".to_owned(),
                format!("{}/{}", artifact.application_id(), artifact.launch_target()),
            ],
        ),
        IdePlatform::IosSimulator => (
            "xcrun",
            vec![
                "simctl".to_owned(),
                "launch".to_owned(),
                device_id.to_owned(),
                artifact.application_id().to_owned(),
            ],
        ),
        IdePlatform::IosDevice => (
            "xcrun",
            vec![
                "devicectl".to_owned(),
                "device".to_owned(),
                "process".to_owned(),
                "launch".to_owned(),
                "--device".to_owned(),
                device_id.to_owned(),
                artifact.application_id().to_owned(),
            ],
        ),
    }
}

const fn platform_label(platform: IdePlatform) -> &'static str {
    match platform {
        IdePlatform::Android => "android",
        IdePlatform::IosSimulator => "ios-simulator",
        IdePlatform::IosDevice => "ios-device",
    }
}

fn project_supports_platform(config: &rustferry_core::FerryConfig, platform: IdePlatform) -> bool {
    let target = match platform {
        IdePlatform::Android => rustferry_core::TargetPlatform::Android,
        IdePlatform::IosSimulator | IdePlatform::IosDevice => rustferry_core::TargetPlatform::Ios,
    };
    config.platforms.contains(&target)
}

const fn log_level(level: cargo_ferry::deployment::LogLevel) -> &'static str {
    match level {
        cargo_ferry::deployment::LogLevel::Debug => "debug",
        cargo_ferry::deployment::LogLevel::Info => "info",
        cargo_ferry::deployment::LogLevel::Warning => "warning",
        cargo_ferry::deployment::LogLevel::Error => "error",
        cargo_ferry::deployment::LogLevel::Fatal => "fatal",
        cargo_ferry::deployment::LogLevel::Unknown => "unknown",
    }
}

#[derive(Debug)]
struct OperationFailure {
    error: ProtocolError,
    exit_code: u8,
    cancelled: bool,
}

impl OperationFailure {
    fn unsupported(code: &str, message: &str, help: &str) -> Self {
        Self {
            error: ProtocolError {
                code: code.to_owned(),
                message: redact_text(message),
                help: Some(redact_text(help)),
                details: Vec::new(),
            },
            exit_code: 3,
            cancelled: false,
        }
    }

    fn invalid_build_metadata(message: &str) -> Self {
        Self {
            error: ProtocolError {
                code: "invalid_build_validation_metadata".to_owned(),
                message: redact_text(message),
                help: Some(
                    "Rebuild the artifact; cargo-ferry never deploys missing or malformed validation evidence."
                        .to_owned(),
                ),
                details: Vec::new(),
            },
            exit_code: 4,
            cancelled: false,
        }
    }
}

impl From<CliError> for OperationFailure {
    fn from(error: CliError) -> Self {
        let cancelled = matches!(&error, CliError::CommandInterrupted { .. })
            || rustferry_core::process_control::interrupt_requested();
        Self {
            error: protocol_error(&error),
            exit_code: if cancelled { 130 } else { error.exit_code() },
            cancelled,
        }
    }
}

impl From<cargo_ferry::deployment::DeploymentError> for OperationFailure {
    fn from(error: cargo_ferry::deployment::DeploymentError) -> Self {
        use cargo_ferry::deployment::DeploymentError;

        let code = error.code().to_owned();
        let message = redact_text(&error.to_string());
        let help = match &error {
            DeploymentError::ToolMissing { help, .. }
            | DeploymentError::CommandFailed { help, .. }
            | DeploymentError::DeviceUnavailable { help, .. }
            | DeploymentError::Unsupported { help, .. } => Some(redact_text(help)),
            DeploymentError::CommandTimedOut { .. } => {
                Some("Verify the selected device remains connected, then retry.".to_owned())
            }
            DeploymentError::Cancelled { .. } => {
                Some("The active deployment process tree was stopped.".to_owned())
            }
            DeploymentError::DeviceNotFound { .. } => {
                Some("Refresh the device inventory and pass one exact stable device ID.".to_owned())
            }
            DeploymentError::DeviceSelectionRequired { .. } => {
                Some("Pass one exact stable device ID from `cargo ferry ide devices`.".to_owned())
            }
            DeploymentError::DeviceKindMismatch { .. }
            | DeploymentError::PlatformMismatch { .. } => {
                Some("Choose a device whose kind matches the requested platform.".to_owned())
            }
            DeploymentError::InvalidArtifact { .. } => {
                Some("Rebuild and revalidate the artifact before deployment.".to_owned())
            }
            DeploymentError::InvalidSigning { .. } => Some(
                "Create a fresh Apple development-signed build with matching provisioning metadata."
                    .to_owned(),
            ),
            DeploymentError::Io { .. } | DeploymentError::InvalidToolOutput { .. } => None,
        };
        let details = match &error {
            DeploymentError::CommandFailed {
                status: Some(status),
                ..
            } => {
                vec![format!("exit_status={status}")]
            }
            _ => Vec::new(),
        };
        let cancelled = matches!(&error, DeploymentError::Cancelled { .. })
            || rustferry_core::process_control::interrupt_requested();
        let exit_code = if cancelled {
            130
        } else {
            match error {
                DeploymentError::Io { .. } => 5,
                DeploymentError::ToolMissing { .. }
                | DeploymentError::CommandTimedOut { .. }
                | DeploymentError::CommandFailed { .. }
                | DeploymentError::InvalidToolOutput { .. } => 4,
                DeploymentError::Cancelled { .. } => 130,
                DeploymentError::DeviceNotFound { .. }
                | DeploymentError::DeviceSelectionRequired { .. }
                | DeploymentError::DeviceUnavailable { .. }
                | DeploymentError::DeviceKindMismatch { .. }
                | DeploymentError::InvalidArtifact { .. }
                | DeploymentError::PlatformMismatch { .. }
                | DeploymentError::Unsupported { .. }
                | DeploymentError::InvalidSigning { .. } => 3,
            }
        };
        Self {
            error: ProtocolError {
                code,
                message,
                help,
                details,
            },
            exit_code,
            cancelled,
        }
    }
}

fn finish_failure(
    emitter: &EventEmitter,
    file: &str,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    finish_failure_impl(emitter, Some(file), phase, failure)
}

fn finish_failure_after_diagnostics(
    emitter: &EventEmitter,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    finish_failure_impl(emitter, None, phase, failure)
}

fn finish_failure_impl(
    emitter: &EventEmitter,
    diagnostic_file: Option<&str>,
    phase: Option<&str>,
    failure: OperationFailure,
) -> Result<(), CliError> {
    if let Some(phase) = phase {
        emit(
            emitter,
            EventBody::PhaseFinished {
                phase: phase.to_owned(),
                success: false,
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    }
    if failure.cancelled {
        emit(
            emitter,
            EventBody::OperationCancelled {
                reason: "requested".to_owned(),
                duration_ms: emitter.elapsed_ms(),
            },
        )?;
    } else {
        if let Some(file) = diagnostic_file {
            emit(
                emitter,
                EventBody::Diagnostic {
                    diagnostic: Diagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: format!("ferry.{}", failure.error.code),
                        message: failure.error.message.clone(),
                        file: file.to_owned(),
                        range: zero_range(),
                        help: failure.error.help.clone(),
                        documentation: None,
                        fixes: Vec::new(),
                    },
                },
            )?;
        }
        emit(
            emitter,
            EventBody::OperationFinished {
                success: false,
                duration_ms: emitter.elapsed_ms(),
                error: Some(failure.error),
            },
        )?;
    }
    Err(CliError::AlreadyReported {
        exit_code: failure.exit_code,
    })
}

fn stream_emitter(
    operation_id: Option<String>,
    parent_operation_id: Option<String>,
) -> Result<EventEmitter, CliError> {
    match EventEmitter::new(operation_id, parent_operation_id) {
        Ok(emitter) => Ok(emitter),
        Err(error) => {
            write_compact(&ProtocolErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error: ProtocolError {
                    code: "invalid_operation_id".to_owned(),
                    message: error.to_string(),
                    help: Some(
                        "Use an opaque identifier containing only letters, digits, '.', '_', ':', or '-'."
                            .to_owned(),
                    ),
                    details: Vec::new(),
                },
            })
            .map_err(stdout_error)?;
            Err(CliError::AlreadyReported { exit_code: 2 })
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn finish_error(emitter: &EventEmitter, workspace: &str, error: CliError) -> Result<(), CliError> {
    let protocol_error = protocol_error(&error);
    emit(
        emitter,
        EventBody::Diagnostic {
            diagnostic: Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: format!("ferry.{}", protocol_error.code),
                message: protocol_error.message.clone(),
                file: workspace.to_owned(),
                range: zero_range(),
                help: protocol_error.help.clone(),
                documentation: None,
                fixes: Vec::new(),
            },
        },
    )?;
    emit(
        emitter,
        EventBody::OperationFinished {
            success: false,
            duration_ms: emitter.elapsed_ms(),
            error: Some(protocol_error),
        },
    )?;
    Err(CliError::AlreadyReported {
        exit_code: error.exit_code(),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn finish_build_error(
    emitter: &EventEmitter,
    root: &camino::Utf8Path,
    error: CliError,
) -> Result<(), CliError> {
    let protocol_error = protocol_error(&error);
    emit(
        emitter,
        EventBody::Diagnostic {
            diagnostic: Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: format!("ferry.{}", protocol_error.code),
                message: protocol_error.message.clone(),
                file: root.join("ferry.toml").to_string(),
                range: zero_range(),
                help: protocol_error.help.clone(),
                documentation: None,
                fixes: Vec::new(),
            },
        },
    )?;
    emit(
        emitter,
        EventBody::PhaseFinished {
            phase: "build".to_owned(),
            success: false,
            duration_ms: emitter.elapsed_ms(),
        },
    )?;
    emit(
        emitter,
        EventBody::OperationFinished {
            success: false,
            duration_ms: emitter.elapsed_ms(),
            error: Some(protocol_error),
        },
    )?;
    Err(CliError::AlreadyReported {
        exit_code: error.exit_code(),
    })
}

fn artifact_architectures(
    config: &rustferry_core::FerryConfig,
    platform: IdePlatform,
) -> Vec<String> {
    match platform {
        IdePlatform::Android => config
            .android
            .abis
            .iter()
            .filter_map(|abi| serde_json::to_value(abi).ok())
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        IdePlatform::IosSimulator => vec![std::env::consts::ARCH.to_owned()],
        IdePlatform::IosDevice => vec!["arm64".to_owned()],
    }
}

fn zero_range() -> SourceRange {
    SourceRange {
        start: Position {
            line: 0,
            character: 0,
        },
        end: Position {
            line: 0,
            character: 0,
        },
    }
}

fn emit(emitter: &EventEmitter, body: EventBody) -> Result<(), CliError> {
    emitter.emit(body).map_err(stdout_error)
}

fn stdout_error(source: std::io::Error) -> CliError {
    CliError::Io {
        action: "write IDE protocol output",
        path: camino::Utf8PathBuf::from("<stdout>"),
        source,
    }
}

fn absolute_display_path(path: &camino::Utf8Path) -> String {
    if let Ok(canonical) = path.canonicalize_utf8() {
        return service::protocol_display_path(&canonical);
    }
    if path.is_absolute() {
        return service::protocol_display_path(path);
    }
    std::env::current_dir()
        .ok()
        .and_then(|directory| camino::Utf8PathBuf::from_path_buf(directory).ok())
        .map_or_else(
            || path.to_string(),
            |directory| service::protocol_display_path(&directory.join(path)),
        )
}

#[cfg(test)]
mod tests {
    use cargo_ferry::job_store::LocalJobId;

    use super::{IdeArtifactSelectionReceipt, retry_attempt_advances, validate_artifact_selection};

    #[test]
    fn retry_attempt_increment_fails_closed_on_overflow() {
        assert!(retry_attempt_advances(0, 1));
        assert!(!retry_attempt_advances(u32::MAX, 0));
    }

    #[test]
    fn artifact_receipt_must_echo_both_exact_selectors() {
        let job = LocalJobId::new("job-contract-1".to_owned()).expect("valid job ID");
        let selection = IdeArtifactSelectionReceipt {
            local_job_id: job.as_str().to_owned(),
            artifact_id: "artifact:1".to_owned(),
            revision: 1,
        };
        assert!(validate_artifact_selection(&selection, &job, "artifact:1").is_ok());
        assert!(validate_artifact_selection(&selection, &job, "artifact:2").is_err());
    }
}
