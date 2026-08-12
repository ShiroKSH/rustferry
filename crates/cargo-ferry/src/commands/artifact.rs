use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    time::{SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use cargo_ferry::job_store::{
    JobOperationKind, JobStore, JobStoreError, LocalJobId, ManagedArtifactRemovalState,
    ManagedArtifactViewV1, StoredJobV1,
};
use clap::{Args, Subcommand};
use rustferry_core::{RetainedDirectoryIdentity, RetainedRegularFileIdentity};
use rustferry_github::artifact_offline::{
    OfflineArtifactContainer, OfflineArtifactError, OfflineArtifactEvidenceLevel,
    OfflineArtifactFile, OfflineArtifactInspection, OfflineArtifactVerification,
    OfflineArtifactVerificationOutcome, OfflineArtifactVerificationRequest, OfflineProductEvidence,
    OfflineSourceEvidence, inspect as inspect_offline, verify as verify_offline,
};
use rustferry_remote::{
    ArtifactKind, ArtifactManifest, ArtifactRecord, BuildProfile, SigningMode, SigningStatus,
    ValidationLevel,
};
use serde::Serialize;

use crate::{
    error::CliError, output::Reporter, project::run_captured_bounded_with_exact_environment,
};

const ARTIFACT_OUTPUT_SCHEMA_VERSION: u32 = 1;
const REVEAL_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Args)]
pub(crate) struct ArtifactArgs {
    #[command(subcommand)]
    pub command: ArtifactCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ArtifactCommand {
    /// List managed local artifacts, optionally for one exact local job.
    List(ArtifactListArgs),
    /// Show one managed artifact and its durable local state.
    Show(ArtifactSelectorArgs),
    /// Inspect exact local bytes without extraction or managed-store access.
    Inspect(ArtifactInspectArgs),
    /// Strictly verify a local path against retained managed build evidence.
    Verify(ArtifactVerifyArgs),
    /// Reveal one revalidated local artifact in the platform file manager.
    Reveal(ArtifactSelectorArgs),
    /// Remove one exact managed artifact without following replacements.
    Remove(ArtifactRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactListArgs {
    /// Restrict results to one stable local job identifier (`job-...`).
    #[arg(long, value_parser = parse_local_job_id)]
    pub job: Option<LocalJobId>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactSelectorArgs {
    /// Provider-scoped artifact identifier.
    #[arg(value_parser = parse_provider_artifact_id)]
    pub provider_artifact_id: String,
    /// Qualify the artifact with one stable local job identifier (`job-...`).
    #[arg(long, value_parser = parse_local_job_id)]
    pub job: Option<LocalJobId>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactInspectArgs {
    /// Exact local file to inspect without extraction.
    pub path: Utf8PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactVerifyArgs {
    /// Exact local file to resolve and verify against durable managed evidence.
    pub path: Utf8PathBuf,
    /// Restrict managed evidence resolution to one stable local job identifier (`job-...`).
    #[arg(long, value_parser = parse_local_job_id)]
    pub job: Option<LocalJobId>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactRemoveArgs {
    /// Provider-scoped artifact identifier.
    #[arg(value_parser = parse_provider_artifact_id)]
    pub provider_artifact_id: String,
    /// Qualify the artifact with one exact stable local job identifier (`job-...`).
    #[arg(long, value_parser = parse_local_job_id)]
    pub job: Option<LocalJobId>,
    /// Confirm removal after exact write-time revalidation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ArtifactSelectorOutputV1 {
    local_job_id: String,
    provider_artifact_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ManagedArtifactOutputV1 {
    selector: ArtifactSelectorOutputV1,
    job: ArtifactJobOutputV1,
    record: ArtifactRecord,
    local_path: Option<String>,
    local_file_identity: Option<String>,
    locally_validated: bool,
    local_validation_level: &'static str,
    remote_validation_levels: Vec<ValidationLevel>,
    signature_evidence: ArtifactSignatureEvidenceV1,
    removal_state: &'static str,
    removal_updated_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ArtifactJobOutputV1 {
    provider: String,
    target: String,
    profile: &'static str,
    requested_signing_mode: &'static str,
    request_sha256: String,
    source_revision: Option<String>,
    source_manifest_sha256: String,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactSignatureEvidenceV1 {
    Signed,
    Unsigned,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactListOutputV1 {
    schema_version: u32,
    dry_run: bool,
    local_job_id: Option<String>,
    returned: usize,
    artifacts: Vec<ManagedArtifactOutputV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactShowOutputV1 {
    schema_version: u32,
    dry_run: bool,
    artifact: ManagedArtifactOutputV1,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactInspectOutputV1 {
    schema_version: u32,
    dry_run: bool,
    path: String,
    inspection: OfflineArtifactInspection,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactVerifyOutputV1 {
    schema_version: u32,
    dry_run: bool,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<ArtifactSelectorOutputV1>,
    #[serde(flatten)]
    result: ArtifactVerificationResultV1,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum ArtifactVerificationResultV1 {
    Verified {
        verification: OfflineArtifactVerification,
    },
    EvidenceUnavailable {
        reason: &'static str,
        inspection: OfflineArtifactInspection,
        #[serde(skip_serializing_if = "Option::is_none")]
        verification: Option<OfflineArtifactVerification>,
    },
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactRevealOutputV1 {
    schema_version: u32,
    dry_run: bool,
    artifact: ArtifactSelectorOutputV1,
    local_path: String,
    launcher: String,
    arguments: Vec<String>,
    working_directory: String,
    environment_policy: &'static str,
    launch_requested: bool,
    exact_path_bound_during_launch: bool,
    post_launch_revalidation: &'static str,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ArtifactRemoveOutputV1 {
    schema_version: u32,
    dry_run: bool,
    artifact: ArtifactSelectorOutputV1,
    confirmation_provided: bool,
    current_state: &'static str,
    executed: bool,
    result_state: Option<&'static str>,
    already_complete: Option<bool>,
}

/// Exact project-bound artifact selector returned to IDE command handlers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeArtifactSelectionReceipt {
    pub(in crate::commands) local_job_id: String,
    pub(in crate::commands) artifact_id: String,
    pub(in crate::commands) revision: u64,
}

/// Strict verification disposition for one exact managed artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactVerifyOutcome {
    Verified,
    EvidenceUnavailable,
}

/// Strongest independently established local evidence level.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactEvidenceLevel {
    Integrity,
    ArchiveSafety,
    Product,
    CrossValidated,
}

/// Bounded container evidence observed from the retained exact file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactContainerReceipt {
    Opaque,
    Zip {
        entry_count: u64,
        expanded_size: u64,
    },
}

/// Path-free retained-file integrity evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeArtifactIntegrityReceipt {
    pub(in crate::commands) size: u64,
    pub(in crate::commands) sha256: String,
    pub(in crate::commands) filesystem_identity: String,
    pub(in crate::commands) container: IdeArtifactContainerReceipt,
}

/// Product kind established by an applicable strict validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactProductKind {
    UnsignedXcarchive,
    Ipa,
    SignedArtifactSet,
}

/// Honest product-validation disposition, distinct from retained-file integrity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactProductReceipt {
    Verified { kind: IdeArtifactProductKind },
    NotApplicable,
    EvidenceUnavailable { reason_code: &'static str },
}

/// Path-free strict verification receipt for an IDE protocol adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeArtifactVerifyReceipt {
    pub(in crate::commands) artifact: IdeArtifactSelectionReceipt,
    pub(in crate::commands) outcome: IdeArtifactVerifyOutcome,
    pub(in crate::commands) evidence_level: IdeArtifactEvidenceLevel,
    pub(in crate::commands) integrity: IdeArtifactIntegrityReceipt,
    pub(in crate::commands) product: IdeArtifactProductReceipt,
    pub(in crate::commands) validation_levels: Vec<String>,
    pub(in crate::commands) signed_cleanup_evidence_bound: bool,
}

/// Path-free file-manager launch receipt for an IDE protocol adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeArtifactRevealReceipt {
    pub(in crate::commands) artifact: IdeArtifactSelectionReceipt,
    pub(in crate::commands) launcher: String,
    pub(in crate::commands) environment_policy: &'static str,
    pub(in crate::commands) launch_requested: bool,
    pub(in crate::commands) exact_path_bound_during_launch: bool,
    pub(in crate::commands) post_launch_revalidation: &'static str,
}

/// Exact durable removal result exposed to an IDE protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands) enum IdeArtifactRemoveResult {
    Removed,
    AlreadyRemoved,
    #[allow(
        dead_code,
        reason = "the store reports preserved replacements as a typed error, never as exact removal success"
    )]
    ReplacementPreserved,
}

/// Path-free exact artifact-removal receipt for an IDE protocol adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the frozen IDE receipt contract represents four independent removal facts"
)]
pub(in crate::commands) struct IdeArtifactRemoveReceipt {
    pub(in crate::commands) artifact: IdeArtifactSelectionReceipt,
    pub(in crate::commands) confirmation_provided: bool,
    pub(in crate::commands) executed: bool,
    pub(in crate::commands) result_state: IdeArtifactRemoveResult,
    pub(in crate::commands) already_complete: bool,
    pub(in crate::commands) replacement_preserved: bool,
}

/// Read-only action availability for one exact project-owned artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeArtifactEligibility {
    pub(in crate::commands) can_verify: bool,
    pub(in crate::commands) verify_reason_code: Option<String>,
    pub(in crate::commands) can_reveal: bool,
    pub(in crate::commands) reveal_reason_code: Option<String>,
    pub(in crate::commands) can_remove: bool,
    pub(in crate::commands) remove_reason_code: Option<String>,
}

#[derive(Clone, Copy)]
struct ProjectArtifactSelector<'a> {
    canonical_root: &'a str,
    filesystem_identity: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedArtifactFile {
    path: Utf8PathBuf,
    expected_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevealPlan {
    program: Utf8PathBuf,
    arguments: Vec<String>,
    current_directory: Utf8PathBuf,
    environment: Vec<(OsString, OsString)>,
    exact_path_binding_supported: bool,
}

pub(crate) fn run(
    arguments: &ArtifactArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    match &arguments.command {
        ArtifactCommand::List(arguments) => list(arguments, dry_run, reporter),
        ArtifactCommand::Show(arguments) => show(arguments, dry_run, reporter),
        ArtifactCommand::Inspect(arguments) => inspect(arguments, dry_run, reporter),
        ArtifactCommand::Verify(arguments) => verify(arguments, dry_run, reporter),
        ArtifactCommand::Reveal(arguments) => reveal(arguments, dry_run, reporter),
        ArtifactCommand::Remove(arguments) => remove(arguments, dry_run, reporter),
    }
}

/// Strictly verify one exact managed artifact owned by the selected project.
pub(in crate::commands) fn ide_verify_for_project(
    canonical_root: &str,
    filesystem_identity: &str,
    local_job_id: &LocalJobId,
    artifact_id: &str,
) -> Result<IdeArtifactVerifyReceipt, CliError> {
    let store = JobStore::open_default_read_only()?;
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let view = store.resolve_managed_artifact(artifact_id, Some(local_job_id))?;
    ensure_record_artifact_binding(&record, &view)?;
    let output = verify_output(&store, &record, &view, false)?;
    Ok(ide_verify_receipt(&record, &view, output))
}

/// Launch the fixed platform file manager for one exact project-owned artifact.
pub(in crate::commands) fn ide_reveal_for_project(
    canonical_root: &str,
    filesystem_identity: &str,
    local_job_id: &LocalJobId,
    artifact_id: &str,
) -> Result<IdeArtifactRevealReceipt, CliError> {
    let store = JobStore::open_default_read_only()?;
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let view = store.resolve_managed_artifact(artifact_id, Some(local_job_id))?;
    ensure_record_artifact_binding(&record, &view)?;
    let silent_reporter = Reporter::new(false, true, false);
    let output = reveal_output(&view, false, &silent_reporter)?;
    let launcher = Utf8Path::new(&output.launcher)
        .file_name()
        .unwrap_or("platform_file_manager")
        .to_owned();
    Ok(IdeArtifactRevealReceipt {
        artifact: ide_artifact_selection(&record, &view),
        launcher,
        environment_policy: output.environment_policy,
        launch_requested: output.launch_requested,
        exact_path_bound_during_launch: output.exact_path_bound_during_launch,
        post_launch_revalidation: output.post_launch_revalidation,
    })
}

/// Remove one exact project-owned artifact after explicit confirmation.
pub(in crate::commands) fn ide_remove_for_project(
    canonical_root: &str,
    filesystem_identity: &str,
    local_job_id: &LocalJobId,
    artifact_id: &str,
    confirmation: bool,
) -> Result<IdeArtifactRemoveReceipt, CliError> {
    let (output, revision) = remove_output(
        artifact_id,
        Some(local_job_id),
        confirmation,
        false,
        Some(ProjectArtifactSelector {
            canonical_root,
            filesystem_identity,
        }),
    )?;
    let revision = revision.ok_or_else(|| CliError::JobsLifecycle {
        code: "artifact_job_provenance_unavailable",
        message: "the exact project-bound artifact revision is unavailable".to_owned(),
        help: "Preserve the local job store and retry the exact workspace, job, and artifact selector."
            .to_owned(),
        details: vec![
            format!("local_job_id={}", local_job_id.as_str()),
            format!("provider_artifact_id={artifact_id}"),
        ],
    })?;
    Ok(ide_remove_receipt(output, revision))
}

/// Inspect current action availability without launching or mutating durable state.
pub(in crate::commands) fn ide_artifact_eligibility_for_project(
    canonical_root: &str,
    filesystem_identity: &str,
    local_job_id: &LocalJobId,
    artifact_id: &str,
) -> Result<IdeArtifactEligibility, CliError> {
    let store = JobStore::open_default_read_only()?;
    let record = store.latest_for_project(local_job_id, canonical_root, filesystem_identity)?;
    let view = store.resolve_managed_artifact(artifact_id, Some(local_job_id))?;
    ensure_record_artifact_binding(&record, &view)?;

    let verify = ide_action_eligibility(ide_verify_eligibility(&view));
    let reveal = ide_action_eligibility(ide_reveal_eligibility(&view));
    let remove = ide_action_eligibility(
        remove_output(
            artifact_id,
            Some(local_job_id),
            false,
            true,
            Some(ProjectArtifactSelector {
                canonical_root,
                filesystem_identity,
            }),
        )
        .map(|_| ()),
    );

    Ok(IdeArtifactEligibility {
        can_verify: verify.0,
        verify_reason_code: verify.1,
        can_reveal: reveal.0,
        reveal_reason_code: reveal.1,
        can_remove: remove.0,
        remove_reason_code: remove.1,
    })
}

fn ide_remove_receipt(output: ArtifactRemoveOutputV1, revision: u64) -> IdeArtifactRemoveReceipt {
    let already_complete = output.already_complete.unwrap_or(false);
    IdeArtifactRemoveReceipt {
        artifact: IdeArtifactSelectionReceipt {
            local_job_id: output.artifact.local_job_id,
            artifact_id: output.artifact.provider_artifact_id,
            revision,
        },
        confirmation_provided: output.confirmation_provided,
        executed: output.executed && !already_complete,
        result_state: if already_complete {
            IdeArtifactRemoveResult::AlreadyRemoved
        } else {
            IdeArtifactRemoveResult::Removed
        },
        already_complete,
        replacement_preserved: false,
    }
}

fn ide_action_eligibility(result: Result<(), CliError>) -> (bool, Option<String>) {
    match result {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error.code().to_owned())),
    }
}

fn ide_verify_eligibility(view: &ManagedArtifactViewV1) -> Result<(), CliError> {
    let file = managed_available_file(view)?;
    drop(inspect_managed_file(view, &file)?);
    Ok(())
}

fn ide_reveal_eligibility(view: &ManagedArtifactViewV1) -> Result<(), CliError> {
    let silent_reporter = Reporter::new(false, true, false);
    drop(reveal_output(view, true, &silent_reporter)?);
    Ok(())
}

fn list(arguments: &ArtifactListArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let store = JobStore::open_default_read_only()?;
    let output = list_output(&store, arguments.job.as_ref(), dry_run)?;
    reporter.success(
        "artifact-list",
        &output,
        || render_artifact_list(&output),
        &[],
    );
    Ok(())
}

fn show(
    arguments: &ArtifactSelectorArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let store = JobStore::open_default_read_only()?;
    let view =
        store.resolve_managed_artifact(&arguments.provider_artifact_id, arguments.job.as_ref())?;
    let job = store.latest(&view.artifact_ref.local_job_id)?;
    let output = ArtifactShowOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run,
        artifact: managed_artifact_output(&view, &job)?,
    };
    reporter.success(
        "artifact-show",
        &output,
        || render_artifact_show(&output),
        &[],
    );
    Ok(())
}

fn inspect(
    arguments: &ArtifactInspectArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let path = absolute_artifact_input_path(&arguments.path)?;
    let output = inspect_output(&path, dry_run)?;
    reporter.success(
        "artifact-inspect",
        &output,
        || render_artifact_inspect(&output),
        &[],
    );
    Ok(())
}

fn verify(
    arguments: &ArtifactVerifyArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let path = absolute_artifact_input_path(&arguments.path)?;
    let inspection = inspect_offline(&path).map_err(map_unmanaged_offline_error)?;
    let store = JobStore::open_default_read_only()?;
    let view = resolve_managed_artifact_path(&store, &path, &inspection, arguments.job.as_ref())?;
    let output = if let Some(view) = view.as_ref() {
        let record = store.latest(&view.artifact_ref.local_job_id)?;
        verify_output(&store, &record, view, dry_run)?
    } else {
        ArtifactVerifyOutputV1 {
            schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
            dry_run,
            path: path.to_string(),
            artifact: None,
            result: ArtifactVerificationResultV1::EvidenceUnavailable {
                reason: "managed_artifact_evidence_unavailable",
                inspection,
                verification: None,
            },
        }
    };
    match &output.result {
        ArtifactVerificationResultV1::Verified { .. } => {
            reporter.success(
                "artifact-verify",
                &output,
                || render_artifact_verify(&output),
                &[],
            );
            Ok(())
        }
        ArtifactVerificationResultV1::EvidenceUnavailable { reason, .. } => {
            let error = evidence_unavailable_error(view.as_ref(), reason);
            reporter.failure_with_data("artifact-verify", &output, &error, || {
                render_artifact_verify(&output)
            });
            Err(CliError::AlreadyReported { exit_code: 3 })
        }
    }
}

fn reveal(
    arguments: &ArtifactSelectorArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let store = JobStore::open_default_read_only()?;
    let view =
        store.resolve_managed_artifact(&arguments.provider_artifact_id, arguments.job.as_ref())?;
    let output = reveal_output(&view, dry_run, reporter)?;
    reporter.success(
        "artifact-reveal",
        &output,
        || render_artifact_reveal(&output),
        &[],
    );
    Ok(())
}

fn reveal_output(
    view: &ManagedArtifactViewV1,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<ArtifactRevealOutputV1, CliError> {
    let file = managed_available_file(view)?;
    let retained_file = RetainedRegularFileIdentity::open(file.path.as_std_path()).map_err(|_| {
        artifact_failure(
            "artifact_integrity_mismatch",
            "the managed artifact could not be retained as its exact safe filesystem object",
            "Do not reveal the path as the recorded artifact; inspect it and download a fresh exact artifact before use.",
            view,
        )
    })?;
    if retained_file.identity().as_str() != file.expected_identity {
        return Err(artifact_failure(
            "artifact_integrity_mismatch",
            "the managed artifact path no longer names its persisted filesystem identity",
            "Do not reveal the replacement as the recorded artifact; preserve it for inspection and download a fresh exact artifact.",
            view,
        ));
    }
    let parent = file.path.parent().ok_or_else(|| {
        artifact_failure(
            "artifact_reveal_uncertain",
            "the managed artifact path has no retainable parent directory",
            "Restore the exact absolute artifact location before requesting reveal.",
            view,
        )
    })?;
    let retained_parent = RetainedDirectoryIdentity::open(parent.as_std_path()).map_err(|_| {
        artifact_failure(
            "artifact_reveal_uncertain",
            "the managed artifact parent could not be retained safely",
            "Restore a normal non-reparse artifact parent directory before requesting reveal.",
            view,
        )
    })?;
    drop(inspect_managed_file(view, &file)?);
    let plan = reveal_plan(&file.path)?;
    if !dry_run {
        verify_reveal_guards(&retained_file, &retained_parent, &file, parent, view)?;
        execute_reveal_plan(&plan, reporter)?;
        verify_reveal_guards(&retained_file, &retained_parent, &file, parent, view)?;
        inspect_managed_file(view, &file).map_err(|_| {
            artifact_failure(
                "artifact_reveal_uncertain",
                "the managed artifact changed or became unverifiable while the file manager was launched",
                "Do not treat the revealed path as the recorded artifact; inspect the path and download a fresh exact artifact before use.",
                view,
            )
        })?;
    }
    let output = ArtifactRevealOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run,
        artifact: ArtifactSelectorOutputV1::from(view),
        local_path: file.path.to_string(),
        launcher: plan.program.to_string(),
        arguments: plan.arguments,
        working_directory: plan.current_directory.to_string(),
        environment_policy: "fixed_no_inheritance",
        launch_requested: !dry_run,
        exact_path_bound_during_launch: !dry_run && plan.exact_path_binding_supported,
        post_launch_revalidation: if dry_run { "not_run" } else { "passed" },
    };
    Ok(output)
}

fn remove(
    arguments: &ArtifactRemoveArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let (output, _) = remove_output(
        &arguments.provider_artifact_id,
        arguments.job.as_ref(),
        arguments.yes,
        dry_run,
        None,
    )?;
    reporter.success(
        "artifact-remove",
        &output,
        || render_artifact_remove(&output),
        &[],
    );
    Ok(())
}

fn remove_output(
    provider_artifact_id: &str,
    local_job_id: Option<&LocalJobId>,
    confirmation: bool,
    dry_run: bool,
    project: Option<ProjectArtifactSelector<'_>>,
) -> Result<(ArtifactRemoveOutputV1, Option<u64>), CliError> {
    let preview_store = JobStore::open_default_read_only()?;
    let preview_record = removal_project_record(&preview_store, local_job_id, project)?;
    let preview = resolve_removal_artifact(&preview_store, provider_artifact_id, local_job_id)?;
    if let Some(record) = preview_record.as_ref() {
        ensure_record_artifact_binding(record, &preview)?;
    }
    if !preview_store.supports_exact_artifact_removal() {
        return Err(JobStoreError::ArtifactRemovalUnsupported.into());
    }
    match preview.removal_state {
        ManagedArtifactRemovalState::Available => {
            let file = managed_available_file(&preview)?;
            drop(inspect_managed_file(&preview, &file)?);
        }
        ManagedArtifactRemovalState::Removed => {}
        ManagedArtifactRemovalState::Intent | ManagedArtifactRemovalState::Uncertain => {
            drop(managed_file_provenance(&preview)?);
        }
    }
    if !dry_run && !confirmation {
        return Err(artifact_lifecycle_error(
            "artifact_removal_confirmation_required",
            "refusing to remove the exact managed artifact without confirmation",
            "Review `cargo ferry --dry-run artifact remove <provider-artifact-id> [--job <local-job-id>]`, then repeat with --yes.",
            &preview,
        ));
    }
    let current_state = removal_state_name(preview.removal_state);
    if dry_run {
        let output = ArtifactRemoveOutputV1 {
            schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
            dry_run: true,
            artifact: ArtifactSelectorOutputV1::from(&preview),
            confirmation_provided: confirmation,
            current_state,
            executed: false,
            result_state: None,
            already_complete: None,
        };
        return Ok((output, preview_record.map(|record| record.revision)));
    }

    drop(preview_store);
    let store = JobStore::open_default()?;
    let exact_local_job_id = preview.artifact_ref.local_job_id.clone();
    let revalidated =
        store.resolve_managed_artifact(provider_artifact_id, Some(&exact_local_job_id))?;
    if revalidated != preview {
        return Err(artifact_lifecycle_error(
            "artifact_removal_plan_changed",
            "the exact managed artifact state changed before removal",
            "Inspect the artifact again, then confirm the new exact removal plan.",
            &revalidated,
        ));
    }
    let lease = store.try_acquire_operation_lease(
        &revalidated.artifact_ref.local_job_id,
        JobOperationKind::ArtifactRemoval,
    )?;
    let revision = if let Some(project) = project {
        let record = store.latest_for_project(
            &exact_local_job_id,
            project.canonical_root,
            project.filesystem_identity,
        )?;
        ensure_record_artifact_binding(&record, &revalidated)?;
        Some(record.revision)
    } else {
        None
    };
    let receipt =
        store.remove_managed_artifact(&lease, &revalidated.artifact_ref, unix_time_ms()?)?;
    if receipt.state != ManagedArtifactRemovalState::Removed {
        return Err(artifact_lifecycle_error(
            "artifact_removal_uncertain",
            "the exact managed artifact removal could not be proven",
            "Preserve the managed store and inspect the recorded path; retry only after reconciling replacement and filesystem identity state.",
            &revalidated,
        ));
    }
    let output = completed_remove_output(&revalidated, current_state, receipt.already_complete);
    Ok((output, revision))
}

fn removal_project_record(
    store: &JobStore,
    local_job_id: Option<&LocalJobId>,
    project: Option<ProjectArtifactSelector<'_>>,
) -> Result<Option<StoredJobV1>, CliError> {
    let Some(project) = project else {
        return Ok(None);
    };
    let local_job_id = local_job_id.ok_or_else(|| CliError::JobsLifecycle {
        code: "artifact_job_qualification_required",
        message: "project-bound artifact removal requires an exact local job selector".to_owned(),
        help: "Retry with the exact workspace, local job, and artifact selector.".to_owned(),
        details: Vec::new(),
    })?;
    store
        .latest_for_project(
            local_job_id,
            project.canonical_root,
            project.filesystem_identity,
        )
        .map(Some)
        .map_err(CliError::from)
}

fn resolve_removal_artifact(
    store: &JobStore,
    provider_artifact_id: &str,
    local_job_id: Option<&LocalJobId>,
) -> Result<ManagedArtifactViewV1, CliError> {
    store
        .resolve_managed_artifact(provider_artifact_id, local_job_id)
        .map_err(CliError::from)
}

fn completed_remove_output(
    view: &ManagedArtifactViewV1,
    current_state: &'static str,
    already_complete: bool,
) -> ArtifactRemoveOutputV1 {
    ArtifactRemoveOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run: false,
        artifact: ArtifactSelectorOutputV1::from(view),
        confirmation_provided: true,
        current_state,
        executed: !already_complete,
        result_state: Some(removal_state_name(ManagedArtifactRemovalState::Removed)),
        already_complete: Some(already_complete),
    }
}

fn list_output(
    store: &JobStore,
    local_job_id: Option<&LocalJobId>,
    dry_run: bool,
) -> Result<ArtifactListOutputV1, CliError> {
    let views = store.list_managed_artifacts(local_job_id)?;
    let mut jobs = BTreeMap::new();
    for view in &views {
        if !jobs.contains_key(&view.artifact_ref.local_job_id) {
            let job = store.latest(&view.artifact_ref.local_job_id)?;
            jobs.insert(view.artifact_ref.local_job_id.clone(), job);
        }
    }
    let artifacts = views
        .iter()
        .map(|view| {
            let job = jobs.get(&view.artifact_ref.local_job_id).ok_or_else(|| {
                artifact_failure(
                    "artifact_job_provenance_unavailable",
                    "the owning job provenance is unavailable",
                    "Preserve the local job store and reconcile its immutable artifact index.",
                    view,
                )
            })?;
            managed_artifact_output(view, job)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(ArtifactListOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run,
        local_job_id: local_job_id.map(|identifier| identifier.as_str().to_owned()),
        returned: artifacts.len(),
        artifacts,
    })
}

fn inspect_output(path: &Utf8Path, dry_run: bool) -> Result<ArtifactInspectOutputV1, CliError> {
    let inspection = inspect_offline(path).map_err(map_unmanaged_offline_error)?;
    Ok(ArtifactInspectOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run,
        path: path.to_string(),
        inspection,
    })
}

fn verify_output(
    store: &JobStore,
    record: &StoredJobV1,
    view: &ManagedArtifactViewV1,
    dry_run: bool,
) -> Result<ArtifactVerifyOutputV1, CliError> {
    ensure_record_artifact_binding(record, view)?;
    let file = managed_available_file(view)?;
    let selector = ArtifactSelectorOutputV1::from(view);
    let path = file.path.to_string();
    let Some(compile_evidence) = record.compile_evidence.clone() else {
        return Ok(ArtifactVerifyOutputV1 {
            schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
            dry_run,
            path,
            artifact: Some(selector),
            result: ArtifactVerificationResultV1::EvidenceUnavailable {
                reason: "compile_evidence_unavailable",
                inspection: inspect_managed_file(view, &file)?,
                verification: None,
            },
        });
    };
    let manifest = select_artifact_manifest(record, &view.record)?;
    let catalog = manifest
        .as_ref()
        .map(|manifest| local_manifest_catalog(store, view, manifest))
        .transpose()?
        .unwrap_or_default();
    let verification = verify_offline(&OfflineArtifactVerificationRequest {
        artifact: OfflineArtifactFile {
            record: view.record.clone(),
            path: file.path,
            expected_filesystem_identity: Some(file.expected_identity),
        },
        request: record.request.clone(),
        request_sha256: record.request_sha256.clone(),
        source: OfflineSourceEvidence {
            repository: record.request.source_repository.clone(),
            revision: record.request.source_revision.clone(),
            sha256: record.source.manifest_sha256.clone(),
        },
        compile_evidence,
        manifest: manifest.clone(),
        signed_cleanup_evidence: manifest
            .as_ref()
            .and(record.signed_cleanup_evidence.clone()),
        catalog,
    })
    .map_err(|error| map_offline_error(error, view))?;
    let result = if verification.outcome == OfflineArtifactVerificationOutcome::Verified {
        ArtifactVerificationResultV1::Verified { verification }
    } else {
        ArtifactVerificationResultV1::EvidenceUnavailable {
            reason: "strict_product_evidence_unavailable",
            inspection: verification.inspection.clone(),
            verification: Some(verification),
        }
    };
    Ok(ArtifactVerifyOutputV1 {
        schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
        dry_run,
        path,
        artifact: Some(selector),
        result,
    })
}

fn ensure_record_artifact_binding(
    record: &StoredJobV1,
    view: &ManagedArtifactViewV1,
) -> Result<(), CliError> {
    if record.local_job_id != view.artifact_ref.local_job_id
        || !record.artifacts.iter().any(|artifact| {
            artifact.record == view.record
                && artifact.local_path == view.local_path
                && artifact.local_file_identity == view.local_file_identity
        })
    {
        return Err(artifact_failure(
            "artifact_record_mismatch",
            "the managed artifact does not match its latest immutable job record",
            "Preserve the local job store and reconcile its immutable artifact provenance before verification.",
            view,
        ));
    }
    Ok(())
}

fn ide_verify_receipt(
    record: &StoredJobV1,
    view: &ManagedArtifactViewV1,
    output: ArtifactVerifyOutputV1,
) -> IdeArtifactVerifyReceipt {
    let artifact = ide_artifact_selection(record, view);
    match output.result {
        ArtifactVerificationResultV1::Verified { verification } => ide_verification_receipt(
            artifact,
            view.record.kind,
            IdeArtifactVerifyOutcome::Verified,
            verification,
            "strict_product_evidence_unavailable",
        ),
        ArtifactVerificationResultV1::EvidenceUnavailable {
            reason,
            inspection: _,
            verification: Some(verification),
        } => ide_verification_receipt(
            artifact,
            view.record.kind,
            IdeArtifactVerifyOutcome::EvidenceUnavailable,
            verification,
            reason,
        ),
        ArtifactVerificationResultV1::EvidenceUnavailable {
            reason,
            inspection,
            verification: None,
        } => IdeArtifactVerifyReceipt {
            artifact,
            outcome: IdeArtifactVerifyOutcome::EvidenceUnavailable,
            evidence_level: ide_inspection_evidence_level(&inspection),
            integrity: ide_integrity_receipt(inspection),
            product: ide_product_receipt(view.record.kind, None, reason),
            validation_levels: Vec::new(),
            signed_cleanup_evidence_bound: false,
        },
    }
}

fn ide_verification_receipt(
    artifact: IdeArtifactSelectionReceipt,
    artifact_kind: ArtifactKind,
    outcome: IdeArtifactVerifyOutcome,
    verification: OfflineArtifactVerification,
    unavailable_reason: &'static str,
) -> IdeArtifactVerifyReceipt {
    IdeArtifactVerifyReceipt {
        artifact,
        outcome,
        evidence_level: ide_evidence_level(verification.evidence_level),
        integrity: ide_integrity_receipt(verification.inspection),
        product: ide_product_receipt(
            artifact_kind,
            verification.product.as_ref(),
            unavailable_reason,
        ),
        validation_levels: verification
            .validation_levels
            .into_iter()
            .map(validation_level_name)
            .map(ToOwned::to_owned)
            .collect(),
        signed_cleanup_evidence_bound: verification.signed_cleanup_evidence_bound,
    }
}

fn ide_artifact_selection(
    record: &StoredJobV1,
    view: &ManagedArtifactViewV1,
) -> IdeArtifactSelectionReceipt {
    IdeArtifactSelectionReceipt {
        local_job_id: view.artifact_ref.local_job_id.as_str().to_owned(),
        artifact_id: view.artifact_ref.provider_artifact_id.clone(),
        revision: record.revision,
    }
}

const fn ide_evidence_level(level: OfflineArtifactEvidenceLevel) -> IdeArtifactEvidenceLevel {
    match level {
        OfflineArtifactEvidenceLevel::Integrity => IdeArtifactEvidenceLevel::Integrity,
        OfflineArtifactEvidenceLevel::ArchiveSafety => IdeArtifactEvidenceLevel::ArchiveSafety,
        OfflineArtifactEvidenceLevel::Product => IdeArtifactEvidenceLevel::Product,
        OfflineArtifactEvidenceLevel::CrossValidated => IdeArtifactEvidenceLevel::CrossValidated,
    }
}

const fn ide_inspection_evidence_level(
    inspection: &OfflineArtifactInspection,
) -> IdeArtifactEvidenceLevel {
    match &inspection.container {
        OfflineArtifactContainer::Opaque => IdeArtifactEvidenceLevel::Integrity,
        OfflineArtifactContainer::Zip { .. } => IdeArtifactEvidenceLevel::ArchiveSafety,
    }
}

fn ide_integrity_receipt(inspection: OfflineArtifactInspection) -> IdeArtifactIntegrityReceipt {
    IdeArtifactIntegrityReceipt {
        size: inspection.size,
        sha256: inspection.sha256,
        filesystem_identity: inspection.filesystem_identity,
        container: match inspection.container {
            OfflineArtifactContainer::Opaque => IdeArtifactContainerReceipt::Opaque,
            OfflineArtifactContainer::Zip {
                entry_count,
                expanded_size,
            } => IdeArtifactContainerReceipt::Zip {
                entry_count: u64::from(entry_count),
                expanded_size,
            },
        },
    }
}

fn ide_product_receipt(
    artifact_kind: ArtifactKind,
    product: Option<&OfflineProductEvidence>,
    unavailable_reason: &'static str,
) -> IdeArtifactProductReceipt {
    match product {
        Some(OfflineProductEvidence::UnsignedXcarchive(_)) => IdeArtifactProductReceipt::Verified {
            kind: IdeArtifactProductKind::UnsignedXcarchive,
        },
        Some(OfflineProductEvidence::Ipa(_)) => IdeArtifactProductReceipt::Verified {
            kind: IdeArtifactProductKind::Ipa,
        },
        Some(OfflineProductEvidence::SignedArtifactSet(_)) => IdeArtifactProductReceipt::Verified {
            kind: IdeArtifactProductKind::SignedArtifactSet,
        },
        None if matches!(
            artifact_kind,
            ArtifactKind::App | ArtifactKind::Xcarchive | ArtifactKind::Ipa
        ) =>
        {
            IdeArtifactProductReceipt::EvidenceUnavailable {
                reason_code: unavailable_reason,
            }
        }
        None => IdeArtifactProductReceipt::NotApplicable,
    }
}

fn select_artifact_manifest(
    record: &StoredJobV1,
    artifact: &ArtifactRecord,
) -> Result<Option<ArtifactManifest>, CliError> {
    let mut matches = record
        .provider_resume
        .as_ref()
        .into_iter()
        .flat_map(|resume| &resume.manifests)
        .filter(|manifest| manifest.artifacts.contains(artifact));
    let selected = matches.next().cloned();
    if matches.next().is_some() {
        return Err(CliError::JobsLifecycle {
            code: "artifact_manifest_ambiguous",
            message: "more than one retained manifest contains the exact artifact record"
                .to_owned(),
            help: "Preserve the local job store and reconcile the provider checkpoint before strict verification."
                .to_owned(),
            details: vec![
                format!("local_job_id={}", record.local_job_id.as_str()),
                format!("provider_artifact_id={}", artifact.artifact_id),
            ],
        });
    }
    Ok(selected)
}

fn local_manifest_catalog(
    store: &JobStore,
    primary: &ManagedArtifactViewV1,
    manifest: &ArtifactManifest,
) -> Result<Vec<OfflineArtifactFile>, CliError> {
    let views = store.list_managed_artifacts(Some(&primary.artifact_ref.local_job_id))?;
    let by_id = views
        .iter()
        .map(|view| (view.artifact_ref.provider_artifact_id.as_str(), view))
        .collect::<BTreeMap<_, _>>();
    let mut catalog = Vec::new();
    for record in &manifest.artifacts {
        if record == &primary.record {
            continue;
        }
        let Some(view) = by_id.get(record.artifact_id.as_str()).copied() else {
            continue;
        };
        if &view.record != record || view.removal_state != ManagedArtifactRemovalState::Available {
            continue;
        }
        let Ok(file) = managed_file_provenance(view) else {
            continue;
        };
        catalog.push(OfflineArtifactFile {
            record: view.record.clone(),
            path: file.path,
            expected_filesystem_identity: Some(file.expected_identity),
        });
    }
    Ok(catalog)
}

fn managed_available_file(view: &ManagedArtifactViewV1) -> Result<ManagedArtifactFile, CliError> {
    if view.removal_state != ManagedArtifactRemovalState::Available {
        return Err(artifact_lifecycle_error(
            match view.removal_state {
                ManagedArtifactRemovalState::Available => "artifact_available",
                ManagedArtifactRemovalState::Intent => "artifact_removal_in_progress",
                ManagedArtifactRemovalState::Removed => "artifact_removed",
                ManagedArtifactRemovalState::Uncertain => "artifact_removal_uncertain",
            },
            format!(
                "the managed artifact is not locally available: {}",
                removal_state_name(view.removal_state)
            ),
            "Use `cargo ferry artifact show` to inspect the durable removal state before accessing local bytes.",
            view,
        ));
    }
    managed_file_provenance(view)
}

fn managed_file_provenance(view: &ManagedArtifactViewV1) -> Result<ManagedArtifactFile, CliError> {
    let path = view.local_path.as_ref().ok_or_else(|| {
        artifact_lifecycle_error(
            "artifact_local_path_unavailable",
            "the managed artifact has no durable local path",
            "Download the exact artifact through RustFerry before inspecting or removing it.",
            view,
        )
    })?;
    let expected_identity = view.local_file_identity.clone().ok_or_else(|| {
        artifact_lifecycle_error(
            "artifact_local_identity_unavailable",
            "the managed artifact has no durable local filesystem identity",
            "Download the exact artifact through a RustFerry version that persists filesystem identity before retrying.",
            view,
        )
    })?;
    Ok(ManagedArtifactFile {
        path: Utf8PathBuf::from(path),
        expected_identity,
    })
}

fn inspect_managed_file(
    view: &ManagedArtifactViewV1,
    file: &ManagedArtifactFile,
) -> Result<OfflineArtifactInspection, CliError> {
    let inspection = inspect_offline(&file.path).map_err(|error| map_offline_error(error, view))?;
    if inspection.size != view.record.size
        || inspection.sha256 != view.record.sha256
        || inspection.filesystem_identity != file.expected_identity
    {
        return Err(artifact_failure(
            "artifact_integrity_mismatch",
            "the retained local artifact no longer matches its immutable record and filesystem identity",
            "Do not use or remove the path as the recorded artifact; preserve it for inspection and download a fresh exact artifact.",
            view,
        ));
    }
    Ok(inspection)
}

fn resolve_managed_artifact_path(
    store: &JobStore,
    path: &Utf8Path,
    inspection: &OfflineArtifactInspection,
    local_job_id: Option<&LocalJobId>,
) -> Result<Option<ManagedArtifactViewV1>, CliError> {
    let canonical = path.canonicalize_utf8().map_err(|_| {
        unmanaged_artifact_failure(
            "artifact_path_invalid",
            "the inspected artifact path could not be resolved canonically",
            "Use an absolute normal path to one retained local artifact file.",
        )
    })?;
    let canonical_inspection = inspect_offline(&canonical).map_err(map_unmanaged_offline_error)?;
    if canonical_inspection.filesystem_identity != inspection.filesystem_identity {
        return Err(unmanaged_artifact_failure(
            "artifact_integrity_mismatch",
            "the artifact filesystem identity changed during managed evidence resolution",
            "Preserve the path for inspection and retry only with one stable exact local file.",
        ));
    }

    let views = store.list_managed_artifacts(local_job_id)?;
    let mut path_matches = Vec::new();
    for view in views {
        let Some(stored_path) = view.local_path.as_deref() else {
            continue;
        };
        let stored_path = Utf8Path::new(stored_path);
        let same_path = stored_path == canonical
            || stored_path == path
            || stored_path
                .canonicalize_utf8()
                .is_ok_and(|candidate| candidate == canonical);
        if same_path {
            path_matches.push(view);
        }
    }
    let mut exact = path_matches
        .iter()
        .filter(|view| {
            view.local_file_identity.as_deref() == Some(inspection.filesystem_identity.as_str())
        })
        .cloned();
    let resolved = exact.next();
    if exact.next().is_some() {
        return Err(CliError::JobsLifecycle {
            code: "artifact_path_ambiguous",
            message: "the canonical path and filesystem identity belong to more than one managed artifact"
                .to_owned(),
            help: "Qualify verification with --job and retry the exact retained path."
                .to_owned(),
            details: path_matches
                .iter()
                .map(|view| {
                    format!(
                        "local_job_id={} provider_artifact_id={}",
                        view.artifact_ref.local_job_id.as_str(),
                        view.artifact_ref.provider_artifact_id
                    )
                })
                .collect(),
        });
    }
    if resolved.is_none()
        && let Some(view) = path_matches.first()
    {
        return Err(artifact_failure(
            "artifact_integrity_mismatch",
            "the managed artifact path no longer names its persisted filesystem identity",
            "Do not use the replacement as the recorded artifact; preserve it for inspection and download a fresh exact artifact.",
            view,
        ));
    }
    Ok(resolved)
}

fn absolute_artifact_input_path(path: &Utf8Path) -> Result<Utf8PathBuf, CliError> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let current = std::env::current_dir().map_err(|_| {
        unmanaged_artifact_failure(
            "artifact_path_invalid",
            "the current directory is unavailable for artifact path resolution",
            "Use an absolute normal path to one local artifact file.",
        )
    })?;
    let current = Utf8PathBuf::from_path_buf(current).map_err(CliError::NonUtf8Path)?;
    Ok(current.join(path))
}

fn evidence_unavailable_error(view: Option<&ManagedArtifactViewV1>, reason: &str) -> CliError {
    CliError::JobsLifecycle {
        code: "artifact_evidence_unavailable",
        message: "strict artifact evidence is unavailable".to_owned(),
        help: "Retain the complete verified compile/product evidence set and retry verification. Integrity evidence remains reported but is not strict product validation."
            .to_owned(),
        details: view
            .map(artifact_details)
            .unwrap_or_default()
            .into_iter()
            .chain([format!("reason={reason}")])
            .collect(),
    }
}

fn map_offline_error(error: OfflineArtifactError, view: &ManagedArtifactViewV1) -> CliError {
    let code = offline_error_code(error);
    artifact_failure(
        code,
        error.to_string(),
        "Preserve the exact managed file and job evidence, correct the reported mismatch, then retry without bypassing strict verification.",
        view,
    )
}

fn map_unmanaged_offline_error(error: OfflineArtifactError) -> CliError {
    unmanaged_artifact_failure(
        offline_error_code(error),
        error.to_string(),
        "Use one absolute normal single-link local file, correct the reported mismatch, then retry without bypassing inspection.",
    )
}

const fn offline_error_code(error: OfflineArtifactError) -> &'static str {
    match error {
        OfflineArtifactError::InvalidInput => "artifact_verification_input_invalid",
        OfflineArtifactError::InvalidPath => "artifact_path_invalid",
        OfflineArtifactError::UnsafeFilesystemObject => "artifact_filesystem_object_unsafe",
        OfflineArtifactError::ResourceLimitExceeded => "artifact_resource_limit_exceeded",
        OfflineArtifactError::InvalidZip => "artifact_zip_invalid",
        OfflineArtifactError::UnsafeZip => "artifact_zip_unsafe",
        OfflineArtifactError::IntegrityMismatch => "artifact_integrity_mismatch",
        OfflineArtifactError::EvidenceMismatch => "artifact_evidence_mismatch",
        OfflineArtifactError::ProductValidationFailed => "artifact_product_validation_failed",
        OfflineArtifactError::LocalIo => "artifact_local_io_failed",
    }
}

fn artifact_failure(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    view: &ManagedArtifactViewV1,
) -> CliError {
    CliError::Remote {
        code,
        message: message.into(),
        help: help.into(),
        details: artifact_details(view),
    }
}

fn unmanaged_artifact_failure(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
) -> CliError {
    CliError::Remote {
        code,
        message: message.into(),
        help: help.into(),
        details: Vec::new(),
    }
}

fn artifact_lifecycle_error(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    view: &ManagedArtifactViewV1,
) -> CliError {
    CliError::JobsLifecycle {
        code,
        message: message.into(),
        help: help.into(),
        details: artifact_details(view),
    }
}

fn artifact_details(view: &ManagedArtifactViewV1) -> Vec<String> {
    vec![
        format!("local_job_id={}", view.artifact_ref.local_job_id.as_str()),
        format!(
            "provider_artifact_id={}",
            view.artifact_ref.provider_artifact_id
        ),
    ]
}

fn verify_reveal_guards(
    retained_file: &RetainedRegularFileIdentity,
    retained_parent: &RetainedDirectoryIdentity,
    file: &ManagedArtifactFile,
    parent: &Utf8Path,
    view: &ManagedArtifactViewV1,
) -> Result<(), CliError> {
    retained_parent
        .verify_path(parent.as_std_path())
        .and_then(|()| retained_file.verify_path(file.path.as_std_path()))
        .map_err(|_| {
            artifact_failure(
                "artifact_reveal_uncertain",
                "the managed artifact or its parent changed while the reveal request was prepared",
                "Do not treat the revealed path as the recorded artifact; inspect the path and download a fresh exact artifact before use.",
                view,
            )
        })
}

fn reveal_plan(path: &Utf8Path) -> Result<RevealPlan, CliError> {
    let parent = path.parent().ok_or_else(|| CliError::Unsupported {
        message: "the managed artifact path has no revealable parent".to_owned(),
        help: "Inspect the managed path and restore a valid absolute artifact location.".to_owned(),
    })?;
    if !parent.is_absolute() {
        return Err(CliError::Unsupported {
            message: "the managed artifact path is not absolute".to_owned(),
            help: "Inspect the durable job record and restore its exact absolute artifact path."
                .to_owned(),
        });
    }
    reveal_plan_platform(path, parent)
}

#[cfg(windows)]
fn reveal_plan_platform(path: &Utf8Path, _parent: &Utf8Path) -> Result<RevealPlan, CliError> {
    let system_root = rustferry_core::windows_system_root()
        .map_err(|_| reveal_tool_missing("Windows Explorer", Vec::new()))?;
    let system_root = Utf8PathBuf::from_path_buf(system_root).map_err(CliError::NonUtf8Path)?;
    let program = system_root.join("explorer.exe");
    if !std::fs::symlink_metadata(&program)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        return Err(reveal_tool_missing(
            "Windows Explorer",
            vec![program.to_string()],
        ));
    }
    let system32 = system_root.join("System32");
    Ok(RevealPlan {
        program,
        arguments: vec![format!("/select,{path}")],
        current_directory: system_root.clone(),
        environment: vec![
            (
                OsString::from("SystemRoot"),
                OsString::from(system_root.as_str()),
            ),
            (
                OsString::from("WINDIR"),
                OsString::from(system_root.as_str()),
            ),
            (
                OsString::from("PATH"),
                OsString::from(format!("{system32};{system_root}")),
            ),
            (
                OsString::from("COMSPEC"),
                OsString::from(system32.join("cmd.exe").as_str()),
            ),
        ],
        exact_path_binding_supported: true,
    })
}

#[cfg(target_os = "macos")]
fn reveal_plan_platform(path: &Utf8Path, _parent: &Utf8Path) -> Result<RevealPlan, CliError> {
    fixed_reveal_plan("/usr/bin/open", ["-R", path.as_str()])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn reveal_plan_platform(_path: &Utf8Path, parent: &Utf8Path) -> Result<RevealPlan, CliError> {
    fixed_reveal_plan("/usr/bin/xdg-open", [parent.as_str()])
}

#[cfg(unix)]
fn fixed_reveal_plan<const N: usize>(
    program: &str,
    arguments: [&str; N],
) -> Result<RevealPlan, CliError> {
    let program = Utf8PathBuf::from(program);
    if !program.is_file() {
        return Err(reveal_tool_missing(
            "platform file manager",
            vec![program.to_string()],
        ));
    }
    Ok(RevealPlan {
        program,
        arguments: arguments.into_iter().map(ToOwned::to_owned).collect(),
        current_directory: Utf8PathBuf::from("/"),
        environment: vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("LANG"), OsString::from("C")),
        ],
        exact_path_binding_supported: false,
    })
}

fn reveal_tool_missing(tool: &str, searched: Vec<String>) -> CliError {
    CliError::ToolMissing {
        tool: tool.to_owned(),
        searched,
        help: "Install or restore the platform's standard file-manager launcher, then retry."
            .to_owned(),
    }
}

fn execute_reveal_plan(plan: &RevealPlan, reporter: &Reporter) -> Result<(), CliError> {
    let arguments = plan
        .arguments
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let output = run_captured_bounded_with_exact_environment(
        &plan.program,
        &arguments,
        &plan.current_directory,
        "reveal managed artifact",
        reporter,
        REVEAL_OUTPUT_LIMIT,
        &plan.environment,
    )?;
    if !output.status.success() {
        return Err(CliError::CommandFailed {
            tool: plan.program.to_string(),
            stage: "reveal managed artifact",
            status: output.status.code(),
            stderr: String::new(),
            log: None,
            help: "Open the exact local path from `cargo ferry artifact show`, or restore the platform file manager and retry."
                .to_owned(),
        });
    }
    Ok(())
}

fn unix_time_ms() -> Result<u64, CliError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| system_clock_error())?;
    u64::try_from(elapsed.as_millis()).map_err(|_| system_clock_error())
}

fn system_clock_error() -> CliError {
    CliError::JobsLifecycle {
        code: "system_clock_invalid",
        message: "the system clock is outside the supported Unix millisecond range".to_owned(),
        help: "Correct the system clock before committing a durable artifact-removal result."
            .to_owned(),
        details: Vec::new(),
    }
}

fn parse_local_job_id(value: &str) -> Result<LocalJobId, String> {
    LocalJobId::new(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_provider_artifact_id(value: &str) -> Result<String, String> {
    let valid = !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(value.to_owned())
    } else {
        Err(
            "provider artifact ID must be 1-160 ASCII letters, digits, '-', '_', '.', or ':'"
                .to_owned(),
        )
    }
}

impl From<&ManagedArtifactViewV1> for ArtifactSelectorOutputV1 {
    fn from(view: &ManagedArtifactViewV1) -> Self {
        Self {
            local_job_id: view.artifact_ref.local_job_id.as_str().to_owned(),
            provider_artifact_id: view.artifact_ref.provider_artifact_id.clone(),
        }
    }
}

fn managed_artifact_output(
    view: &ManagedArtifactViewV1,
    job: &StoredJobV1,
) -> Result<ManagedArtifactOutputV1, CliError> {
    if job.local_job_id != view.artifact_ref.local_job_id {
        return Err(artifact_failure(
            "artifact_job_provenance_mismatch",
            "the artifact index points to a different owning job",
            "Preserve the local job store and reconcile its immutable artifact index.",
            view,
        ));
    }
    let artifact = job
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.record == view.record
                && artifact.local_path == view.local_path
                && artifact.local_file_identity == view.local_file_identity
        })
        .ok_or_else(|| {
            artifact_failure(
                "artifact_job_provenance_mismatch",
                "the managed artifact does not match its owning job record",
                "Preserve the local job store and reconcile its immutable artifact index.",
                view,
            )
        })?;
    Ok(ManagedArtifactOutputV1 {
        selector: ArtifactSelectorOutputV1::from(view),
        job: ArtifactJobOutputV1 {
            provider: job.provider.provider.clone(),
            target: job.target.clone(),
            profile: profile_name(job.profile),
            requested_signing_mode: signing_mode_name(job.signing_mode),
            request_sha256: job.request_sha256.clone(),
            source_revision: job.source.revision.clone(),
            source_manifest_sha256: job.source.manifest_sha256.clone(),
            created_at_ms: job.created_at_ms,
            updated_at_ms: job.updated_at_ms,
        },
        record: view.record.clone(),
        local_path: view.local_path.clone(),
        local_file_identity: view.local_file_identity.clone(),
        locally_validated: artifact.locally_validated,
        local_validation_level: if artifact.locally_validated {
            "integrity"
        } else {
            "not_revalidated"
        },
        remote_validation_levels: remote_validation_levels(job, &view.record),
        signature_evidence: signature_evidence(job, &view.record),
        removal_state: removal_state_name(view.removal_state),
        removal_updated_at_ms: view.removal_updated_at_ms,
    })
}

fn job_manifests(job: &StoredJobV1) -> &[ArtifactManifest] {
    job.provider_resume
        .as_ref()
        .map_or(&[], |resume| resume.manifests.as_slice())
}

fn matching_manifests<'a>(
    manifests: &'a [ArtifactManifest],
    record: &'a ArtifactRecord,
) -> impl Iterator<Item = &'a ArtifactManifest> {
    manifests
        .iter()
        .filter(|manifest| manifest.artifacts.contains(record))
}

fn remote_validation_levels(job: &StoredJobV1, record: &ArtifactRecord) -> Vec<ValidationLevel> {
    remote_validation_levels_from_manifests(job_manifests(job), record)
}

fn remote_validation_levels_from_manifests(
    manifests: &[ArtifactManifest],
    record: &ArtifactRecord,
) -> Vec<ValidationLevel> {
    matching_manifests(manifests, record)
        .flat_map(|manifest| &manifest.validation_levels)
        .copied()
        .filter(|level| remote_level_applies_to_artifact(record.kind, *level))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

const fn remote_level_applies_to_artifact(kind: ArtifactKind, level: ValidationLevel) -> bool {
    match level {
        ValidationLevel::ArtifactValidated => true,
        ValidationLevel::ArchiveBuilt => matches!(kind, ArtifactKind::Xcarchive),
        ValidationLevel::AppBundleBuilt => matches!(kind, ArtifactKind::App),
        ValidationLevel::CertificateValidated
        | ValidationLevel::ProvisioningValidated
        | ValidationLevel::NestedCodeSigned
        | ValidationLevel::ApplicationSigned
        | ValidationLevel::IpaExported => matches!(kind, ArtifactKind::Ipa),
        ValidationLevel::SourceValidated
        | ValidationLevel::RemoteBuilderValidated
        | ValidationLevel::DeviceTargetCompiled
        | ValidationLevel::DeviceBinaryBuilt
        | ValidationLevel::DownloadedToClient
        | ValidationLevel::InstallValidated
        | ValidationLevel::LaunchValidated
        | ValidationLevel::RuntimeValidated => false,
    }
}

fn signature_evidence(job: &StoredJobV1, record: &ArtifactRecord) -> ArtifactSignatureEvidenceV1 {
    let unsigned_archive_matches = job.compile_evidence.as_ref().is_some_and(|compile| {
        compile.sealed_archive.transport.size == record.size
            && compile.sealed_archive.transport.sha256 == record.sha256
    });
    signature_evidence_from_manifests(job_manifests(job), record, unsigned_archive_matches)
}

fn signature_evidence_from_manifests(
    manifests: &[ArtifactManifest],
    record: &ArtifactRecord,
    unsigned_archive_matches: bool,
) -> ArtifactSignatureEvidenceV1 {
    if !matches!(
        record.kind,
        ArtifactKind::App | ArtifactKind::Xcarchive | ArtifactKind::Ipa
    ) {
        return ArtifactSignatureEvidenceV1::NotApplicable;
    }
    if matches!(record.kind, ArtifactKind::App | ArtifactKind::Ipa)
        && matching_manifests(manifests, record).any(|manifest| {
            manifest.signing.mode.is_signed()
                && manifest.signing.status == SigningStatus::ArtifactValidated
                && manifest
                    .validation_levels
                    .contains(&ValidationLevel::ApplicationSigned)
                && manifest
                    .validation_levels
                    .contains(&ValidationLevel::ArtifactValidated)
                && (record.kind != ArtifactKind::Ipa
                    || manifest
                        .validation_levels
                        .contains(&ValidationLevel::IpaExported))
        })
    {
        return ArtifactSignatureEvidenceV1::Signed;
    }
    if record.kind == ArtifactKind::Xcarchive && unsigned_archive_matches {
        return ArtifactSignatureEvidenceV1::Unsigned;
    }
    ArtifactSignatureEvidenceV1::Unknown
}

const fn removal_state_name(state: ManagedArtifactRemovalState) -> &'static str {
    match state {
        ManagedArtifactRemovalState::Available => "available",
        ManagedArtifactRemovalState::Intent => "intent",
        ManagedArtifactRemovalState::Removed => "removed",
        ManagedArtifactRemovalState::Uncertain => "uncertain",
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

const fn validation_level_name(level: ValidationLevel) -> &'static str {
    match level {
        ValidationLevel::SourceValidated => "source_validated",
        ValidationLevel::RemoteBuilderValidated => "remote_builder_validated",
        ValidationLevel::DeviceTargetCompiled => "device_target_compiled",
        ValidationLevel::DeviceBinaryBuilt => "device_binary_built",
        ValidationLevel::AppBundleBuilt => "app_bundle_built",
        ValidationLevel::ArchiveBuilt => "archive_built",
        ValidationLevel::CertificateValidated => "certificate_validated",
        ValidationLevel::ProvisioningValidated => "provisioning_validated",
        ValidationLevel::NestedCodeSigned => "nested_code_signed",
        ValidationLevel::ApplicationSigned => "application_signed",
        ValidationLevel::IpaExported => "ipa_exported",
        ValidationLevel::ArtifactValidated => "artifact_validated",
        ValidationLevel::DownloadedToClient => "downloaded_to_client",
        ValidationLevel::InstallValidated => "install_validated",
        ValidationLevel::LaunchValidated => "launch_validated",
        ValidationLevel::RuntimeValidated => "runtime_validated",
    }
}

const fn signature_evidence_name(evidence: ArtifactSignatureEvidenceV1) -> &'static str {
    match evidence {
        ArtifactSignatureEvidenceV1::Signed => "signed",
        ArtifactSignatureEvidenceV1::Unsigned => "unsigned",
        ArtifactSignatureEvidenceV1::Unknown => "unknown",
        ArtifactSignatureEvidenceV1::NotApplicable => "not_applicable",
    }
}

fn rendered_validation_levels(levels: &[ValidationLevel]) -> String {
    if levels.is_empty() {
        return "unknown".to_owned();
    }
    levels
        .iter()
        .copied()
        .map(validation_level_name)
        .collect::<Vec<_>>()
        .join(",")
}

fn render_artifact_list(output: &ArtifactListOutputV1) -> String {
    if output.artifacts.is_empty() {
        return output.local_job_id.as_deref().map_or_else(
            || "No managed local artifacts are recorded.".to_owned(),
            |job| format!("Job {job} has no managed local artifacts."),
        );
    }
    output
        .artifacts
        .iter()
        .map(|artifact| {
            format!(
                concat!(
                    "{}/{} kind={} target={} profile={} requested_signing={} signature={} ",
                    "remote_validation={} local_validation={} size={} sha256={} ",
                    "source_sha256={} request_sha256={} provider={} created_at_ms={} ",
                    "updated_at_ms={} removal_state={} path={}"
                ),
                artifact.selector.local_job_id,
                artifact.selector.provider_artifact_id,
                artifact_kind_name(artifact.record.kind),
                artifact.job.target,
                artifact.job.profile,
                artifact.job.requested_signing_mode,
                signature_evidence_name(artifact.signature_evidence),
                rendered_validation_levels(&artifact.remote_validation_levels),
                artifact.local_validation_level,
                artifact.record.size,
                artifact.record.sha256,
                artifact.job.source_manifest_sha256,
                artifact.job.request_sha256,
                artifact.job.provider,
                artifact.job.created_at_ms,
                artifact.job.updated_at_ms,
                artifact.removal_state,
                artifact.local_path.as_deref().unwrap_or("<not-downloaded>")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_artifact_show(output: &ArtifactShowOutputV1) -> String {
    let artifact = &output.artifact;
    format!(
        concat!(
            "local_job_id: {}\n",
            "provider_artifact_id: {}\n",
            "provider: {}\n",
            "target: {}\n",
            "profile: {}\n",
            "requested_signing_mode: {}\n",
            "signature_evidence: {}\n",
            "source_revision: {}\n",
            "source_manifest_sha256: {}\n",
            "request_sha256: {}\n",
            "job_created_at_ms: {}\n",
            "job_updated_at_ms: {}\n",
            "kind: {}\n",
            "file_name: {}\n",
            "size: {}\n",
            "sha256: {}\n",
            "media_type: {}\n",
            "local_path: {}\n",
            "local_file_identity: {}\n",
            "locally_validated: {}\n",
            "local_validation_level: {}\n",
            "remote_validation_levels: {}\n",
            "removal_state: {}"
        ),
        artifact.selector.local_job_id,
        artifact.selector.provider_artifact_id,
        artifact.job.provider,
        artifact.job.target,
        artifact.job.profile,
        artifact.job.requested_signing_mode,
        signature_evidence_name(artifact.signature_evidence),
        artifact.job.source_revision.as_deref().unwrap_or("-"),
        artifact.job.source_manifest_sha256,
        artifact.job.request_sha256,
        artifact.job.created_at_ms,
        artifact.job.updated_at_ms,
        artifact_kind_name(artifact.record.kind),
        artifact.record.file_name,
        artifact.record.size,
        artifact.record.sha256,
        artifact.record.media_type.as_deref().unwrap_or("-"),
        artifact.local_path.as_deref().unwrap_or("-"),
        artifact.local_file_identity.as_deref().unwrap_or("-"),
        artifact.locally_validated,
        artifact.local_validation_level,
        rendered_validation_levels(&artifact.remote_validation_levels),
        artifact.removal_state,
    )
}

fn render_artifact_inspect(output: &ArtifactInspectOutputV1) -> String {
    format!(
        "Artifact path {:?} passed bounded local inspection: size={} sha256={} filesystem_identity={}",
        output.path,
        output.inspection.size,
        output.inspection.sha256,
        output.inspection.filesystem_identity,
    )
}

fn render_artifact_verify(output: &ArtifactVerifyOutputV1) -> String {
    let subject = output.artifact.as_ref().map_or_else(
        || format!("path {:?}", output.path),
        |artifact| {
            format!(
                "{}/{}",
                artifact.local_job_id, artifact.provider_artifact_id
            )
        },
    );
    match &output.result {
        ArtifactVerificationResultV1::Verified { verification } => format!(
            "Artifact {subject} verified at {:?} evidence level.",
            verification.evidence_level
        ),
        ArtifactVerificationResultV1::EvidenceUnavailable {
            reason, inspection, ..
        } if output.artifact.is_some() => format!(
            "Artifact {subject} integrity is verified (size={}, sha256={}), but strict product evidence is unavailable: {reason}.",
            inspection.size, inspection.sha256,
        ),
        ArtifactVerificationResultV1::EvidenceUnavailable {
            reason, inspection, ..
        } => format!(
            "Artifact {subject} bytes were inspected (size={}, sha256={}), but no managed integrity or product evidence is available: {reason}.",
            inspection.size, inspection.sha256,
        ),
    }
}

fn render_artifact_reveal(output: &ArtifactRevealOutputV1) -> String {
    if output.launch_requested {
        format!(
            "Requested the platform file manager to reveal managed artifact {} (exact_path_bound_during_launch={}).",
            output.local_path, output.exact_path_bound_during_launch,
        )
    } else {
        format!(
            "Would request the platform file manager to reveal managed artifact {} with {}.",
            output.local_path, output.launcher
        )
    }
}

fn render_artifact_remove(output: &ArtifactRemoveOutputV1) -> String {
    if output.already_complete == Some(true) {
        format!(
            "Managed artifact {}/{} was already removed; no removal was executed.",
            output.artifact.local_job_id, output.artifact.provider_artifact_id,
        )
    } else if output.executed {
        format!(
            "Removed exact managed artifact {}/{}.",
            output.artifact.local_job_id, output.artifact.provider_artifact_id,
        )
    } else {
        format!(
            "Would remove exact managed artifact {}/{} from current state {} after write-time revalidation.",
            output.artifact.local_job_id,
            output.artifact.provider_artifact_id,
            output.current_state,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use cargo_ferry::job_store::{
        JOB_STORE_SCHEMA_VERSION, ManagedArtifactRefV1, ManagedArtifactRemovalState,
        StoredArtifactV1, StoredCancellationStatus, StoredCleanupStatus, StoredJobState,
        StoredProjectIdentityV1, StoredProviderIdentityV1, StoredRetryLineageV1,
        StoredSourceIdentityV1,
    };
    use clap::Parser;
    use rustferry_core::{DirectoryFilesystemIdentity, RegularFileFilesystemIdentity};
    use rustferry_github::provider::{GITHUB_PROVIDER_ID, GithubPrincipalIdentityV1};
    use rustferry_remote::{
        BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType, IosDeviceBuildRequest,
        IosDeviceProductExpectation, SigningPlan, SigningTarget, SigningTargetKind, SourceManifest,
        SourceMode, canonical_request_sha256, canonical_retry_template_sha256_v1,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Debug, Parser)]
    struct ArtifactTestParser {
        #[command(subcommand)]
        command: ArtifactCommand,
    }

    #[test]
    fn provider_artifact_selector_is_one_bounded_component() {
        assert_eq!(
            parse_provider_artifact_id("signed-ipa:1").unwrap(),
            "signed-ipa:1"
        );
        for invalid in ["", "../ipa", "ipa/child", "ipa\\child", "ipa\nchild"] {
            assert!(parse_provider_artifact_id(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn remove_parser_accepts_a_bare_id_and_an_optional_job_qualifier() {
        let bare = ArtifactTestParser::try_parse_from([
            "artifact-test",
            "remove",
            "artifact-one",
            "--yes",
        ])
        .unwrap();
        let ArtifactCommand::Remove(bare) = bare.command else {
            panic!("remove command");
        };
        assert_eq!(bare.provider_artifact_id, "artifact-one");
        assert!(bare.job.is_none());
        assert!(bare.yes);

        let qualified = ArtifactTestParser::try_parse_from([
            "artifact-test",
            "remove",
            "artifact-one",
            "--job",
            "job-artifact-one",
        ])
        .unwrap();
        let ArtifactCommand::Remove(qualified) = qualified.command else {
            panic!("remove command");
        };
        assert_eq!(
            qualified.job.as_ref().map(LocalJobId::as_str),
            Some("job-artifact-one")
        );
        assert!(!qualified.yes);
    }

    #[test]
    fn unqualified_remove_resolves_one_real_store_match_but_rejects_two() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let store = JobStore::open_at(root.path().join("config")).unwrap();
        let first = persist_removal_test_artifact(&store, &project, "job-artifact-one");

        let unique = resolve_removal_artifact(&store, "shared-artifact", None).unwrap();
        assert_eq!(unique.artifact_ref.local_job_id, first);

        let second = persist_removal_test_artifact(&store, &project, "job-artifact-two");
        let error = resolve_removal_artifact(&store, "shared-artifact", None).unwrap_err();
        assert_eq!(error.code(), "artifact_reference_ambiguous");

        let qualified = resolve_removal_artifact(&store, "shared-artifact", Some(&second)).unwrap();
        assert_eq!(qualified.artifact_ref.local_job_id, second);
    }

    #[test]
    fn ide_receipts_remain_path_free_and_preserve_honest_evidence() {
        let verification = OfflineArtifactVerification {
            schema_version: 1,
            artifact_id: "sanitized-log".to_owned(),
            artifact_kind: ArtifactKind::SanitizedLog,
            file_name: "sanitized.log".to_owned(),
            evidence_level: OfflineArtifactEvidenceLevel::ArchiveSafety,
            outcome: OfflineArtifactVerificationOutcome::EvidenceUnavailable,
            inspection: OfflineArtifactInspection {
                schema_version: 1,
                size: 42,
                sha256: "a".repeat(64),
                filesystem_identity: "regular-file-v1:test".to_owned(),
                container: OfflineArtifactContainer::Zip {
                    entry_count: 3,
                    expanded_size: 99,
                },
            },
            validation_levels: BTreeSet::from([ValidationLevel::DownloadedToClient]),
            product: None,
            signed_cleanup_evidence_bound: false,
        };
        let receipt = ide_verification_receipt(
            IdeArtifactSelectionReceipt {
                local_job_id: "job-test".to_owned(),
                artifact_id: "sanitized-log".to_owned(),
                revision: 7,
            },
            ArtifactKind::SanitizedLog,
            IdeArtifactVerifyOutcome::EvidenceUnavailable,
            verification,
            "strict_product_evidence_unavailable",
        );
        assert_eq!(
            receipt.evidence_level,
            IdeArtifactEvidenceLevel::ArchiveSafety
        );
        assert_eq!(receipt.validation_levels, ["downloaded_to_client"]);
        assert_eq!(receipt.product, IdeArtifactProductReceipt::NotApplicable);
        assert_eq!(receipt.integrity.size, 42);
        assert_eq!(
            receipt.integrity.container,
            IdeArtifactContainerReceipt::Zip {
                entry_count: 3,
                expanded_size: 99,
            }
        );
        assert_eq!(
            ide_product_receipt(ArtifactKind::Ipa, None, "compile_evidence_unavailable"),
            IdeArtifactProductReceipt::EvidenceUnavailable {
                reason_code: "compile_evidence_unavailable",
            }
        );

        let reveal = IdeArtifactRevealReceipt {
            artifact: receipt.artifact,
            launcher: "explorer.exe".to_owned(),
            environment_policy: "fixed_no_inheritance",
            launch_requested: true,
            exact_path_bound_during_launch: true,
            post_launch_revalidation: "passed",
        };
        let value = serde_json::to_value(reveal).unwrap();
        for forbidden in ["local_path", "arguments", "working_directory"] {
            assert!(value.get(forbidden).is_none(), "{forbidden}");
        }
    }

    #[test]
    fn ide_remove_receipt_distinguishes_execution_from_idempotent_completion() {
        let output = |already_complete| ArtifactRemoveOutputV1 {
            schema_version: ARTIFACT_OUTPUT_SCHEMA_VERSION,
            dry_run: false,
            artifact: ArtifactSelectorOutputV1 {
                local_job_id: "job-test".to_owned(),
                provider_artifact_id: "artifact-test".to_owned(),
            },
            confirmation_provided: true,
            current_state: if already_complete {
                "removed"
            } else {
                "available"
            },
            executed: true,
            result_state: Some("removed"),
            already_complete: Some(already_complete),
        };

        let removed = ide_remove_receipt(output(false), 7);
        assert!(removed.executed);
        assert!(!removed.already_complete);
        assert_eq!(removed.result_state, IdeArtifactRemoveResult::Removed);

        let already_removed = ide_remove_receipt(output(true), 7);
        assert!(!already_removed.executed);
        assert!(already_removed.already_complete);
        assert_eq!(
            already_removed.result_state,
            IdeArtifactRemoveResult::AlreadyRemoved
        );
    }

    #[test]
    fn completed_remove_output_reports_an_idempotent_no_op_distinctly() {
        let root = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("artifact.log")).unwrap();
        fs::write(&path, b"sanitized\n").unwrap();
        let view = managed_view(&path, b"sanitized\n");

        let removed = completed_remove_output(&view, "available", false);
        assert!(removed.executed);
        assert_eq!(
            render_artifact_remove(&removed),
            "Removed exact managed artifact job-artifact-test/sanitized-log."
        );

        let already_removed = completed_remove_output(&view, "removed", true);
        assert!(!already_removed.executed);
        assert_eq!(already_removed.already_complete, Some(true));
        assert_eq!(
            serde_json::to_value(&already_removed).unwrap()["executed"],
            false
        );
        assert_eq!(
            render_artifact_remove(&already_removed),
            "Managed artifact job-artifact-test/sanitized-log was already removed; no removal was executed."
        );
    }

    #[test]
    fn ide_action_eligibility_uses_stable_path_free_reason_codes() {
        assert_eq!(ide_action_eligibility(Ok(())), (true, None));
        assert_eq!(
            ide_action_eligibility(Err(CliError::Unsupported {
                message: "private path and details".to_owned(),
                help: "private help".to_owned(),
            })),
            (false, Some("unsupported".to_owned()))
        );
    }

    #[test]
    fn inspect_requires_the_exact_managed_identity_after_same_byte_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("artifact.log")).unwrap();
        fs::write(&path, b"sanitized\n").unwrap();
        let view = managed_view(&path, b"sanitized\n");
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, b"sanitized\n").unwrap();
        fs::remove_file(&path).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let file = managed_available_file(&view).unwrap();
        let error = inspect_managed_file(&view, &file).unwrap_err();
        assert!(matches!(
            error.code(),
            "artifact_integrity_mismatch" | "artifact_filesystem_object_unsafe"
        ));
    }

    #[test]
    fn unavailable_and_removed_artifacts_never_reach_local_inspection() {
        let root = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("artifact.log")).unwrap();
        fs::write(&path, b"sanitized\n").unwrap();
        let mut view = managed_view(&path, b"sanitized\n");
        for (state, code) in [
            (
                ManagedArtifactRemovalState::Intent,
                "artifact_removal_in_progress",
            ),
            (ManagedArtifactRemovalState::Removed, "artifact_removed"),
            (
                ManagedArtifactRemovalState::Uncertain,
                "artifact_removal_uncertain",
            ),
        ] {
            view.removal_state = state;
            assert_eq!(
                managed_available_file(&view).unwrap_err().code(),
                code,
                "{state:?}"
            );
        }
    }

    #[test]
    fn reveal_uses_one_fixed_platform_program_and_argument_boundaries() {
        let path = Utf8Path::new(if cfg!(windows) {
            "C:/artifact folder/app.ipa"
        } else {
            "/tmp/artifact folder/app.ipa"
        });
        let plan = reveal_plan(path).unwrap();
        assert!(plan.program.is_absolute());
        assert!(!plan.arguments.is_empty());
        assert!(plan.current_directory.is_absolute());
        assert_ne!(plan.current_directory, path.parent().unwrap());
        let environment_names = plan
            .environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        for forbidden in [
            "BROWSER",
            "HOME",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "GH_TOKEN",
            "GITHUB_TOKEN",
        ] {
            assert!(!environment_names.contains(forbidden));
        }
        #[cfg(windows)]
        {
            assert_eq!(plan.program.file_name(), Some("explorer.exe"));
            assert_eq!(plan.arguments, [format!("/select,{path}")]);
            assert!(plan.exact_path_binding_supported);
            assert_eq!(plan.current_directory, plan.program.parent().unwrap());
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(plan.arguments, ["-R", path.as_str()]);
            assert!(!plan.exact_path_binding_supported);
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            assert_eq!(plan.arguments, [path.parent().unwrap().as_str()]);
            assert!(!plan.exact_path_binding_supported);
        }
    }

    #[test]
    fn requested_signed_mode_without_exact_signature_evidence_remains_unknown() {
        let ipa = artifact_record(ArtifactKind::Ipa, "signed-ipa");
        let mut manifest = ArtifactManifest::new("operation", "provider-job");
        manifest.artifacts.push(ipa.clone());
        manifest.signing.mode = SigningMode::Development;
        assert_eq!(
            signature_evidence_from_manifests(&[manifest], &ipa, false),
            ArtifactSignatureEvidenceV1::Unknown
        );
    }

    #[test]
    fn exact_remote_evidence_excludes_client_download_validation() {
        let ipa = artifact_record(ArtifactKind::Ipa, "signed-ipa");
        let unrelated = artifact_record(ArtifactKind::Ipa, "other-ipa");
        let mut manifest = ArtifactManifest::new("operation", "provider-job");
        manifest.artifacts.push(ipa.clone());
        manifest.signing.mode = SigningMode::Development;
        manifest.signing.status = SigningStatus::ArtifactValidated;
        manifest.validation_levels = BTreeSet::from([
            ValidationLevel::ApplicationSigned,
            ValidationLevel::IpaExported,
            ValidationLevel::ArtifactValidated,
            ValidationLevel::DownloadedToClient,
        ]);

        let levels = remote_validation_levels_from_manifests(&[manifest.clone()], &ipa);
        assert!(levels.contains(&ValidationLevel::ApplicationSigned));
        assert!(levels.contains(&ValidationLevel::IpaExported));
        assert!(levels.contains(&ValidationLevel::ArtifactValidated));
        assert!(!levels.contains(&ValidationLevel::DownloadedToClient));
        assert_eq!(
            signature_evidence_from_manifests(&[manifest.clone()], &ipa, false),
            ArtifactSignatureEvidenceV1::Signed
        );
        assert!(remote_validation_levels_from_manifests(&[manifest], &unrelated).is_empty());
    }

    fn persist_removal_test_artifact(
        store: &JobStore,
        project: &std::path::Path,
        local_job_id: &str,
    ) -> LocalJobId {
        let mut record = removal_test_record(project, local_job_id);
        store.create(&record).unwrap();
        for state in [StoredJobState::Submitting, StoredJobState::Running] {
            record = next_removal_test_revision(record, state);
            store.append(&record).unwrap();
        }
        record = next_removal_test_revision(record, StoredJobState::ArtifactReady);
        record.artifacts = vec![StoredArtifactV1 {
            record: ArtifactRecord {
                artifact_id: "shared-artifact".to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: format!("{local_job_id}.log"),
                size: 1,
                sha256: "a".repeat(64),
                media_type: Some("text/plain; charset=utf-8".to_owned()),
            },
            download_destination: None,
            download_parent_identity: None,
            local_path: None,
            local_file_identity: None,
            locally_validated: false,
        }];
        store.append(&record).unwrap();
        record.local_job_id
    }

    fn next_removal_test_revision(mut record: StoredJobV1, state: StoredJobState) -> StoredJobV1 {
        record.revision += 1;
        record.updated_at_ms += 1;
        record.state = state;
        record.last_confirmed_state = Some(state);
        record
    }

    fn removal_test_record(project: &std::path::Path, local_job_id: &str) -> StoredJobV1 {
        let request = removal_test_request(local_job_id);
        let project = Utf8PathBuf::from_path_buf(project.canonicalize().unwrap()).unwrap();
        StoredJobV1 {
            schema_version: JOB_STORE_SCHEMA_VERSION,
            local_job_id: LocalJobId::new(local_job_id).unwrap(),
            revision: 1,
            project: StoredProjectIdentityV1 {
                canonical_root: project.to_string(),
                filesystem_identity: DirectoryFilesystemIdentity::capture(project.as_std_path())
                    .unwrap()
                    .to_string(),
                application_identifier: request.bundle_identifier.clone(),
            },
            provider: StoredProviderIdentityV1 {
                provider: GITHUB_PROVIDER_ID.to_owned(),
                provider_config_sha256: "a".repeat(64),
                principal: GithubPrincipalIdentityV1::User {
                    id: 7,
                    login: "artifact-test-user".to_owned(),
                },
                execution_repository: "https://github.com/example/artifact-test".to_owned(),
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
            updated_at_ms: 100,
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

    fn removal_test_request(local_job_id: &str) -> IosDeviceBuildRequest {
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: format!("operation-{local_job_id}"),
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
            source_repository: Some("https://github.com/example/artifact-test".to_owned()),
            source_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            source: empty_removal_test_manifest(),
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

    fn empty_removal_test_manifest() -> SourceManifest {
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

    fn artifact_record(kind: ArtifactKind, artifact_id: &str) -> ArtifactRecord {
        ArtifactRecord {
            artifact_id: artifact_id.to_owned(),
            kind,
            file_name: format!("{artifact_id}.zip"),
            size: 1,
            sha256: "a".repeat(64),
            media_type: Some("application/zip".to_owned()),
        }
    }

    fn managed_view(path: &Utf8Path, bytes: &[u8]) -> ManagedArtifactViewV1 {
        let identity = RegularFileFilesystemIdentity::capture(path.as_std_path())
            .unwrap()
            .to_string();
        ManagedArtifactViewV1 {
            artifact_ref: ManagedArtifactRefV1 {
                local_job_id: LocalJobId::new("job-artifact-test").unwrap(),
                provider_artifact_id: "sanitized-log".to_owned(),
            },
            record: ArtifactRecord {
                artifact_id: "sanitized-log".to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: "sanitized-build-log.txt".to_owned(),
                size: u64::try_from(bytes.len()).unwrap(),
                sha256: sha256(bytes),
                media_type: Some("text/plain; charset=utf-8".to_owned()),
            },
            local_path: Some(path.to_string()),
            local_file_identity: Some(identity),
            removal_state: ManagedArtifactRemovalState::Available,
            removal_updated_at_ms: None,
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        lower_hex(Sha256::digest(bytes))
    }

    fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = bytes.as_ref();
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}
