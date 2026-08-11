//! Zero-write GitHub snapshot preview and exact public-upload consent.

use std::io::{self, IsTerminal as _, Write as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use camino::Utf8Path;
use rustferry_github::git_endpoint::{GithubGitEndpoint, GithubGitTransport};
use rustferry_github::snapshot::{
    GIT_SNAPSHOT_STAGE_SCHEMA_VERSION, GitSnapshotKeepaliveRef, GitSnapshotObjectGraphV1,
    GitSnapshotPrecomputeInputs, GitSnapshotSourceRef, GitSnapshotStageDirectory,
    GitSnapshotStageLocatorV1, GitSnapshotStageV1,
};
use rustferry_remote::{
    GitSnapshotDescriptor, IosDeviceBuildRequest, SourceBundleDescriptor, SourceBundlePlan,
    SourceManifest, canonical_git_snapshot_descriptor_bytes, create_source_bundle_archive,
    git_snapshot_archive_limits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::CliError;
use crate::output::Reporter;

const CONSENT_SCHEMA_VERSION: u32 = 1;
const CONSENT_DOMAIN: &[u8] = b"rustferry-github-snapshot-consent-v1\0";
const ARCHIVE_STATUS_AFTER_CONSENT: &str = "computed_after_consent";
const REMOTE_RETENTION: &str = "until_terminal_cleanup";
const LOCAL_RETENTION: &str = "until_explicit_complete_lineage_prune";
const SECRET_SCAN_RESIDUAL: &str = "unrecognized_secrets_may_remain";
const PUBLIC_OBJECT_WARNING: &str = "Snapshot bytes enter the configured PUBLIC GitHub object database. Ref deletion is retention cleanup, not erasure.";
const INVOCATION_BOUND_DIGEST_WARNING: &str = "This consent SHA-256 is bound to this invocation's operation ID, timestamp, and source ref. A later invocation computes and authorizes a different exact digest.";
const IDE_CONSENT_TOKEN_DOMAIN: &[u8] = b"rustferry-ide-github-snapshot-consent-token-v1\0";
const IDE_CONSENT_TOKEN_MAX_BYTES: usize = 512;
const IDE_WORKSPACE_BINDING_DOMAIN: &[u8] = b"rustferry-ide-workspace-binding-v1\0";
const IDE_SOURCE_REPOSITORY_DOMAIN: &[u8] = b"rustferry-ide-source-repository-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeSnapshotPreview {
    pub(in crate::commands) preview_sha256: String,
    pub(in crate::commands) consent_token: String,
    pub(in crate::commands) source_manifest_sha256: String,
    pub(in crate::commands) file_count: u64,
    pub(in crate::commands) total_bytes: u64,
    pub(in crate::commands) effects: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands) struct DecodedIdeSnapshotConsent {
    pub(in crate::commands) profile: rustferry_remote::BuildProfile,
    pub(in crate::commands) operation_id: String,
    pub(in crate::commands) source_created_at_ms: u64,
    pub(in crate::commands) source_repository_sha256: String,
    pub(in crate::commands) preview_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdeSnapshotConsentTokenV1 {
    #[serde(rename = "v")]
    schema_version: u32,
    #[serde(rename = "w")]
    workspace_binding_sha256: String,
    #[serde(rename = "p")]
    profile: rustferry_remote::BuildProfile,
    #[serde(rename = "o")]
    operation_id: String,
    #[serde(rename = "t")]
    source_created_at_ms: u64,
    #[serde(rename = "r")]
    source_repository_sha256: String,
    #[serde(rename = "d")]
    preview_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct GithubSnapshotArchivePreviewV1 {
    pub(super) status: &'static str,
    pub(super) size: Option<u64>,
    pub(super) sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct GithubSnapshotConsentPlanV1 {
    pub(super) schema_version: u32,
    pub(super) operation_id: String,
    pub(super) source_created_at_ms: u64,
    pub(super) source_repository: String,
    pub(super) source_repository_visibility: &'static str,
    pub(super) source_ref: String,
    pub(super) source: SourceManifest,
    pub(super) path_dependencies: Vec<String>,
    pub(super) external_paths: Vec<String>,
    pub(super) excluded_sensitive_paths: Vec<String>,
    pub(super) archive: GithubSnapshotArchivePreviewV1,
    pub(super) remote_source_ref_retention: &'static str,
    pub(super) local_keepalive_retention: &'static str,
    pub(super) ref_deletion_erases_objects: bool,
    pub(super) secret_scan_residual: &'static str,
    pub(super) public_object_warning: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct GithubSnapshotPreviewV1 {
    pub(super) consent_sha256: String,
    pub(super) plan: GithubSnapshotConsentPlanV1,
}

#[derive(Debug)]
pub(super) struct StagedGithubSnapshotV1 {
    pub(super) request: IosDeviceBuildRequest,
    pub(super) locator: GitSnapshotStageLocatorV1,
    pub(super) stage: GitSnapshotStageV1,
}

impl GithubSnapshotPreviewV1 {
    pub(super) fn new(
        operation_id: &str,
        source_created_at_ms: u64,
        source_repository: &str,
        source: &SourceBundlePlan,
        path_dependencies: &[String],
    ) -> Result<Self, CliError> {
        let endpoint = GithubGitEndpoint::parse(source_repository).map_err(|_| {
            snapshot_error(
                "snapshot_source_repository_invalid",
                "the configured snapshot source repository is not a canonical GitHub endpoint",
                "Rerun GitHub setup with one credential-free canonical HTTPS source repository.",
                Vec::new(),
            )
        })?;
        if endpoint.transport() != GithubGitTransport::Https
            || endpoint.canonical_url() != source_repository
        {
            return Err(snapshot_error(
                "snapshot_source_repository_invalid",
                "the configured snapshot source repository is not canonical HTTPS",
                "Rerun GitHub setup with the exact normalized HTTPS source repository.",
                Vec::new(),
            ));
        }
        if source_created_at_ms / 1_000 > i64::MAX as u64 {
            return Err(snapshot_error(
                "snapshot_timestamp_invalid",
                "the snapshot commit timestamp is outside the supported range",
                "Correct the system clock before approving a GitHub snapshot.",
                Vec::new(),
            ));
        }
        let source_ref = GitSnapshotSourceRef::for_operation(operation_id).map_err(|_| {
            snapshot_error(
                "snapshot_operation_invalid",
                "the snapshot operation cannot derive its exact source ref",
                "Create a new build operation with a safe operation identifier.",
                Vec::new(),
            )
        })?;
        let mut path_dependencies = path_dependencies.to_vec();
        path_dependencies.sort();
        path_dependencies.dedup();
        let mut excluded_sensitive_paths = source.excluded_sensitive_paths().to_vec();
        excluded_sensitive_paths.sort();
        excluded_sensitive_paths.dedup();
        let plan = GithubSnapshotConsentPlanV1 {
            schema_version: CONSENT_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            source_created_at_ms,
            source_repository: source_repository.to_owned(),
            source_repository_visibility: "public",
            source_ref: source_ref.as_str().to_owned(),
            source: source.manifest().clone(),
            path_dependencies,
            external_paths: Vec::new(),
            excluded_sensitive_paths,
            archive: GithubSnapshotArchivePreviewV1 {
                status: ARCHIVE_STATUS_AFTER_CONSENT,
                size: None,
                sha256: None,
            },
            remote_source_ref_retention: REMOTE_RETENTION,
            local_keepalive_retention: LOCAL_RETENTION,
            ref_deletion_erases_objects: false,
            secret_scan_residual: SECRET_SCAN_RESIDUAL,
            public_object_warning: PUBLIC_OBJECT_WARNING,
        };
        let consent_sha256 = consent_sha256(&plan)?;
        Ok(Self {
            consent_sha256,
            plan,
        })
    }
}

pub(in crate::commands) fn ide_snapshot_preview(
    workspace_root: &Utf8Path,
    workspace_filesystem_identity: &str,
    profile: rustferry_remote::BuildProfile,
    preview: &GithubSnapshotPreviewV1,
) -> Result<IdeSnapshotPreview, CliError> {
    let payload = IdeSnapshotConsentTokenV1 {
        schema_version: 1,
        workspace_binding_sha256: ide_workspace_binding_sha256(
            workspace_root,
            workspace_filesystem_identity,
        ),
        profile,
        operation_id: preview.plan.operation_id.clone(),
        source_created_at_ms: preview.plan.source_created_at_ms,
        source_repository_sha256: ide_source_repository_sha256(&preview.plan.source_repository),
        preview_sha256: preview.consent_sha256.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| ide_token_error())?;
    let mut digest = Sha256::new();
    digest.update(IDE_CONSENT_TOKEN_DOMAIN);
    digest.update(&payload_bytes);
    let mut token_bytes = payload_bytes;
    token_bytes.extend_from_slice(&digest.finalize());
    let token = URL_SAFE_NO_PAD.encode(token_bytes);
    if token.len() > IDE_CONSENT_TOKEN_MAX_BYTES {
        return Err(ide_token_error());
    }
    Ok(IdeSnapshotPreview {
        preview_sha256: preview.consent_sha256.clone(),
        consent_token: token,
        source_manifest_sha256: preview.plan.source.sha256.clone(),
        file_count: u64::try_from(preview.plan.source.entries.len()).map_err(|_| {
            snapshot_error(
                "snapshot_plan_bound_exceeded",
                "the exact snapshot plan contains too many source entries",
                "Reduce the source set before requesting IDE snapshot consent.",
                Vec::new(),
            )
        })?,
        total_bytes: preview.plan.source.total_size,
        effects: vec![
            "upload_source_snapshot_to_public_github_object_database".to_owned(),
            "create_custom_source_ref_until_terminal_cleanup".to_owned(),
            "retain_local_keepalive_until_explicit_complete_lineage_prune".to_owned(),
            "submit_unsigned_physical_iphone_github_build".to_owned(),
        ],
    })
}

pub(in crate::commands) fn decode_ide_snapshot_consent(
    workspace_root: &Utf8Path,
    workspace_filesystem_identity: &str,
    token: &str,
    preview_sha256: &str,
) -> Result<DecodedIdeSnapshotConsent, CliError> {
    if token.is_empty()
        || token.len() > IDE_CONSENT_TOKEN_MAX_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ide_token_error());
    }
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ide_token_error())?;
    if URL_SAFE_NO_PAD.encode(&token_bytes) != token || token_bytes.len() <= 32 {
        return Err(ide_token_error());
    }
    let (payload_bytes, supplied_digest) = token_bytes.split_at(token_bytes.len() - 32);
    let payload: IdeSnapshotConsentTokenV1 =
        serde_json::from_slice(payload_bytes).map_err(|_| ide_token_error())?;
    if serde_json::to_vec(&payload).map_err(|_| ide_token_error())? != payload_bytes {
        return Err(ide_token_error());
    }
    let mut digest = Sha256::new();
    digest.update(IDE_CONSENT_TOKEN_DOMAIN);
    digest.update(payload_bytes);
    if supplied_digest != digest.finalize().as_slice()
        || payload.schema_version != 1
        || payload.workspace_binding_sha256
            != ide_workspace_binding_sha256(workspace_root, workspace_filesystem_identity)
        || payload.preview_sha256 != preview_sha256
        || GitSnapshotSourceRef::for_operation(&payload.operation_id).is_err()
    {
        return Err(ide_token_error());
    }
    Ok(DecodedIdeSnapshotConsent {
        profile: payload.profile,
        operation_id: payload.operation_id,
        source_created_at_ms: payload.source_created_at_ms,
        source_repository_sha256: payload.source_repository_sha256,
        preview_sha256: payload.preview_sha256,
    })
}

pub(in crate::commands) fn ide_source_repository_matches(
    consent: &DecodedIdeSnapshotConsent,
    source_repository: &str,
) -> bool {
    consent.source_repository_sha256 == ide_source_repository_sha256(source_repository)
}

fn ide_workspace_binding_sha256(
    workspace_root: &Utf8Path,
    workspace_filesystem_identity: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(IDE_WORKSPACE_BINDING_DOMAIN);
    digest.update(workspace_root.as_str().as_bytes());
    digest.update([0]);
    digest.update(workspace_filesystem_identity.as_bytes());
    lower_hex(&digest.finalize())
}

fn ide_source_repository_sha256(source_repository: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(IDE_SOURCE_REPOSITORY_DOMAIN);
    digest.update(source_repository.as_bytes());
    lower_hex(&digest.finalize())
}

fn ide_token_error() -> CliError {
    snapshot_error(
        "snapshot_consent_token_invalid",
        "the IDE snapshot consent token is invalid or no longer matches this workspace",
        "Request a new zero-write snapshot preview and approve only its exact current token.",
        Vec::new(),
    )
}

pub(super) fn ensure_same_snapshot_plan(
    approved: &GithubSnapshotPreviewV1,
    revalidated: &GithubSnapshotPreviewV1,
) -> Result<(), CliError> {
    if approved == revalidated {
        return Ok(());
    }
    Err(snapshot_error(
        "snapshot_plan_changed",
        "the exact GitHub snapshot plan changed after consent",
        "Review a new zero-write snapshot preview and confirm its new consent SHA-256.",
        vec![
            format!("approved_consent_sha256={}", approved.consent_sha256),
            format!("revalidated_consent_sha256={}", revalidated.consent_sha256),
        ],
    ))
}

pub(super) fn require_snapshot_consent(
    preview: &GithubSnapshotPreviewV1,
    yes: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    match confirmation_requirement(yes, reporter.is_json(), io::stdin().is_terminal()) {
        ConfirmationRequirement::Confirmed => {
            reporter.progress(render_snapshot_consent(preview));
            Ok(())
        }
        ConfirmationRequirement::ExplicitFlagRequired => Err(confirmation_required(preview)),
        ConfirmationRequirement::Interactive => prompt_for_confirmation(preview),
    }
}

pub(super) fn report_snapshot_preview(preview: &GithubSnapshotPreviewV1, reporter: &Reporter) {
    reporter.success(
        "build",
        preview,
        || render_snapshot_consent(preview),
        &[
            PUBLIC_OBJECT_WARNING.to_owned(),
            INVOCATION_BOUND_DIGEST_WARNING.to_owned(),
        ],
    );
}

pub(super) fn snapshot_warnings(consent_sha256: &str) -> Vec<String> {
    vec![
        PUBLIC_OBJECT_WARNING.to_owned(),
        format!("Snapshot consent SHA-256 for this invocation: {consent_sha256}"),
    ]
}

pub(super) fn stage_same_invocation_snapshot(
    isolation_root: &Utf8Path,
    source: &SourceBundlePlan,
    mut request: IosDeviceBuildRequest,
    source_created_at_ms: u64,
    approved_consent_sha256: &str,
    precompute: impl FnOnce(
        &mut GitSnapshotPrecomputeInputs,
        &str,
        u64,
    ) -> Result<GitSnapshotObjectGraphV1, CliError>,
) -> Result<StagedGithubSnapshotV1, CliError> {
    if request.source_revision.is_some()
        || request.source != *source.manifest()
        || request.operation_id.is_empty()
    {
        return Err(snapshot_error(
            "snapshot_stage_request_invalid",
            "the accepted GitHub snapshot request is not a pre-publication template",
            "Create a new exact snapshot plan before staging source bytes.",
            Vec::new(),
        ));
    }
    let operation_id = request.operation_id.clone();
    let stage_directory =
        GitSnapshotStageDirectory::create(isolation_root.as_std_path(), &operation_id)
            .map_err(|_| snapshot_stage_error("create the private operation stage"))?;
    let archive_path = camino::Utf8PathBuf::from_path_buf(stage_directory.archive_path())
        .map_err(|_| snapshot_stage_error("resolve the private archive path"))?;
    let archive =
        create_source_bundle_archive(source, &archive_path, git_snapshot_archive_limits())
            .map_err(|_| snapshot_stage_error("create the deterministic private archive"))?;
    let archive_identity = stage_directory
        .seal_archive(&archive)
        .map_err(|_| snapshot_stage_error("seal the deterministic private archive"))?;
    let descriptor = GitSnapshotDescriptor::from_request(
        &request,
        SourceBundleDescriptor::new(archive.clone(), request.source.clone()),
    )
    .map_err(|_| snapshot_stage_error("bind the canonical snapshot descriptor"))?;
    let descriptor_bytes = canonical_git_snapshot_descriptor_bytes(&descriptor)
        .map_err(|_| snapshot_stage_error("encode the canonical snapshot descriptor"))?;
    let descriptor_identity = stage_directory
        .write_descriptor_create_new(&descriptor)
        .map_err(|_| snapshot_stage_error("publish the private snapshot descriptor"))?;
    let mut inputs = stage_directory
        .precompute_inputs(
            &archive_identity,
            &descriptor_identity,
            &archive,
            &descriptor,
        )
        .map_err(|_| snapshot_stage_error("reopen the retained snapshot inputs"))?;
    let graph = precompute(&mut inputs, &operation_id, source_created_at_ms)?;
    inputs
        .verify_contents()
        .map_err(|_| snapshot_stage_error("revalidate the retained snapshot inputs"))?;
    request.source_revision = Some(graph.commit.as_str().to_owned());
    request
        .validate()
        .map_err(|_| snapshot_stage_error("validate the final snapshot build request"))?;
    let source_repository = request
        .source_repository
        .clone()
        .ok_or_else(|| snapshot_stage_error("bind the canonical public source repository"))?;
    let stage = GitSnapshotStageV1 {
        schema_version: GIT_SNAPSHOT_STAGE_SCHEMA_VERSION,
        operation_id: operation_id.clone(),
        isolation_root_identity: stage_directory.isolation_root_identity().to_owned(),
        snapshots_store_identity: stage_directory.snapshots_store_identity().to_owned(),
        stage_directory_identity: stage_directory.stage_directory_identity().to_owned(),
        source_repository,
        source_ref: GitSnapshotSourceRef::for_operation(&operation_id)
            .map_err(|_| snapshot_stage_error("derive the exact snapshot source ref"))?,
        keepalive_ref: GitSnapshotKeepaliveRef::for_operation(&operation_id)
            .map_err(|_| snapshot_stage_error("derive the exact snapshot keepalive ref"))?,
        source_created_at_ms,
        consent_sha256: approved_consent_sha256.to_owned(),
        request_template_sha256: descriptor.request_template_sha256.clone(),
        manifest_sha256: request.source.sha256.clone(),
        archive,
        descriptor_sha256: lower_hex(&Sha256::digest(descriptor_bytes)),
        final_request: request.clone(),
        archive_file_identity: archive_identity.to_string(),
        descriptor_file_identity: descriptor_identity.to_string(),
        graph,
    };
    let locator = stage_directory
        .publish_metadata_create_new(&stage, &descriptor, &request)
        .map_err(|_| snapshot_stage_error("publish the complete private snapshot stage"))?;
    Ok(StagedGithubSnapshotV1 {
        request,
        locator,
        stage,
    })
}

fn snapshot_stage_error(action: &'static str) -> CliError {
    snapshot_error(
        "snapshot_stage_failed",
        format!("the controller could not {action}"),
        "Preserve the private Git isolation directory for inspection; do not rename or reuse the operation stage.",
        Vec::new(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationRequirement {
    Confirmed,
    ExplicitFlagRequired,
    Interactive,
}

const fn confirmation_requirement(
    yes: bool,
    json: bool,
    stdin_terminal: bool,
) -> ConfirmationRequirement {
    if yes {
        ConfirmationRequirement::Confirmed
    } else if json || !stdin_terminal {
        ConfirmationRequirement::ExplicitFlagRequired
    } else {
        ConfirmationRequirement::Interactive
    }
}

fn prompt_for_confirmation(preview: &GithubSnapshotPreviewV1) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{}", render_snapshot_consent(preview)).map_err(|source| CliError::Io {
        action: "write GitHub snapshot consent prompt",
        path: "<stderr>".into(),
        source,
    })?;
    write!(stderr, "Publish this exact snapshot plan? [y/N] ").map_err(|source| CliError::Io {
        action: "write GitHub snapshot consent prompt",
        path: "<stderr>".into(),
        source,
    })?;
    stderr.flush().map_err(|source| CliError::Io {
        action: "flush GitHub snapshot consent prompt",
        path: "<stderr>".into(),
        source,
    })?;
    drop(stderr);

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|source| CliError::Io {
            action: "read GitHub snapshot consent",
            path: "<stdin>".into(),
            source,
        })?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(snapshot_error(
            "snapshot_consent_declined",
            "the GitHub snapshot was not approved",
            "No archive, job, or remote ref was created. Review the plan and rerun only if the public upload is intended.",
            confirmation_details(preview),
        ))
    }
}

fn confirmation_required(preview: &GithubSnapshotPreviewV1) -> CliError {
    snapshot_error(
        "snapshot_confirmation_required",
        "publishing this exact source snapshot requires explicit confirmation",
        "A fresh invocation creates a new operation-bound plan. Pass --yes only to authorize that invocation's newly computed exact source state.",
        confirmation_details(preview),
    )
}

fn confirmation_details(preview: &GithubSnapshotPreviewV1) -> Vec<String> {
    vec![
        format!("consent_sha256={}", preview.consent_sha256),
        format!("operation_id={}", preview.plan.operation_id),
        format!("source_created_at_ms={}", preview.plan.source_created_at_ms),
        format!(
            "public_source_repository={}",
            preview.plan.source_repository
        ),
        format!("source_ref={}", preview.plan.source_ref),
        format!("source_files={}", preview.plan.source.entries.len()),
        format!("source_bytes={}", preview.plan.source.total_size),
        format!("source_manifest_sha256={}", preview.plan.source.sha256),
        format!("archive_sha256={ARCHIVE_STATUS_AFTER_CONSENT}"),
        format!("secret_scan_residual={SECRET_SCAN_RESIDUAL}"),
        PUBLIC_OBJECT_WARNING.to_owned(),
    ]
}

fn render_snapshot_consent(preview: &GithubSnapshotPreviewV1) -> String {
    let included = preview
        .plan
        .source
        .entries
        .iter()
        .map(|entry| {
            format!(
                "  {}  {:>10}  {:<10}  {}",
                entry.sha256,
                entry.size,
                if entry.executable { "100755" } else { "100644" },
                entry.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let path_dependencies = render_path_list(&preview.plan.path_dependencies);
    let external_paths = render_path_list(&preview.plan.external_paths);
    let exclusions = render_path_list(&preview.plan.excluded_sensitive_paths);
    format!(
        "GitHub source snapshot consent\n\n{PUBLIC_OBJECT_WARNING}\n{INVOCATION_BOUND_DIGEST_WARNING}\nSecret-scan residual: {SECRET_SCAN_RESIDUAL}\n\nExact plan:\n  Consent SHA-256: {}\n  Operation ID: {}\n  Source created at (Unix ms): {}\n  Public repository: {}\n  Source ref: {}\n  Manifest SHA-256: {}\n  Source files: {}\n  Raw source bytes: {}\n  Archive SHA-256: {ARCHIVE_STATUS_AFTER_CONSENT}\n  Remote ref retention: {REMOTE_RETENTION}\n  Local keepalive retention: {LOCAL_RETENTION}\n\nIncluded paths:\n{}\n\nPath dependencies:\n{}\n\nExternal paths:\n{}\n\nSensitive exclusions:\n{}",
        preview.consent_sha256,
        preview.plan.operation_id,
        preview.plan.source_created_at_ms,
        preview.plan.source_repository,
        preview.plan.source_ref,
        preview.plan.source.sha256,
        preview.plan.source.entries.len(),
        preview.plan.source.total_size,
        included,
        path_dependencies,
        external_paths,
        exclusions,
    )
}

fn render_path_list(paths: &[String]) -> String {
    if paths.is_empty() {
        "  none".to_owned()
    } else {
        paths
            .iter()
            .map(|path| format!("  {path}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn consent_sha256(plan: &GithubSnapshotConsentPlanV1) -> Result<String, CliError> {
    let bytes = serde_json::to_vec(plan).map_err(|_| {
        snapshot_error(
            "snapshot_plan_encoding_failed",
            "the exact GitHub snapshot plan could not be encoded canonically",
            "Preserve the project and report this snapshot planner failure.",
            Vec::new(),
        )
    })?;
    let mut digest = Sha256::new();
    digest.update(CONSENT_DOMAIN);
    digest.update(bytes);
    Ok(lower_hex(&digest.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn snapshot_error(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    details: Vec<String>,
) -> CliError {
    CliError::JobsLifecycle {
        code,
        message: message.into(),
        help: help.into(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::path::Path;

    use camino::Utf8PathBuf;
    use rustferry_github::snapshot::{
        GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION, GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
        GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE, GIT_SNAPSHOT_STAGE_METADATA_FILE, GitSha1ObjectId,
    };
    use rustferry_remote::{
        BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType,
        IosDeviceProductExpectation, SigningMode, SigningPlan, SigningTarget, SigningTargetKind,
        SourceBundleRequest, SourceMode, plan_source_bundle,
    };

    use super::*;

    fn source_plan() -> (tempfile::TempDir, SourceBundlePlan) {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname='app'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
        let plan = plan_source_bundle(&SourceBundleRequest::new(&root, &root)).unwrap();
        (temporary, plan)
    }

    fn preview(plan: &SourceBundlePlan) -> GithubSnapshotPreviewV1 {
        GithubSnapshotPreviewV1::new(
            "operation-snapshot-preview-1",
            123_456,
            "https://github.com/example/source",
            plan,
            &["shared".to_owned(), "shared".to_owned()],
        )
        .unwrap()
    }

    fn object(character: char) -> GitSha1ObjectId {
        GitSha1ObjectId::new(character.to_string().repeat(40)).unwrap()
    }

    fn snapshot_request(plan: &SourceBundlePlan) -> IosDeviceBuildRequest {
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-snapshot-stage-1".to_owned(),
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
            source_mode: SourceMode::GitSnapshot,
            source_repository: Some("https://github.com/example/source".to_owned()),
            source_revision: None,
            source: plan.manifest().clone(),
            signing: SigningPlan {
                mode: SigningMode::UnsignedCompileOnly,
                signing: None,
                team: None,
                device: None,
                targets: vec![SigningTarget {
                    name: "App".to_owned(),
                    bundle_identifier: BundleIdentifier::new("com.example.app").unwrap(),
                    kind: SigningTargetKind::Application,
                }],
                provisioning: Vec::new(),
                entitlements: Vec::new(),
                allow_provisioning_updates: false,
            },
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        }
    }

    fn object_graph() -> GitSnapshotObjectGraphV1 {
        GitSnapshotObjectGraphV1 {
            schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
            archive_blob: object('1'),
            descriptor_blob: object('2'),
            goal3_tree: object('3'),
            rustferry_tree: object('4'),
            root_tree: object('5'),
            commit: object('6'),
        }
    }

    fn filesystem_snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<(String, Option<Vec<u8>>)>) {
            let mut entries = std::fs::read_dir(current)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if entry.file_type().unwrap().is_dir() {
                    output.push((format!("{relative}/"), None));
                    visit(root, &path, output);
                } else {
                    output.push((relative, Some(std::fs::read(path).unwrap())));
                }
            }
        }

        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    fn private_isolation_root(temporary: &tempfile::TempDir) -> Utf8PathBuf {
        let path = temporary.path().join("isolation");
        #[cfg(windows)]
        drop(
            rustferry_core::windows_private_directory::create_private_directory(&path)
                .expect("private snapshot isolation root"),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = std::fs::DirBuilder::new();
            builder
                .mode(0o700)
                .create(&path)
                .expect("private snapshot isolation root");
        }
        Utf8PathBuf::from_path_buf(path).unwrap()
    }

    #[test]
    fn zero_write_preview_is_deterministic_and_names_public_retention_risk() {
        let (temporary, plan) = source_plan();
        let before = filesystem_snapshot(temporary.path());
        let first = preview(&plan);
        let second = preview(&plan);
        assert_eq!(filesystem_snapshot(temporary.path()), before);
        assert!(!temporary.path().join("snapshots").exists());
        assert_eq!(first, second);
        assert_eq!(
            first.consent_sha256,
            "3fe5c8d06d9e6192449de68e7ccf59147c91f50122aaedb816469ac6f0932e50"
        );
        assert_eq!(first.plan.archive.size, None);
        assert_eq!(first.plan.archive.sha256, None);
        assert_eq!(first.plan.archive.status, "computed_after_consent");
        assert_eq!(first.plan.source_repository_visibility, "public");
        assert!(!first.plan.ref_deletion_erases_objects);
        assert!(first.plan.external_paths.is_empty());
        assert_eq!(first.plan.path_dependencies, ["shared"]);
        let rendered = render_snapshot_consent(&first);
        assert!(rendered.contains("PUBLIC GitHub object database"));
        assert!(rendered.contains("not erasure"));
        assert!(rendered.contains("later invocation computes and authorizes a different"));
        assert!(rendered.contains("src/lib.rs"));
        assert!(rendered.contains("100644"));
        assert!(rendered.contains("Path dependencies:\n  shared"));
        assert!(rendered.contains("External paths:\n  none"));
        assert!(rendered.contains("Sensitive exclusions:\n  none"));
        assert_eq!(
            snapshot_warnings(&first.consent_sha256)[1],
            format!(
                "Snapshot consent SHA-256 for this invocation: {}",
                first.consent_sha256
            )
        );
    }

    #[test]
    fn stage_callback_runs_after_payloads_and_metadata_is_append_last() {
        let (_source, plan) = source_plan();
        let isolation = tempfile::tempdir().unwrap();
        let isolation = private_isolation_root(&isolation);
        let request = snapshot_request(&plan);
        let stage_path = isolation
            .join("snapshots")
            .join(request.operation_id.as_str());
        let precompute_called = Cell::new(false);

        let staged = stage_same_invocation_snapshot(
            &isolation,
            &plan,
            request.clone(),
            123_456,
            &"a".repeat(64),
            |inputs, operation_id, created_at_ms| {
                precompute_called.set(true);
                assert_eq!(operation_id, request.operation_id);
                assert_eq!(created_at_ms, 123_456);
                assert!(inputs.expected_archive().size > 0);
                assert!(!inputs.descriptor_bytes().is_empty());
                assert!(stage_path.join(GIT_SNAPSHOT_STAGE_ARCHIVE_FILE).is_file());
                assert!(
                    stage_path
                        .join(GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE)
                        .is_file()
                );
                assert!(!stage_path.join(GIT_SNAPSHOT_STAGE_METADATA_FILE).exists());
                Ok(object_graph())
            },
        )
        .unwrap();

        assert!(precompute_called.get());
        assert!(stage_path.join(GIT_SNAPSHOT_STAGE_METADATA_FILE).is_file());
        assert_eq!(
            staged.request.source_revision.as_deref(),
            Some(object('6').as_str())
        );
        assert_eq!(staged.stage.final_request, staged.request);
        staged
            .locator
            .validate_for_operation(&request.operation_id)
            .unwrap();
    }

    #[test]
    fn failed_precompute_never_publishes_complete_stage_metadata() {
        let (_source, plan) = source_plan();
        let isolation = tempfile::tempdir().unwrap();
        let isolation = private_isolation_root(&isolation);
        let request = snapshot_request(&plan);
        let stage_path = isolation
            .join("snapshots")
            .join(request.operation_id.as_str());

        let error = stage_same_invocation_snapshot(
            &isolation,
            &plan,
            request,
            123_456,
            &"a".repeat(64),
            |_inputs, _operation_id, _created_at_ms| {
                Err(snapshot_error(
                    "test_precompute_failed",
                    "test precompute failed",
                    "test help",
                    Vec::new(),
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "test_precompute_failed");
        assert!(stage_path.join(GIT_SNAPSHOT_STAGE_ARCHIVE_FILE).is_file());
        assert!(
            stage_path
                .join(GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE)
                .is_file()
        );
        assert!(!stage_path.join(GIT_SNAPSHOT_STAGE_METADATA_FILE).exists());
    }

    #[test]
    fn consent_hash_changes_with_any_replanned_source_drift() {
        let (temporary, first_plan) = source_plan();
        let first = preview(&first_plan);
        std::fs::write(
            temporary.path().join("src/lib.rs"),
            b"pub fn answer() -> u8 { 43 }\n",
        )
        .unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let second_plan = plan_source_bundle(&SourceBundleRequest::new(&root, &root)).unwrap();
        let second = preview(&second_plan);
        assert_ne!(first.consent_sha256, second.consent_sha256);
        let error = ensure_same_snapshot_plan(&first, &second).unwrap_err();
        assert_eq!(error.code(), "snapshot_plan_changed");
    }

    #[test]
    fn consent_hash_binds_operation_time_repository_ref_and_dependency_audit() {
        let (_temporary, plan) = source_plan();
        let approved = preview(&plan);
        let changed = GithubSnapshotPreviewV1::new(
            "operation-snapshot-preview-2",
            approved.plan.source_created_at_ms + 1,
            "https://github.com/example/other-source",
            &plan,
            &["different-dependency".to_owned()],
        )
        .unwrap();
        assert_ne!(changed.consent_sha256, approved.consent_sha256);
        assert_ne!(changed.plan.source_ref, approved.plan.source_ref);
        assert_eq!(
            ensure_same_snapshot_plan(&approved, &changed)
                .unwrap_err()
                .code(),
            "snapshot_plan_changed"
        );
    }

    #[test]
    fn ide_consent_token_is_compact_canonical_and_workspace_bound() {
        let (temporary, plan) = source_plan();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let preview = preview(&plan);
        let identity = "test-filesystem-identity";
        let ide = ide_snapshot_preview(&root, identity, BuildProfile::Debug, &preview).unwrap();

        assert!(ide.consent_token.len() <= IDE_CONSENT_TOKEN_MAX_BYTES);
        assert!(!ide.consent_token.contains('.'));
        assert!(
            ide.consent_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        );
        assert_eq!(ide.preview_sha256, preview.consent_sha256);
        assert_eq!(ide.source_manifest_sha256, preview.plan.source.sha256);

        let decoded =
            decode_ide_snapshot_consent(&root, identity, &ide.consent_token, &ide.preview_sha256)
                .unwrap();
        assert_eq!(decoded.profile, BuildProfile::Debug);
        assert_eq!(decoded.operation_id, preview.plan.operation_id);
        assert_eq!(
            decoded.source_created_at_ms,
            preview.plan.source_created_at_ms
        );
        assert!(ide_source_repository_matches(
            &decoded,
            &preview.plan.source_repository
        ));
        assert!(!ide_source_repository_matches(
            &decoded,
            "https://github.com/example/other-source"
        ));

        let other_root = root.join("src");
        assert!(
            decode_ide_snapshot_consent(
                &other_root,
                identity,
                &ide.consent_token,
                &ide.preview_sha256,
            )
            .is_err()
        );
        assert!(
            decode_ide_snapshot_consent(
                &root,
                "replacement-identity",
                &ide.consent_token,
                &ide.preview_sha256,
            )
            .is_err()
        );
        assert!(
            decode_ide_snapshot_consent(&root, identity, &ide.consent_token, &"0".repeat(64),)
                .is_err()
        );
    }

    #[test]
    fn ide_consent_token_rejects_noncanonical_or_tampered_input() {
        let (temporary, plan) = source_plan();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let preview = preview(&plan);
        let ide = ide_snapshot_preview(&root, "identity", BuildProfile::Release, &preview).unwrap();
        let mut tampered = ide.consent_token.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();

        for token in [tampered, "a.b".to_owned(), "a".repeat(513)] {
            assert!(
                decode_ide_snapshot_consent(&root, "identity", &token, &preview.consent_sha256,)
                    .is_err()
            );
        }
    }

    #[test]
    fn json_and_nonterminal_consent_require_yes() {
        assert_eq!(
            confirmation_requirement(true, true, false),
            ConfirmationRequirement::Confirmed
        );
        assert_eq!(
            confirmation_requirement(false, true, true),
            ConfirmationRequirement::ExplicitFlagRequired
        );
        assert_eq!(
            confirmation_requirement(false, false, false),
            ConfirmationRequirement::ExplicitFlagRequired
        );
        assert_eq!(
            confirmation_requirement(false, false, true),
            ConfirmationRequirement::Interactive
        );
    }

    #[test]
    fn preview_rejects_noncanonical_or_non_https_repositories() {
        let (_temporary, plan) = source_plan();
        for repository in [
            "https://github.com/Example/Source",
            "git@github.com:example/source",
            "https://example.com/example/source",
        ] {
            let error = GithubSnapshotPreviewV1::new(
                "operation-snapshot-preview-1",
                123_456,
                repository,
                &plan,
                &[],
            )
            .unwrap_err();
            assert_eq!(error.code(), "snapshot_source_repository_invalid");
        }
    }
}
