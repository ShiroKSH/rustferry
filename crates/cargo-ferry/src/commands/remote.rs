use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rustferry_core::{
    DirectoryFilesystemIdentity, RegularFileFilesystemIdentity, RetainedDirectoryIdentity,
    regular_file_identity_from_file, verify_directory_identity, verify_regular_file_identity,
};
#[cfg(windows)]
use rustferry_core::{ExactRegularFileRemoval, open_regular_file_for_exact_removal};
#[cfg(unix)]
use rustferry_github::git_endpoint::GithubGitTransport;
use rustferry_github::git_endpoint::{GithubGitEndpoint, GithubRemoteSnapshot};
use rustferry_github::provider::{
    CallerGitOutput, CallerGitRepository, GITHUB_PROVIDER_ID, GitExecutionError, GitProcessRunner,
    GitPublisherConfigError, GitTemporaryRefPublisher, GithubBuildProvider,
    GithubDurableIdentityV1, GithubGitSnapshotRecoveryCandidateV1, GithubGitSnapshotSubmissionV1,
    GithubJobReconciliation, GithubMutationAuthorization, GithubPollingPolicy,
    GithubProviderConfig, SystemProviderClock, WorkflowFingerprint,
};
use rustferry_github::transport::{
    EnvironmentSecretWriteRequest, GhAuthentication, GhProcessRunner, GithubTransport,
    MAX_ENVIRONMENT_SECRET_BYTES, Repository, TokenEnvironmentVariable, TransportError,
    TransportLimits,
};
use rustferry_github::workflow::{PublicSourceRepository, WorkflowRunTrigger};
use rustferry_github::{
    GithubVerifiedArtifactStore, MAX_SIGNING_PROFILES, ProtectedEnvironment, SigningSecretNames,
    TemporaryBranchNamespace, TrustedSourceRef, WorkerDistribution, WorkflowConfig,
    WorkflowFileName, generate_workflow,
};
use rustferry_remote::{
    ArtifactDownloadRequest, ArtifactKind, ArtifactListRequest, BuildProfile, BuildProvider,
    BundleIdentifier, CURRENT_PROTOCOL_VERSION, CancellationRequest, CancellationToken,
    CleanupConfirmation, CleanupRequest, DiagnosticSeverity, EventRequest, HandshakeRequest,
    IosArtifactType, IosDeviceBuildRequest, JobState, MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES,
    ProtocolPath, ProtocolPathSemantics, ProviderDoctorRequest, ProviderFeature, ProviderFuture,
    RemoteBuildEvent, RemoteBuildEventKind, SecretBytes, SigningMode, SigningPlan, SigningTarget,
    SigningTargetKind, SourceArchive, SourceArchiveLimits, SourceBundleDescriptor,
    SourceBundlePlan, SourceBundleRequest, SourceLimits, SourceManifest, SourceManifestEntry,
    SourceMode, UnsignedNestedBundleKind, ValidationLevel,
    canonical_git_snapshot_request_template_sha256, canonical_request_sha256,
    canonical_retry_template_sha256_v1, create_source_bundle_archive, plan_source_bundle,
    validate_source_manifest, verify_and_extract_source_bundle,
    write_source_bundle_descriptor_file,
};
use same_file::Handle as FileIdentityHandle;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cli::{
    BuildArtifactSelection, GithubWorkflowTriggerChoice, RemoteArgs, RemoteBundleArgs,
    RemoteBundleCommand, RemoteBundleCreateArgs, RemoteBundleInspectArgs, RemoteBundleVerifyArgs,
    RemoteCommand, RemoteDoctorArgs, RemoteProviderChoice, RemoteSetupArgs, RemoteStatusArgs,
};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{
    capture_project_directory_identity, find_in_path, find_project_root, run_captured_bounded,
    verify_project_directory_identity,
};
use cargo_ferry::job_store::{
    GithubJobStoreCheckpointSink, JOB_STORE_SCHEMA_VERSION, JobOperationKind, JobOperationLease,
    JobStore, JobStoreError, LocalJobId, MAX_LISTED_JOBS, RetryLineageBindingV1,
    RetryLineageOptionsV1, RetryParentPolicyV1, RetrySourcePolicyV1, SnapshotOperationVacancyV1,
    StoredArtifactV1, StoredBuildOutcome, StoredCancellationStatus, StoredCleanupStatus,
    StoredFailureV1, StoredJobState, StoredJobV1, StoredProjectIdentityV1,
    StoredProviderIdentityV1, StoredRetryLineageV1, StoredSourceIdentityV1,
    VacantSnapshotOperationLease, retry_recapture_confirmation_sha256,
};

#[path = "github_job_session.rs"]
mod github_job_session;

#[cfg(test)]
pub(super) use github_job_session::test_retry_completion_receipt;
pub(super) use github_job_session::{
    BoundGithubJobSession, BoundGithubRetrySession, DurableGithubCancellationSession,
    GithubCancellationSessionReceipt, GithubRetryChildDisposition, GithubRetryChildSession,
    GithubRetryCompletionReceipt, PreparedGithubJobSession, PreparedGithubRetrySession,
    ingest_github_job_logs_once, ingest_github_job_logs_once_in_store,
};

const CONFIG_SCHEMA_VERSION: u32 = 4;
const CONFIG_RELATIVE_PATH: &str = "target/ferry/github/provider.json";
const CONFIG_LOCK_RELATIVE_PATH: &str = "target/ferry/github/.provider.lock";
const CONFIG_BACKUP_PREFIX: &str = ".provider-backup-";
const CACHE_RELATIVE_PATH: &str = "target/ferry/github/cache";
const GIT_ISOLATION_RELATIVE_PATH: &str = "target/ferry/github/git-isolation";
const WORKFLOW_FILE: &str = "rustferry-goal3-iphone.yml";
const PROTECTED_ENVIRONMENT: &str = "rustferry-goal3-signing";
const TEMPORARY_NAMESPACE: &str = "rustferry/goal3/builds";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PUBLIC_TEXT_BYTES: usize = 4 * 1024;
const GIT_PATHSPEC_ARGUMENT_BYTES: usize = 6 * 1024;
const GIT_BLOB_BATCH_BYTES: u64 = 16 * 1024 * 1024;
const GIT_BLOB_BATCH_COUNT: usize = 128;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const BUILD_TIMEOUT: Duration = Duration::from_hours(2);
const CANCELLATION_TIMEOUT: Duration = Duration::from_mins(10);
const BUILD_LEASE_REACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_LEASE_REACQUIRE_POLL: Duration = Duration::from_millis(50);
const SUBMIT_RECONCILIATION_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const SUBMIT_RECONCILIATION_MAX_BACKOFF: Duration = Duration::from_mins(1);
const SUBMIT_RECONCILIATION_POST_DEADLINE_ATTEMPTS: u8 = 3;
const ARTIFACT_LIST_ATTEMPTS: usize = 6;
const ARTIFACT_LIST_BACKOFF: Duration = Duration::from_secs(2);
const MAX_CURRENT_SNAPSHOT_DIFF_PATHS: usize = 128;
const MAX_CURRENT_SNAPSHOT_DIFF_PATH_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredGithubWorkflowTrigger {
    #[default]
    Push,
    WorkflowDispatch,
}

impl StoredGithubWorkflowTrigger {
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde skip_serializing_if callbacks receive a shared reference"
    )]
    const fn is_push(value: &Self) -> bool {
        matches!(value, Self::Push)
    }
}

impl From<GithubWorkflowTriggerChoice> for StoredGithubWorkflowTrigger {
    fn from(value: GithubWorkflowTriggerChoice) -> Self {
        match value {
            GithubWorkflowTriggerChoice::Push => Self::Push,
            GithubWorkflowTriggerChoice::WorkflowDispatch => Self::WorkflowDispatch,
        }
    }
}

impl From<StoredGithubWorkflowTrigger> for WorkflowRunTrigger {
    fn from(value: StoredGithubWorkflowTrigger) -> Self {
        match value {
            StoredGithubWorkflowTrigger::Push => Self::Push,
            StoredGithubWorkflowTrigger::WorkflowDispatch => Self::WorkflowDispatch,
        }
    }
}

type GithubProvider = GithubBuildProvider<
    GhProcessRunner,
    GitTemporaryRefPublisher<GitProcessRunner>,
    GithubVerifiedArtifactStore<GhProcessRunner>,
    SystemProviderClock,
>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredGithubConfig {
    schema_version: u32,
    /// GitHub Actions execution repository slug.
    repository: String,
    /// Public project-source repository as a canonical HTTPS URL.
    source_repository: String,
    source_fetch_endpoint: GithubGitEndpoint,
    source_push_endpoint: GithubGitEndpoint,
    execution_fetch_endpoint: GithubGitEndpoint,
    execution_push_endpoint: GithubGitEndpoint,
    trusted_source_ref: String,
    workflow_file: String,
    protected_environment: String,
    temporary_namespace: String,
    worker_repository: String,
    worker_revision: String,
    worker_version: String,
    #[serde(default, skip_serializing_if = "StoredGithubWorkflowTrigger::is_push")]
    run_trigger: StoredGithubWorkflowTrigger,
    /// Public target graph used to render static protected-secret expressions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    signing_targets: Vec<SigningTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing: Option<SigningPlan>,
}

#[derive(Debug)]
struct GithubPaths {
    config: Utf8PathBuf,
    config_lock: Utf8PathBuf,
    cache: Utf8PathBuf,
    git_isolation: Utf8PathBuf,
    workflow: Utf8PathBuf,
}

impl GithubPaths {
    fn new(project_root: &Utf8Path, repository_root: &Utf8Path) -> Self {
        Self {
            config: project_root.join(CONFIG_RELATIVE_PATH),
            config_lock: project_root.join(CONFIG_LOCK_RELATIVE_PATH),
            cache: project_root.join(CACHE_RELATIVE_PATH),
            git_isolation: project_root.join(GIT_ISOLATION_RELATIVE_PATH),
            workflow: repository_root
                .join(".github/workflows")
                .join(WORKFLOW_FILE),
        }
    }
}

#[derive(Debug)]
struct GitContext {
    caller_git: CallerGitRepository,
    root: Utf8PathBuf,
    repository: Repository,
    repository_slug: String,
    source_repository: String,
    fetch_endpoint: GithubGitEndpoint,
    push_endpoint: GithubGitEndpoint,
    revision: String,
}

#[derive(Debug)]
struct GitRemoteContext {
    repository: Repository,
    repository_slug: String,
    source_repository: String,
    fetch_endpoint: GithubGitEndpoint,
    push_endpoint: GithubGitEndpoint,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
    resolve: Option<CargoMetadataResolve>,
    workspace_members: Vec<String>,
    workspace_root: Utf8PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    id: String,
    manifest_path: Utf8PathBuf,
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataResolve {
    nodes: Vec<CargoMetadataNode>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNode {
    id: String,
    dependencies: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SetupOutput {
    source_repository: String,
    execution_repository: String,
    authenticated_as: String,
    workflow: String,
    provider_config: String,
    trusted_source_ref: String,
    worker_revision: String,
    signing_mode: &'static str,
    installed: bool,
    unchanged: bool,
    workflow_preview: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    source_repository: String,
    execution_repository: String,
    provider_config: String,
    workflow: String,
    workflow_matches: bool,
    trusted_source_ref: String,
    worker_revision: String,
    signing_mode: &'static str,
}

#[derive(Debug, Serialize)]
struct DoctorOutput {
    provider: String,
    ready: bool,
    checks: Vec<rustferry_remote::ProviderCheck>,
    signing_mode: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeSigningReadinessCheck {
    pub(in crate::commands) code: String,
    pub(in crate::commands) required: bool,
    pub(in crate::commands) ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::commands) reason_code: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct IdeSigningReadiness {
    pub(in crate::commands) ready: bool,
    pub(in crate::commands) checks: Vec<IdeSigningReadinessCheck>,
}

#[derive(Debug, Serialize)]
struct SourceBundleInspectOutput {
    project: String,
    workspace: String,
    path_dependencies: Vec<String>,
    symlinks: Vec<String>,
    excluded_sensitive_paths: Vec<String>,
    manifest: SourceManifest,
}

#[derive(Debug, Serialize)]
struct SourceBundleCreateOutput {
    project: String,
    workspace: String,
    archive_path: String,
    descriptor_path: String,
    archive: Option<SourceArchive>,
    path_dependencies: Vec<String>,
    symlinks: Vec<String>,
    excluded_sensitive_paths: Vec<String>,
    manifest: SourceManifest,
    created: bool,
    dry_run: bool,
}

#[derive(Debug)]
struct SourceBundleOutputPaths {
    archive: Utf8PathBuf,
    descriptor: Utf8PathBuf,
}

#[derive(Debug, Serialize)]
struct SourceBundleVerifyOutput {
    archive_path: String,
    descriptor_path: String,
    archive: SourceArchive,
    project_path: String,
    source_sha256: String,
    source_files: usize,
    source_bytes: u64,
    verified: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct ManualGithubSigningPreview {
    source_repository: String,
    execution_repository: String,
    protected_environment: String,
    required_secret_names: Vec<String>,
    team_id: String,
    certificate_common_name: String,
    certificate_sha256: String,
    certificate_expires_at_unix_seconds: u64,
    profiles: Vec<ManualGithubProfilePreview>,
    device_udid_sha256: String,
    target_bundle_identifiers: Vec<String>,
    installed: bool,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct ManualGithubProfilePreview {
    target: String,
    secret_name: String,
    uuid: String,
    name: String,
    expires_at_unix_seconds: u64,
    profile_type: &'static str,
    bundle_identifier_pattern: String,
}

impl ManualGithubSigningPreview {
    pub(super) fn human_summary(&self) -> String {
        format!(
            "Manual iPhone signing\n\nPublic source:\n  {}\n\nPrivate execution:\n  {}\n\nProtected Environment:\n  {}\n\nTeam:\n  {}\n\nCertificate:\n  {}\n  SHA-256: {}\n  Expires: {}\n\nProvisioning profiles:\n  {}\n\nDevice SHA-256:\n  {}\n\nTargets:\n  {}\n\nSecret roles:\n  {}",
            self.source_repository,
            self.execution_repository,
            self.protected_environment,
            self.team_id,
            self.certificate_common_name,
            self.certificate_sha256,
            self.certificate_expires_at_unix_seconds,
            self.profiles
                .iter()
                .map(|profile| format!(
                    "{}: {}\n    Secret: {}\n    UUID: {}\n    Type: {}\n    Bundle pattern: {}\n    Expires: {}",
                    profile.target,
                    profile.name,
                    profile.secret_name,
                    profile.uuid,
                    profile.profile_type,
                    profile.bundle_identifier_pattern,
                    profile.expires_at_unix_seconds,
                ))
                .collect::<Vec<_>>()
                .join("\n  "),
            self.device_udid_sha256,
            self.target_bundle_identifiers.join("\n  "),
            self.required_secret_names.join("\n  "),
        )
    }
}

#[derive(Clone)]
pub(super) struct ManualGithubSigningAssets {
    certificate: rustferry_remote::SigningCertificate,
    profiles: BTreeMap<String, rustferry_remote::ProvisioningProfile>,
}

impl ManualGithubSigningAssets {
    pub(super) fn new(
        certificate: rustferry_remote::SigningCertificate,
        profiles: BTreeMap<String, rustferry_remote::ProvisioningProfile>,
    ) -> Result<Self, CliError> {
        if profiles.is_empty()
            || profiles.len() > MAX_SIGNING_PROFILES
            || certificate.validate().is_err()
        {
            return Err(remote_error(
                "invalid_validated_signing_assets",
                "the validated signing asset set is empty or exceeds the supported target bound",
                "Validate one application profile and at most the Widget and Live Activity profiles.",
            ));
        }
        for profile in profiles.values() {
            if profile.validate_metadata().is_err()
                || profile.team.id() != certificate.team.id()
                || !profile
                    .certificate_fingerprints
                    .contains(&certificate.sha256_fingerprint)
            {
                return Err(remote_error(
                    "invalid_validated_signing_assets",
                    "a validated profile does not match the retained signing identity",
                    "Revalidate the exact certificate and target profiles together.",
                ));
            }
        }
        Ok(Self {
            certificate,
            profiles,
        })
    }
}

pub(super) struct ManualGithubSecretValues {
    certificate_p12: CanonicalBase64SigningBlob,
    certificate_password: RawSigningPassword,
    profiles: BTreeMap<String, CanonicalBase64SigningBlob>,
}

impl ManualGithubSecretValues {
    pub(super) fn from_validated_inputs(
        expected: &ManualGithubSigningAssets,
        identity: rustferry_apple::ManualSigningIdentityInput,
        profiles: Vec<(String, SecretBytes)>,
    ) -> Result<Self, CliError> {
        let (actual_certificate, identity) =
            rustferry_apple::validate_manual_signing_identity(identity).map_err(|error| {
                remote_error_with_details(
                    "manual_signing_asset_revalidation_failed",
                    "the retained signing assets failed validation immediately before upload",
                    "Do not upload. Revalidate the original Apple Development assets and retry.",
                    vec![error.to_string()],
                )
            })?;
        if actual_certificate != expected.certificate {
            return Err(remote_error(
                "manual_signing_asset_revalidation_mismatch",
                "the retained signing assets no longer match the reviewed public metadata",
                "Do not upload. Restart signing setup from the original stable asset files.",
            ));
        }
        let mut retained_profiles = BTreeMap::new();
        for (target, profile) in profiles {
            if retained_profiles.contains_key(&target) {
                return Err(remote_error(
                    "manual_signing_asset_revalidation_mismatch",
                    "a retained signing target has duplicate profile bytes",
                    "Do not upload. Restart signing setup from the original stable asset files.",
                ));
            }
            let (actual, profile) = rustferry_apple::validate_manual_signing_profile(
                profile,
                &actual_certificate,
            )
            .map_err(|error| {
                remote_error_with_details(
                    "manual_signing_asset_revalidation_failed",
                    "a retained provisioning profile failed validation immediately before upload",
                    "Do not upload. Revalidate the original target profile and retry.",
                    vec![format!("target={target}"), error.to_string()],
                )
            })?;
            if expected.profiles.get(&target) != Some(&actual) {
                return Err(remote_error_with_details(
                    "manual_signing_asset_revalidation_mismatch",
                    "a retained profile no longer matches the reviewed public metadata",
                    "Do not upload. Restart signing setup from the original stable asset files.",
                    vec![format!("target={target}")],
                ));
            }
            retained_profiles.insert(
                target,
                CanonicalBase64SigningBlob::from_raw(&profile, "provisioning_profile")?,
            );
        }
        if retained_profiles.keys().collect::<BTreeSet<_>>()
            != expected.profiles.keys().collect::<BTreeSet<_>>()
        {
            return Err(remote_error(
                "manual_signing_asset_revalidation_mismatch",
                "the retained target-profile set differs from the reviewed set",
                "Do not upload. Restart signing setup from the original stable asset files.",
            ));
        }
        let (certificate_p12, certificate_password) = identity.into_parts();
        Ok(Self {
            certificate_p12: CanonicalBase64SigningBlob::from_raw(
                &certificate_p12,
                "certificate_p12",
            )?,
            certificate_password: RawSigningPassword::new(certificate_password)?,
            profiles: retained_profiles,
        })
    }
}

struct CanonicalBase64SigningBlob(SecretBytes);

impl CanonicalBase64SigningBlob {
    fn from_raw(raw: &SecretBytes, role: &'static str) -> Result<Self, CliError> {
        let encoded_length = base64::encoded_len(raw.len(), true)
            .ok_or_else(|| signing_secret_encoding_error(role, "encoded length is unavailable"))?;
        if encoded_length > MAX_ENVIRONMENT_SECRET_BYTES {
            return Err(signing_secret_too_large(role));
        }
        let mut encoded = SecretOutputBuffer(vec![0; encoded_length]);
        let written = STANDARD
            .encode_slice(raw.expose_secret_bytes(), &mut encoded.0)
            .map_err(|_| signing_secret_encoding_error(role, "base64 encoding failed"))?;
        if written != encoded_length {
            return Err(signing_secret_encoding_error(
                role,
                "encoded length changed",
            ));
        }
        Self::try_from_encoded(encoded.into_secret(), role)
    }

    fn try_from_encoded(encoded: SecretBytes, role: &'static str) -> Result<Self, CliError> {
        if encoded.is_empty() || encoded.len() > MAX_ENVIRONMENT_SECRET_BYTES {
            return Err(signing_secret_too_large(role));
        }
        let decoded = STANDARD
            .decode(encoded.expose_secret_bytes())
            .map(SecretBytes::new)
            .map_err(|_| signing_secret_encoding_error(role, "base64 is malformed"))?;
        if decoded.is_empty() {
            return Err(signing_secret_encoding_error(
                role,
                "decoded value is empty",
            ));
        }
        let canonical =
            SecretBytes::new(STANDARD.encode(decoded.expose_secret_bytes()).into_bytes());
        if canonical.expose_secret_bytes() != encoded.expose_secret_bytes() {
            return Err(signing_secret_encoding_error(
                role,
                "base64 is not canonical padded form",
            ));
        }
        Ok(Self(encoded))
    }

    const fn as_secret(&self) -> &SecretBytes {
        &self.0
    }
}

struct SecretOutputBuffer(Vec<u8>);

impl SecretOutputBuffer {
    fn into_secret(mut self) -> SecretBytes {
        SecretBytes::new(std::mem::take(&mut self.0))
    }
}

impl Drop for SecretOutputBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
        let _ = std::hint::black_box(&mut self.0);
    }
}

struct RawSigningPassword(SecretBytes);

impl RawSigningPassword {
    fn new(value: SecretBytes) -> Result<Self, CliError> {
        if value.len() > rustferry_apple::MAX_MANUAL_SIGNING_PASSWORD_BYTES
            || value.len() > MAX_ENVIRONMENT_SECRET_BYTES
        {
            return Err(signing_secret_too_large("certificate_password"));
        }
        if std::str::from_utf8(value.expose_secret_bytes()).is_err()
            || value
                .expose_secret_bytes()
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(remote_error(
                "invalid_signing_password_value",
                "the retained PKCS#12 password is not bounded safe UTF-8",
                "Use the exact password without NUL or line-break bytes.",
            ));
        }
        Ok(Self(value))
    }

    const fn as_secret(&self) -> &SecretBytes {
        &self.0
    }
}

fn signing_secret_too_large(role: &'static str) -> CliError {
    remote_error_with_details(
        "github_signing_secret_too_large",
        "a protected signing secret exceeds GitHub's fixed value limit",
        "Use signing assets whose encoded values fit within 48 KiB; no secret was uploaded.",
        vec![
            format!("role={role}"),
            format!("maximum={MAX_ENVIRONMENT_SECRET_BYTES}"),
        ],
    )
}

fn signing_secret_encoding_error(role: &'static str, reason: &'static str) -> CliError {
    remote_error_with_details(
        "invalid_github_signing_secret_encoding",
        "a signing asset did not have the required canonical remote representation",
        "Revalidate and encode the original signing asset before upload.",
        vec![format!("role={role}"), format!("reason={reason}")],
    )
}

pub(super) struct ManualGithubSigningSession<R = GithubManualSigningRemote> {
    root: Utf8PathBuf,
    expected_project_state: SigningProjectState,
    paths: GithubPaths,
    stored: StoredGithubConfig,
    original_config_identity: Option<ArtifactFileIdentity>,
    original_config_bytes: Vec<u8>,
    expected_workflow: Vec<u8>,
    plan: SigningPlan,
    assets: ManualGithubSigningAssets,
    source_repository: Repository,
    execution_repository: Repository,
    environment: ProtectedEnvironment,
    secret_names: SigningSecretNames,
    remote: R,
    config_lock: Option<ProviderConfigLock>,
}

#[derive(Clone, Debug, PartialEq)]
struct SigningProjectState {
    ferry_config: rustferry_core::FerryConfig,
    binary_name: String,
    targets: Vec<SigningTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SigningSecretUpload {
    role: String,
    secret_name: String,
}

pub(super) trait ManualSigningRemote {
    fn verify_policy(
        &mut self,
        source_repository: &Repository,
        execution_repository: &Repository,
        environment: &ProtectedEnvironment,
        stored: &StoredGithubConfig,
        phase: &'static str,
    ) -> Result<BTreeSet<String>, CliError>;

    fn set_secret(
        &mut self,
        request: &EnvironmentSecretWriteRequest,
        value: &SecretBytes,
    ) -> Result<(), TransportError>;
}

pub(super) struct GithubManualSigningRemote {
    transport: GithubTransport<GhProcessRunner>,
}

impl ManualSigningRemote for GithubManualSigningRemote {
    fn verify_policy(
        &mut self,
        source_repository: &Repository,
        execution_repository: &Repository,
        environment: &ProtectedEnvironment,
        stored: &StoredGithubConfig,
        phase: &'static str,
    ) -> Result<BTreeSet<String>, CliError> {
        verify_manual_signing_policy(
            &mut self.transport,
            source_repository,
            execution_repository,
            environment,
            stored,
            phase,
        )
    }

    fn set_secret(
        &mut self,
        request: &EnvironmentSecretWriteRequest,
        value: &SecretBytes,
    ) -> Result<(), TransportError> {
        self.transport
            .set_environment_secret(request, value)
            .map(drop)
    }
}

struct ProviderConfigLock {
    _file: File,
    #[cfg(windows)]
    _parent: File,
}

#[derive(Debug)]
enum ConfigCommitError {
    NotCommitted(Box<CliError>),
    CommittedNeedsInspection(Box<CliError>),
}

#[derive(Debug, Serialize)]
struct RemoteBuildOutput {
    project: String,
    provider: &'static str,
    profile: &'static str,
    signing_mode: &'static str,
    source_revision: String,
    source_sha256: String,
    source_files: usize,
    expected_artifact: String,
    artifact: Option<String>,
    artifact_sha256: Option<String>,
    supporting_artifacts: Vec<String>,
    local_job_id: Option<String>,
    job_id: Option<String>,
    validated: bool,
    cleanup_confirmed: bool,
    dry_run: bool,
}

#[derive(Clone, Debug)]
struct ExpectedDownload {
    kind: ArtifactKind,
    path: Utf8PathBuf,
}

#[derive(Debug)]
struct ValidatedLocalArtifact {
    path: String,
    file_identity: RegularFileFilesystemIdentity,
}

#[derive(Debug)]
struct RetainedArtifactValidation {
    path: Utf8PathBuf,
    identity: RegularFileFilesystemIdentity,
    file: File,
    expected_size: u64,
    expected_sha256: String,
    #[cfg(windows)]
    exact: ExactRegularFileRemoval,
}

impl RetainedArtifactValidation {
    fn capture(
        path: &Utf8Path,
        identity: &RegularFileFilesystemIdentity,
        artifact: &rustferry_remote::ArtifactRecord,
    ) -> Result<Self, CliError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| CliError::Io {
                action: "retain validated artifact identity",
                path: path.to_owned(),
                source,
            })?;
        let handle_identity = regular_file_identity_from_file(&file).map_err(|error| {
            remote_error_with_details(
                "artifact_validation_guard_failed",
                "a validated artifact could not be retained as its exact filesystem object",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
                vec![error.to_string()],
            )
        })?;
        if &handle_identity != identity {
            return Err(remote_error(
                "artifact_validation_guard_failed",
                "a validated artifact changed before its exact filesystem object could be retained",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
            ));
        }
        #[cfg(windows)]
        let exact = {
            let exact = open_regular_file_for_exact_removal(path.as_std_path()).map_err(|error| {
                remote_error_with_details(
                    "artifact_validation_guard_failed",
                    "a validated artifact could not be retained against replacement",
                    "Do not report success; preserve the local job and reconcile the exact artifact path.",
                    vec![error.to_string()],
                )
            })?;
            if exact.identity() != identity {
                return Err(remote_error(
                    "artifact_validation_guard_failed",
                    "a validated artifact changed while its replacement guard was opened",
                    "Do not report success; preserve the local job and reconcile the exact artifact path.",
                ));
            }
            exact
        };
        let retained = Self {
            path: path.to_owned(),
            identity: identity.clone(),
            file,
            expected_size: artifact.size,
            expected_sha256: artifact.sha256.clone(),
            #[cfg(windows)]
            exact,
        };
        retained.verify()?;
        Ok(retained)
    }

    fn verify(&self) -> Result<(), CliError> {
        let handle_identity = regular_file_identity_from_file(&self.file).map_err(|error| {
            remote_error_with_details(
                "artifact_validation_guard_failed",
                "a retained artifact handle no longer has its validated filesystem identity",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
                vec![error.to_string()],
            )
        })?;
        if handle_identity != self.identity {
            return Err(remote_error(
                "artifact_validation_guard_failed",
                "a retained artifact handle changed filesystem identity",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
            ));
        }
        #[cfg(windows)]
        if self.exact.identity() != &self.identity {
            return Err(remote_error(
                "artifact_validation_guard_failed",
                "an artifact replacement guard differs from its validated filesystem identity",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
            ));
        }
        verify_regular_file_identity(self.path.as_std_path(), &self.identity).map_err(|error| {
            remote_error_with_details(
                "artifact_validation_guard_failed",
                "a validated artifact path changed before durable success was committed",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
                vec![error.to_string()],
            )
        })?;
        if regular_file_identity_from_file(&self.file).map_err(|error| {
            remote_error_with_details(
                "artifact_validation_guard_failed",
                "a retained artifact handle could not be revalidated",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
                vec![error.to_string()],
            )
        })? != self.identity
        {
            return Err(remote_error(
                "artifact_validation_guard_failed",
                "a retained artifact handle changed during path revalidation",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
            ));
        }
        self.verify_bytes()?;
        Ok(())
    }

    fn verify_bytes(&self) -> Result<(), CliError> {
        let mut file = self.file.try_clone().map_err(|source| CliError::Io {
            action: "clone retained artifact handle for final validation",
            path: self.path.clone(),
            source,
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| CliError::Io {
                action: "rewind retained artifact for final validation",
                path: self.path.clone(),
                source,
            })?;
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        let mut bytes_read = 0_u64;
        loop {
            let count = file.read(buffer.as_mut()).map_err(|source| CliError::Io {
                action: "rehash retained artifact before reporting success",
                path: self.path.clone(),
                source,
            })?;
            if count == 0 {
                break;
            }
            bytes_read = bytes_read.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            if bytes_read > self.expected_size {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if bytes_read != self.expected_size || sha256_hex(digest.finalize()) != self.expected_sha256
        {
            return Err(remote_error(
                "artifact_validation_guard_failed",
                "a retained artifact changed bytes before durable success was reported",
                "Do not report success; preserve the local job and reconcile the exact artifact path.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CompletedArtifactDownloads {
    primary_sha256: String,
    destinations: BTreeMap<String, DownloadDestinationBinding>,
    validation_guards: Vec<RetainedArtifactValidation>,
}

#[derive(Debug)]
pub(super) struct ProjectFilesystemBinding {
    root: Utf8PathBuf,
    identity: DirectoryFilesystemIdentity,
    retained: RetainedDirectoryIdentity,
}

#[derive(Debug)]
struct DownloadDestinationBinding {
    path: String,
    managed_root: Utf8PathBuf,
    managed_root_identity: DirectoryFilesystemIdentity,
    managed_root_retained: RetainedDirectoryIdentity,
    parent: Utf8PathBuf,
    parent_identity: DirectoryFilesystemIdentity,
    parent_retained: RetainedDirectoryIdentity,
}

impl DownloadDestinationBinding {
    fn capture(
        path: &Utf8Path,
        project_binding: &ProjectFilesystemBinding,
    ) -> Result<Self, CliError> {
        project_binding.verify()?;
        let canonical_project_root =
            project_binding
                .root
                .canonicalize_utf8()
                .map_err(|source| CliError::Io {
                    action: "resolve the durable project root for artifact download",
                    path: project_binding.root.clone(),
                    source,
                })?;
        if canonical_project_root != project_binding.root {
            return Err(remote_error(
                "artifact_project_alias_rejected",
                "the durable project root resolves through a link, junction, or path alias",
                "Restore the exact canonical project directory before reconciling artifact downloads.",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            remote_error(
                "artifact_destination_invalid",
                "an artifact destination has no parent directory",
                "Use the standard project-local target directory.",
            )
        })?;
        let managed_root = canonical_project_root.join("target").join("ferry");
        let canonical_managed_root =
            managed_root
                .canonicalize_utf8()
                .map_err(|source| CliError::Io {
                    action: "resolve the managed artifact root",
                    path: managed_root.clone(),
                    source,
                })?;
        let canonical_parent = parent.canonicalize_utf8().map_err(|source| CliError::Io {
            action: "resolve an artifact destination parent",
            path: parent.to_owned(),
            source,
        })?;
        if canonical_managed_root != managed_root
            || canonical_parent != parent
            || !canonical_parent.starts_with(&canonical_managed_root)
        {
            return Err(remote_error(
                "artifact_parent_alias_rejected",
                "an artifact destination parent resolves through a link, junction, or path alias",
                "Restore a plain project-local target/ferry directory tree before retrying.",
            ));
        }
        let file_name = path.file_name().ok_or_else(|| {
            remote_error(
                "artifact_destination_invalid",
                "an artifact destination has no final file name",
                "Use the standard project-local artifact destination.",
            )
        })?;
        let canonical_path = canonical_parent.join(file_name);
        if canonical_path != path {
            return Err(remote_error(
                "artifact_destination_alias_rejected",
                "an artifact destination is not the exact canonical project-local path",
                "Use the standard project-local artifact destination without aliases.",
            ));
        }
        let parent_retained = RetainedDirectoryIdentity::open(canonical_parent.as_std_path())
            .map_err(|error| {
                remote_error_with_details(
                    "artifact_parent_identity_unavailable",
                    "an artifact destination parent could not be bound to a durable filesystem identity",
                    "Preserve the local job and restore the exact project target directory before retrying.",
                    vec![error.to_string()],
                )
            })?;
        let parent_identity = parent_retained.identity().clone();
        let managed_root_retained =
            RetainedDirectoryIdentity::open(canonical_managed_root.as_std_path()).map_err(
                |error| {
                    remote_error_with_details(
                        "artifact_root_identity_unavailable",
                        "the managed artifact root could not be bound to a filesystem identity",
                        "Preserve the local job and restore the exact project target directory before retrying.",
                        vec![error.to_string()],
                    )
                },
            )?;
        let managed_root_identity = managed_root_retained.identity().clone();
        let binding = Self {
            path: canonical_path.to_string(),
            managed_root: canonical_managed_root,
            managed_root_identity,
            managed_root_retained,
            parent: canonical_parent,
            parent_identity,
            parent_retained,
        };
        project_binding.verify()?;
        binding.verify(project_binding)?;
        Ok(binding)
    }

    fn verify_canonical_namespace(
        &self,
        project_binding: &ProjectFilesystemBinding,
    ) -> Result<(), CliError> {
        let canonical_project_root =
            project_binding
                .root
                .canonicalize_utf8()
                .map_err(|source| CliError::Io {
                    action: "re-resolve the durable project root for artifact download",
                    path: project_binding.root.clone(),
                    source,
                })?;
        let expected_managed_root = canonical_project_root.join("target").join("ferry");
        let canonical_managed_root =
            self.managed_root
                .canonicalize_utf8()
                .map_err(|source| CliError::Io {
                    action: "re-resolve the managed artifact root",
                    path: self.managed_root.clone(),
                    source,
                })?;
        let canonical_parent = self
            .parent
            .canonicalize_utf8()
            .map_err(|source| CliError::Io {
                action: "re-resolve the artifact destination parent",
                path: self.parent.clone(),
                source,
            })?;
        let path = Utf8Path::new(&self.path);
        if canonical_project_root != project_binding.root
            || expected_managed_root != self.managed_root
            || canonical_managed_root != self.managed_root
            || canonical_parent != self.parent
            || !canonical_parent.starts_with(&canonical_managed_root)
            || path.parent() != Some(self.parent.as_path())
        {
            return Err(remote_error(
                "artifact_namespace_changed",
                "the project, managed artifact root, or destination parent changed namespace binding",
                "Preserve the local job and reconcile the exact canonical destination before retrying.",
            ));
        }
        Ok(())
    }

    fn verify(&self, project_binding: &ProjectFilesystemBinding) -> Result<(), CliError> {
        project_binding.verify()?;
        self.verify_canonical_namespace(project_binding)?;
        self.managed_root_retained
            .verify_path(self.managed_root.as_std_path())
            .map_err(|error| {
                remote_error_with_details(
                    "artifact_root_identity_changed",
                    "the managed artifact root changed filesystem identity",
                    "Preserve the local job and reconcile its exact intended destination before retrying.",
                    vec![error.to_string()],
                )
            })?;
        verify_directory_identity(
            self.managed_root.as_std_path(),
            &self.managed_root_identity,
        )
        .map_err(|error| {
            remote_error_with_details(
                "artifact_root_identity_changed",
                "the managed artifact root changed filesystem identity",
                "Preserve the local job and reconcile its exact intended destination before retrying.",
                vec![error.to_string()],
            )
        })?;
        self.parent_retained
            .verify_path(self.parent.as_std_path())
            .map_err(|error| {
                remote_error_with_details(
                    "artifact_parent_identity_changed",
                    "an artifact destination parent changed filesystem identity",
                    "Preserve the local job and reconcile its exact intended destination before retrying.",
                    vec![error.to_string()],
                )
            })?;
        verify_directory_identity(self.parent.as_std_path(), &self.parent_identity).map_err(
            |error| {
                remote_error_with_details(
                    "artifact_parent_identity_changed",
                    "an artifact destination parent changed filesystem identity",
                    "Preserve the local job and reconcile its exact intended destination before retrying.",
                    vec![error.to_string()],
                )
            },
        )?;
        self.verify_canonical_namespace(project_binding)?;
        project_binding.verify()
    }
}

impl ProjectFilesystemBinding {
    pub(super) fn capture(root: &Utf8Path) -> Result<Self, CliError> {
        let canonical_root = root.canonicalize_utf8().map_err(|source| CliError::Io {
            action: "resolve project directory for durable job identity",
            path: root.to_owned(),
            source,
        })?;
        if canonical_root != root {
            return Err(remote_error(
                "project_path_alias_rejected",
                "the selected project path is not its exact canonical directory",
                "Use the canonical project directory without links, junctions, or path aliases.",
            ));
        }
        let identity = capture_project_directory_identity(&canonical_root).map_err(|error| {
            remote_error_with_details(
                "project_identity_unavailable",
                "the project directory could not be bound to a durable filesystem identity",
                "Keep the project on a local filesystem that supports stable directory identity, then retry.",
                vec![error.to_string()],
            )
        })?;
        let retained = RetainedDirectoryIdentity::open(canonical_root.as_std_path()).map_err(
            |error| {
                remote_error_with_details(
                    "project_identity_unavailable",
                    "the project directory could not be retained as an exact filesystem object",
                    "Keep the project on a local filesystem that supports stable directory identity, then retry.",
                    vec![error.to_string()],
                )
            },
        )?;
        if retained.identity() != &identity {
            return Err(remote_error(
                "project_identity_changed",
                "the project directory changed while its durable filesystem identity was captured",
                "Retry only after restoring the exact canonical project directory.",
            ));
        }
        let binding = Self {
            root: canonical_root,
            identity,
            retained,
        };
        binding.verify()?;
        Ok(binding)
    }

    pub(super) fn root(&self) -> &Utf8Path {
        &self.root
    }

    pub(super) fn identity_string(&self) -> String {
        self.identity.to_string()
    }

    pub(super) fn verify(&self) -> Result<(), CliError> {
        self.verify_canonical_root()?;
        self.retained
            .verify_path(self.root.as_std_path())
            .map_err(|error| {
                remote_error_with_details(
                    "project_identity_changed",
                    "the durable project directory identity changed during the remote build",
                    "Stop using this result; restore the exact original project directory before reconciling the local job.",
                    vec![error.to_string()],
                )
            })?;
        verify_project_directory_identity(&self.root, &self.identity).map_err(|error| {
            remote_error_with_details(
                "project_identity_changed",
                "the durable project directory identity changed during the remote build",
                "Stop using this result; restore the exact original project directory before reconciling the local job.",
                vec![error.to_string()],
            )
        })?;
        self.retained
            .verify_path(self.root.as_std_path())
            .map_err(|error| {
                remote_error_with_details(
                    "project_identity_changed",
                    "the durable project directory identity changed during the remote build",
                    "Stop using this result; restore the exact original project directory before reconciling the local job.",
                    vec![error.to_string()],
                )
            })?;
        self.verify_canonical_root()
    }

    fn verify_canonical_root(&self) -> Result<(), CliError> {
        let canonical_root = self
            .root
            .canonicalize_utf8()
            .map_err(|source| CliError::Io {
                action: "re-resolve the durable project directory",
                path: self.root.clone(),
                source,
            })?;
        if canonical_root != self.root {
            return Err(remote_error(
                "project_namespace_changed",
                "the durable project directory now resolves through a link, junction, or path alias",
                "Stop using this result; restore the exact original canonical project directory before reconciling the local job.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ArtifactFileIdentity(FileIdentityHandle);

impl ArtifactFileIdentity {
    fn capture(path: &Utf8Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Self::validate_metadata(&metadata)?;
        let identity = FileIdentityHandle::from_path(path)?;
        Self::validate_metadata(&identity.as_file().metadata()?)?;
        let final_metadata = fs::symlink_metadata(path)?;
        Self::validate_metadata(&final_metadata)?;
        if FileIdentityHandle::from_path(path)? != identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "file identity changed while it was captured",
            ));
        }
        Ok(Self(identity))
    }

    fn from_file(file: &File) -> std::io::Result<Self> {
        Self::validate_metadata(&file.metadata()?)?;
        Ok(Self(FileIdentityHandle::from_file(file.try_clone()?)?))
    }

    fn validate_metadata(metadata: &fs::Metadata) -> std::io::Result<()> {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file identity target is not a regular file",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CreatedArtifact {
    path: Utf8PathBuf,
    identity: ArtifactFileIdentity,
    #[cfg(windows)]
    persistent_identity: Option<RegularFileFilesystemIdentity>,
    #[cfg(windows)]
    exact_removal: Option<ExactRegularFileRemoval>,
}

#[derive(Default)]
pub(super) struct ArtifactDownloadRollback {
    created: Vec<CreatedArtifact>,
    committed: bool,
}

impl ArtifactDownloadRollback {
    #[cfg(test)]
    pub(super) fn record(&mut self, path: &Utf8Path) -> std::io::Result<()> {
        #[cfg(windows)]
        let exact_removal = {
            let persistent_identity = RegularFileFilesystemIdentity::capture(path.as_std_path())
                .map_err(std::io::Error::other)?;
            let removal = open_regular_file_for_exact_removal(path.as_std_path())
                .map_err(std::io::Error::other)?;
            if removal.identity() != &persistent_identity {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "exact removal handle differs from the captured artifact identity",
                ));
            }
            (persistent_identity, Some(removal))
        };
        self.created.push(CreatedArtifact {
            path: path.to_owned(),
            identity: ArtifactFileIdentity::capture(path)?,
            #[cfg(windows)]
            persistent_identity: Some(exact_removal.0),
            #[cfg(windows)]
            exact_removal: exact_removal.1,
        });
        Ok(())
    }

    pub(super) fn record_hard_link_from_file(
        &mut self,
        source: &File,
        path: &Utf8Path,
    ) -> std::io::Result<()> {
        let identity = ArtifactFileIdentity::from_file(source)?;
        self.created.push(CreatedArtifact {
            path: path.to_owned(),
            identity,
            #[cfg(windows)]
            persistent_identity: None,
            #[cfg(windows)]
            exact_removal: None,
        });
        let published = ArtifactFileIdentity::capture(path)?;
        if self
            .created
            .last()
            .is_none_or(|created| created.identity != published)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "hard-link publication changed filesystem identity",
            ));
        }
        Ok(())
    }

    pub(super) fn commit(&mut self) {
        self.committed = true;
    }

    pub(super) fn abort(&mut self) -> std::io::Result<()> {
        if self.committed {
            return Ok(());
        }
        let mut failed = false;
        while let Some(artifact) = self.created.pop() {
            if rollback_created_artifact(artifact).is_err() {
                failed = true;
            }
        }
        if failed {
            Err(std::io::Error::other(
                "one or more created artifact paths could not be rolled back safely",
            ))
        } else {
            self.committed = true;
            Ok(())
        }
    }
}

impl Drop for ArtifactDownloadRollback {
    fn drop(&mut self) {
        if !self.committed {
            while let Some(artifact) = self.created.pop() {
                let _ = rollback_created_artifact(artifact);
            }
        }
    }
}

fn rollback_created_artifact(artifact: CreatedArtifact) -> std::io::Result<()> {
    rollback_created_artifact_with(artifact, |_| {})
}

#[cfg(windows)]
fn rollback_created_artifact_with(
    mut artifact: CreatedArtifact,
    before_exact_removal: impl FnOnce(&Utf8Path),
) -> std::io::Result<()> {
    before_exact_removal(&artifact.path);
    let removal = artifact.exact_removal.take().ok_or_else(|| {
        std::io::Error::other(
            "artifact has no retained single-link handle for exact Windows rollback",
        )
    })?;
    let expected = artifact.persistent_identity.as_ref().ok_or_else(|| {
        std::io::Error::other("artifact has no persistent identity for exact Windows rollback")
    })?;
    if removal.identity() != expected {
        return Err(std::io::Error::other(
            "retained Windows rollback handle changed artifact identity",
        ));
    }
    removal.remove().map_err(std::io::Error::other)
}

#[cfg(not(windows))]
fn rollback_created_artifact_with(
    artifact: CreatedArtifact,
    after_quarantine: impl FnOnce(&Utf8Path),
) -> std::io::Result<()> {
    let Some(parent) = artifact.path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact path has no parent",
        ));
    };
    let quarantine = tempfile::Builder::new()
        .prefix(".rustferry-rollback-")
        .tempdir_in(parent)?;
    let quarantine_root =
        Utf8PathBuf::from_path_buf(quarantine.path().to_path_buf()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "rollback path is not UTF-8",
            )
        })?;
    let quarantined = quarantine_root.join("artifact");
    if let Err(error) = fs::rename(&artifact.path, &quarantined) {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
    after_quarantine(&quarantined);

    let current = ArtifactFileIdentity::capture(&quarantined);
    let unchanged = current
        .as_ref()
        .is_ok_and(|current| current == &artifact.identity);
    drop(current);
    drop(artifact.identity);
    let Ok(temporary_path) = tempfile::TempPath::try_from_path(quarantined.to_path_buf()) else {
        let _ = quarantine.keep();
        return Err(std::io::Error::other(
            "quarantined artifact path could not be guarded",
        ));
    };
    if unchanged {
        temporary_path.close()?;
        quarantine.close()?;
        return Ok(());
    }

    match temporary_path.persist_noclobber(&artifact.path) {
        Ok(()) => {
            let _ = quarantine.close();
            Err(std::io::Error::other(
                "artifact path changed identity during rollback",
            ))
        }
        Err(mut error) => {
            error.path.disable_cleanup(true);
            drop(error);
            let _ = quarantine.keep();
            Err(std::io::Error::other(
                "artifact replacement could not be restored after rollback",
            ))
        }
    }
}

pub fn run(arguments: RemoteArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        RemoteCommand::Add(arguments) => match arguments.provider {
            crate::cli::RemoteAddProvider::SshMac(arguments) => {
                super::ssh_remote::add(&arguments, dry_run, reporter)
            }
        },
        RemoteCommand::Setup(arguments) => setup(arguments, dry_run, reporter),
        RemoteCommand::Doctor(arguments) => {
            if arguments.target == "github" {
                doctor(&arguments, reporter)
            } else {
                super::ssh_remote::doctor(&arguments, reporter)
            }
        }
        RemoteCommand::Status(arguments) => status(&arguments, reporter),
        RemoteCommand::Bundle(arguments) => bundle(arguments, dry_run, reporter),
    }
}

fn bundle(arguments: RemoteBundleArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        RemoteBundleCommand::Inspect(arguments) => inspect_source_bundle(&arguments, reporter),
        RemoteBundleCommand::Create(arguments) => {
            create_source_bundle(&arguments, dry_run, reporter)
        }
        RemoteBundleCommand::Verify(arguments) => verify_source_bundle(&arguments, reporter),
    }
}

fn inspect_source_bundle(
    arguments: &RemoteBundleInspectArgs,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let project = find_project_root(arguments.project_dir.as_deref())?;
    let (workspace, plan, path_dependencies) =
        snapshot_source_bundle_plan(&project, &arguments.executable, reporter)?;
    let output = SourceBundleInspectOutput {
        project: project.to_string(),
        workspace: workspace.to_string(),
        path_dependencies,
        symlinks: Vec::new(),
        excluded_sensitive_paths: plan.excluded_sensitive_paths().to_vec(),
        manifest: plan.manifest().clone(),
    };
    reporter.success(
        "remote-bundle-inspect",
        &output,
        || {
            format!(
                "Source bundle\n\nProject:\n  {}\n\nWorkspace:\n  {}\n\nPath dependencies:\n{}\n\nSymlinks:\n  none (rejected during planning)\n\nExcluded sensitive paths:\n{}\n\nFiles:\n{}\n\nTotal:\n  {} files, {} bytes\n\nManifest SHA-256:\n  {}",
                output.project,
                output.workspace,
                source_bundle_audit_list(&output.path_dependencies),
                source_bundle_audit_list(&output.excluded_sensitive_paths),
                source_bundle_file_list(&output.manifest),
                output.manifest.entries.len(),
                output.manifest.total_size,
                output.manifest.sha256,
            )
        },
        &[],
    );
    Ok(())
}

fn create_source_bundle(
    arguments: &RemoteBundleCreateArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let project = find_project_root(arguments.project_dir.as_deref())?;
    let (workspace, plan, path_dependencies) =
        snapshot_source_bundle_plan(&project, &arguments.executable, reporter)?;
    let paths = source_bundle_output_paths(arguments, &workspace)?;

    if dry_run {
        report_source_bundle_create_plan(
            &project,
            &workspace,
            &paths,
            &plan,
            &path_dependencies,
            reporter,
        );
        return Ok(());
    }

    let limits = SourceArchiveLimits::default();
    let archive = create_source_bundle_archive(&plan, &paths.archive, limits)
        .map_err(|error| source_bundle_error("source_bundle_create_failed", &error))?;

    let descriptor = SourceBundleDescriptor::new(archive.clone(), plan.manifest().clone());
    write_source_bundle_descriptor_file(&descriptor, &paths.descriptor, limits).map_err(
        |error| {
            remote_error_with_details(
                "source_bundle_descriptor_create_failed",
                "the source archive was created, but its descriptor could not be published safely",
                "Keep the reported archive for inspection, then retry with two new output paths; RustFerry will not delete or overwrite a path after losing its filesystem identity.",
                vec![
                    format!("archive_path={}", paths.archive),
                    format!("descriptor_path={}", paths.descriptor),
                    error.to_string(),
                ],
            )
        },
    )?;

    report_created_source_bundle(
        &project,
        &workspace,
        &paths,
        &plan,
        path_dependencies,
        archive,
        reporter,
    );
    Ok(())
}

fn report_source_bundle_create_plan(
    project: &Utf8Path,
    workspace: &Utf8Path,
    paths: &SourceBundleOutputPaths,
    plan: &SourceBundlePlan,
    path_dependencies: &[String],
    reporter: &Reporter,
) {
    let output = SourceBundleCreateOutput {
        project: project.to_string(),
        workspace: workspace.to_string(),
        archive_path: paths.archive.to_string(),
        descriptor_path: paths.descriptor.to_string(),
        archive: None,
        path_dependencies: path_dependencies.to_vec(),
        symlinks: Vec::new(),
        excluded_sensitive_paths: plan.excluded_sensitive_paths().to_vec(),
        manifest: plan.manifest().clone(),
        created: false,
        dry_run: true,
    };
    reporter.success(
        "remote-bundle-create",
        &output,
        || {
            format!(
                "Source bundle creation plan\n\nArchive:\n  {}\n\nDescriptor:\n  {}\n\nPath dependencies:\n{}\n\nSymlinks:\n  none (rejected during planning)\n\nExcluded sensitive paths:\n{}\n\nFiles:\n{}\n\nTotal:\n  {} files, {} bytes\n\nManifest SHA-256:\n  {}",
                output.archive_path,
                output.descriptor_path,
                source_bundle_audit_list(&output.path_dependencies),
                source_bundle_audit_list(&output.excluded_sensitive_paths),
                source_bundle_file_list(&output.manifest),
                output.manifest.entries.len(),
                output.manifest.total_size,
                output.manifest.sha256,
            )
        },
        &[],
    );
}

fn report_created_source_bundle(
    project: &Utf8Path,
    workspace: &Utf8Path,
    paths: &SourceBundleOutputPaths,
    plan: &SourceBundlePlan,
    path_dependencies: Vec<String>,
    archive: SourceArchive,
    reporter: &Reporter,
) {
    let output = SourceBundleCreateOutput {
        project: project.to_string(),
        workspace: workspace.to_string(),
        archive_path: paths.archive.to_string(),
        descriptor_path: paths.descriptor.to_string(),
        archive: Some(archive),
        path_dependencies,
        symlinks: Vec::new(),
        excluded_sensitive_paths: plan.excluded_sensitive_paths().to_vec(),
        manifest: plan.manifest().clone(),
        created: true,
        dry_run: false,
    };
    reporter.success(
        "remote-bundle-create",
        &output,
        || {
            let archive = output.archive.as_ref().expect("created archive descriptor");
            format!(
                "✓ Created deterministic source bundle\n\nArchive:\n  {}\n  {} bytes\n  SHA-256: {}\n\nDescriptor:\n  {}\n\nSource:\n  {} files, {} bytes\n  SHA-256: {}",
                output.archive_path,
                archive.size,
                archive.sha256,
                output.descriptor_path,
                output.manifest.entries.len(),
                output.manifest.total_size,
                output.manifest.sha256,
            )
        },
        &[],
    );
}

fn source_bundle_output_paths(
    arguments: &RemoteBundleCreateArgs,
    workspace: &Utf8Path,
) -> Result<SourceBundleOutputPaths, CliError> {
    let archive = new_source_bundle_output(&arguments.output, "source archive")?;
    let descriptor_argument = arguments.descriptor.clone().unwrap_or_else(|| {
        Utf8PathBuf::from(format!("{}.manifest.json", arguments.output.as_str()))
    });
    let descriptor = new_source_bundle_output(&descriptor_argument, "source descriptor")?;
    if archive == descriptor {
        return Err(remote_error(
            "source_bundle_output_collision",
            "the source archive and descriptor resolve to the same path",
            "Choose two distinct new output paths.",
        ));
    }
    for (role, path) in [
        ("source archive", &archive),
        ("source descriptor", &descriptor),
    ] {
        if path.starts_with(workspace) {
            return Err(remote_error_with_details(
                "source_bundle_output_inside_workspace",
                format!("the {role} output is inside the selected Cargo workspace"),
                "Choose two new output paths outside the workspace so bundle creation cannot change its own source snapshot.",
                vec![format!("workspace={workspace}"), format!("path={path}")],
            ));
        }
    }
    Ok(SourceBundleOutputPaths {
        archive,
        descriptor,
    })
}

fn verify_source_bundle(
    arguments: &RemoteBundleVerifyArgs,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let descriptor_bytes = read_stable_source_bundle_file(
        &arguments.descriptor,
        MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES,
        "source bundle descriptor",
    )?;
    let descriptor =
        serde_json::from_slice::<SourceBundleDescriptor>(&descriptor_bytes).map_err(|_| {
            remote_error(
                "invalid_source_bundle_descriptor",
                "the source bundle descriptor is malformed or contains unknown fields",
                "Use the exact descriptor created with `cargo ferry remote bundle create`.",
            )
        })?;
    descriptor
        .validate(SourceArchiveLimits::default())
        .map_err(|error| source_bundle_error("invalid_source_bundle_descriptor", &error))?;

    let temporary = tempfile::Builder::new()
        .prefix("rustferry-source-verify-")
        .tempdir()
        .map_err(|source| CliError::Io {
            action: "create source verification directory",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
    let temporary_root = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
        .map_err(CliError::NonUtf8Path)?;
    let destination = temporary_root.join("extracted");
    let actual = verify_and_extract_source_bundle(
        &arguments.archive,
        &descriptor.archive,
        &descriptor.manifest,
        &destination,
        SourceArchiveLimits::default(),
    )
    .map_err(|error| source_bundle_error("source_bundle_verification_failed", &error))?;
    if actual != descriptor.archive {
        return Err(remote_error(
            "source_bundle_verification_failed",
            "the verified source archive descriptor changed unexpectedly",
            "Discard the archive and transfer it again from the trusted sender.",
        ));
    }

    let output = SourceBundleVerifyOutput {
        archive_path: arguments.archive.to_string(),
        descriptor_path: arguments.descriptor.to_string(),
        archive: actual,
        project_path: descriptor.manifest.project_path,
        source_sha256: descriptor.manifest.sha256,
        source_files: descriptor.manifest.entries.len(),
        source_bytes: descriptor.manifest.total_size,
        verified: true,
    };
    reporter.success(
        "remote-bundle-verify",
        &output,
        || {
            format!(
                "✓ Source bundle verified\n\nArchive:\n  {}\n  {} bytes\n  SHA-256: {}\n\nSource:\n  {} files, {} bytes\n  SHA-256: {}",
                output.archive_path,
                output.archive.size,
                output.archive.sha256,
                output.source_files,
                output.source_bytes,
                output.source_sha256,
            )
        },
        &[],
    );
    Ok(())
}

pub(super) fn snapshot_source_bundle_plan(
    project: &Utf8Path,
    explicit_executables: &[Utf8PathBuf],
    reporter: &Reporter,
) -> Result<(Utf8PathBuf, SourceBundlePlan, Vec<String>), CliError> {
    snapshot_source_bundle_plan_with_git_modes(project, explicit_executables, reporter, true)
}

fn snapshot_build_source_bundle_plan(
    project: &Utf8Path,
    reporter: &Reporter,
) -> Result<(Utf8PathBuf, SourceBundlePlan, Vec<String>), CliError> {
    snapshot_source_bundle_plan_with_git_modes(project, &[], reporter, false)
}

fn snapshot_source_bundle_plan_with_git_modes(
    project: &Utf8Path,
    explicit_executables: &[Utf8PathBuf],
    reporter: &Reporter,
    read_git_index_modes: bool,
) -> Result<(Utf8PathBuf, SourceBundlePlan, Vec<String>), CliError> {
    #[cfg(unix)]
    let _ = read_git_index_modes;
    let project = project.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve RustFerry project root",
        path: project.to_owned(),
        source,
    })?;
    let metadata = source_bundle_cargo_metadata(&project, reporter)?;
    let workspace = source_bundle_workspace(&metadata, &project)?;
    let selected_package = source_bundle_selected_package(&metadata, &project)?;
    let reachable = source_bundle_reachable_packages(&metadata, &selected_package)?;
    let (mut request, path_dependencies) =
        source_bundle_request(&metadata, &workspace, &project, &reachable)?;
    let baseline = plan_source_bundle(&request)
        .map_err(|error| source_bundle_error("source_bundle_plan_failed", &error))?;
    let executable_modes = explicit_executables
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    #[cfg(not(unix))]
    let mut executable_modes = executable_modes;
    #[cfg(not(unix))]
    {
        let selected = baseline
            .manifest()
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<HashSet<_>>();
        if read_git_index_modes {
            executable_modes.extend(
                git_index_executable_paths(&workspace, reporter)?
                    .into_iter()
                    .filter(|path| selected.contains(path.as_str())),
            );
        }
    }
    if executable_modes.is_empty() {
        return Ok((workspace, baseline, path_dependencies));
    }
    for path in executable_modes {
        request = request.with_executable_mode(path, true);
    }
    let plan = plan_source_bundle(&request)
        .map_err(|error| source_bundle_error("source_bundle_plan_failed", &error))?;
    Ok((workspace, plan, path_dependencies))
}

fn source_bundle_cargo_metadata(
    project: &Utf8Path,
    reporter: &Reporter,
) -> Result<CargoMetadata, CliError> {
    let cargo = executable("cargo")?;
    let metadata_target_directory = tempfile::Builder::new()
        .prefix("rustferry-cargo-metadata-")
        .tempdir()
        .map_err(|source| CliError::Io {
            action: "create isolated Cargo metadata directory",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
    let metadata_target = Utf8PathBuf::from_path_buf(metadata_target_directory.path().to_owned())
        .map_err(CliError::NonUtf8Path)?;
    let target_config = format!(
        "build.target-dir={}",
        serde_json::to_string(metadata_target.as_str()).expect("UTF-8 path is JSON encodable")
    );
    let output = checked_output(
        &cargo,
        &[
            OsString::from("metadata"),
            OsString::from("--format-version"),
            OsString::from("1"),
            OsString::from("--locked"),
            OsString::from("--offline"),
            OsString::from("--config"),
            OsString::from(target_config),
        ],
        project,
        "read Cargo metadata for source bundle",
        reporter,
    )?;
    serde_json::from_slice(&output).map_err(|_| {
        remote_error(
            "invalid_cargo_metadata",
            "Cargo returned malformed or unsupported project metadata",
            "Run `cargo metadata --format-version 1 --locked` and correct the manifest error.",
        )
    })
}

fn source_bundle_workspace(
    metadata: &CargoMetadata,
    project: &Utf8Path,
) -> Result<Utf8PathBuf, CliError> {
    let workspace = metadata
        .workspace_root
        .canonicalize_utf8()
        .map_err(|source| CliError::Io {
            action: "resolve Cargo workspace root",
            path: metadata.workspace_root.clone(),
            source,
        })?;
    if project.starts_with(&workspace) {
        Ok(workspace)
    } else {
        Err(remote_error(
            "project_outside_workspace",
            "the RustFerry project is outside the Cargo workspace selected by metadata",
            "Run the command from the workspace that contains the project.",
        ))
    }
}

fn source_bundle_selected_package(
    metadata: &CargoMetadata,
    project: &Utf8Path,
) -> Result<String, CliError> {
    for package in metadata
        .packages
        .iter()
        .filter(|package| package.source.is_none())
    {
        if source_bundle_package_root(package)? == project {
            return Ok(package.id.clone());
        }
    }
    Err(remote_error(
        "project_package_not_found",
        "Cargo metadata did not identify the selected RustFerry project package",
        "Run the command from a package directory containing both Cargo.toml and ferry.toml.",
    ))
}

fn source_bundle_reachable_packages(
    metadata: &CargoMetadata,
    selected_package: &str,
) -> Result<HashSet<String>, CliError> {
    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        remote_error(
            "cargo_dependency_graph_unavailable",
            "Cargo metadata did not return a resolved dependency graph",
            "Run `cargo metadata --format-version 1 --locked` and correct the workspace resolution error.",
        )
    })?;
    let dependencies = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.dependencies.as_slice()))
        .collect::<BTreeMap<_, _>>();
    if !dependencies.contains_key(selected_package) {
        return Err(remote_error(
            "project_dependency_graph_missing",
            "Cargo's resolved dependency graph does not contain the selected project package",
            "Regenerate Cargo.lock and rerun `cargo metadata --format-version 1 --locked`.",
        ));
    }
    let mut reachable = HashSet::new();
    let mut pending = vec![selected_package.to_owned()];
    while let Some(package) = pending.pop() {
        if !reachable.insert(package.clone()) {
            continue;
        }
        if let Some(package_dependencies) = dependencies.get(package.as_str()) {
            pending.extend(
                package_dependencies
                    .iter()
                    .map(|dependency| (*dependency).clone()),
            );
        }
    }
    Ok(reachable)
}

fn source_bundle_request(
    metadata: &CargoMetadata,
    workspace: &Utf8Path,
    project: &Utf8Path,
    reachable: &HashSet<String>,
) -> Result<(SourceBundleRequest, Vec<String>), CliError> {
    let workspace_members = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut included = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    for package in metadata.packages.iter().filter(|package| {
        package.source.is_none()
            && (reachable.contains(&package.id) || workspace_members.contains(package.id.as_str()))
    }) {
        let canonical = source_bundle_package_root(package)?;
        let relative = canonical.strip_prefix(workspace).map_err(|_| {
            remote_error(
                "local_dependency_outside_workspace",
                "a local Cargo path dependency is outside the selected workspace",
                "Move the dependency into the workspace or publish it before creating a portable snapshot.",
            )
        })?;
        if canonical == project {
            continue;
        }
        if relative.as_str().is_empty() || relative == Utf8Path::new(".") {
            if reachable.contains(&package.id) {
                return Err(remote_error(
                    "workspace_root_dependency_unsupported",
                    "a nested RustFerry project depends on a package rooted at the workspace root",
                    "Move the shared package into a named workspace subdirectory or create the bundle from a root RustFerry project.",
                ));
            }
            continue;
        }
        if reachable.contains(&package.id) {
            included.insert(relative.to_owned());
        } else if project == workspace && workspace_members.contains(package.id.as_str()) {
            excluded.insert(relative.to_owned());
        }
    }
    reject_overlapping_package_roots(&included, &excluded)?;

    let path_dependencies = included.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut request = SourceBundleRequest::new(workspace, project);
    for path in included {
        request = request.include_workspace_path(path);
    }
    for path in excluded {
        request = request.exclude_workspace_path(path);
    }
    Ok((request, path_dependencies))
}

fn source_bundle_package_root(package: &CargoMetadataPackage) -> Result<Utf8PathBuf, CliError> {
    let parent = package.manifest_path.parent().ok_or_else(|| {
        remote_error(
            "invalid_local_dependency",
            "a local Cargo package manifest has no parent directory",
            "Correct the local package manifest path.",
        )
    })?;
    parent.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve local Cargo package",
        path: parent.to_owned(),
        source,
    })
}

fn reject_overlapping_package_roots(
    included: &BTreeSet<Utf8PathBuf>,
    excluded: &BTreeSet<Utf8PathBuf>,
) -> Result<(), CliError> {
    if let Some((dependency, unrelated)) = included.iter().find_map(|dependency| {
        excluded
            .iter()
            .find(|unrelated| dependency.starts_with(unrelated))
            .map(|unrelated| (dependency, unrelated))
    }) {
        return Err(remote_error_with_details(
            "overlapping_workspace_package_roots",
            "an unrelated workspace package contains a required local dependency",
            "Move the nested package to a distinct workspace path before creating a portable snapshot.",
            vec![
                format!("required={dependency}"),
                format!("unrelated={unrelated}"),
            ],
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn git_index_executable_paths(
    workspace: &Utf8Path,
    reporter: &Reporter,
) -> Result<BTreeSet<Utf8PathBuf>, CliError> {
    let Some(found) = find_in_path("git") else {
        reporter.verbose(
            "Git is unavailable; pass --executable for source files that need a Unix executable bit",
        );
        return Ok(BTreeSet::new());
    };
    let git = executable_entrypoint(&found, "git")?;
    let output = run_captured_bounded(
        &git,
        &[
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
            OsString::from("--"),
        ],
        workspace,
        "read portable executable modes from the Git index",
        reporter,
        MAX_TOOL_OUTPUT_BYTES,
    )?;
    if !output.status.success() {
        reporter.verbose(
            "No Git index is available; pass --executable for source files that need a Unix executable bit",
        );
        return Ok(BTreeSet::new());
    }
    parse_git_index_executable_paths(&output.stdout)
}

#[cfg(any(test, not(unix)))]
fn parse_git_index_executable_paths(bytes: &[u8]) -> Result<BTreeSet<Utf8PathBuf>, CliError> {
    let mut executable = BTreeSet::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                remote_error(
                    "invalid_git_executable_metadata",
                    "Git returned a malformed index entry while reading executable modes",
                    "Resolve the Git index and retry, or pass explicit --executable paths.",
                )
            })?;
        let header = std::str::from_utf8(&record[..separator]).map_err(|_| {
            remote_error(
                "invalid_git_executable_metadata",
                "Git returned non-UTF-8 executable metadata",
                "Use UTF-8 repository paths or pass explicit --executable paths.",
            )
        })?;
        let mut fields = header.split_ascii_whitespace();
        let mode = fields.next();
        let object = fields.next();
        let stage = fields.next();
        if mode.is_none()
            || object.is_none()
            || stage.is_none()
            || fields.next().is_some()
            || stage != Some("0")
        {
            return Err(remote_error(
                "invalid_git_executable_metadata",
                "Git returned an unresolved or malformed index entry",
                "Resolve index conflicts and retry, or pass explicit --executable paths.",
            ));
        }
        if mode != Some("100755") {
            continue;
        }
        let path = std::str::from_utf8(&record[separator + 1..]).map_err(|_| {
            remote_error(
                "invalid_git_executable_metadata",
                "Git returned a non-UTF-8 executable path",
                "Use UTF-8 repository paths or pass an explicit --executable path.",
            )
        })?;
        executable.insert(Utf8PathBuf::from(path));
    }
    Ok(executable)
}

fn source_bundle_file_list(manifest: &SourceManifest) -> String {
    manifest
        .entries
        .iter()
        .map(|entry| {
            let mode = if entry.executable {
                "executable"
            } else {
                "file"
            };
            format!(
                "  {}  {:>10}  {mode}  {}",
                entry.sha256, entry.size, entry.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn source_bundle_audit_list(paths: &[String]) -> String {
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

fn new_source_bundle_output(path: &Utf8Path, role: &'static str) -> Result<Utf8PathBuf, CliError> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            remote_error(
                "invalid_source_bundle_destination",
                format!("the {role} path has no file name"),
                "Choose a new regular-file path in an existing directory.",
            )
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_str().is_empty())
        .unwrap_or_else(|| Utf8Path::new("."));
    let parent = parent.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve source bundle output directory",
        path: parent.to_owned(),
        source,
    })?;
    let resolved = parent.join(file_name);
    match fs::symlink_metadata(&resolved) {
        Ok(_) => Err(remote_error_with_details(
            "source_bundle_output_exists",
            format!("the {role} output already exists or is linked"),
            "Choose a new path; RustFerry never overwrites source bundle output.",
            vec![format!("path={resolved}")],
        )),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(resolved),
        Err(source) => Err(CliError::Io {
            action: "inspect source bundle output",
            path: resolved,
            source,
        }),
    }
}

fn read_stable_source_bundle_file(
    path: &Utf8Path,
    maximum: u64,
    role: &'static str,
) -> Result<Vec<u8>, CliError> {
    let initial_metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect source bundle input",
        path: path.to_owned(),
        source,
    })?;
    validate_source_bundle_input_metadata(&initial_metadata, maximum, role)?;
    let initial_length = initial_metadata.len();
    let initial_modified = initial_metadata.modified().ok();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| CliError::Io {
        action: "open source bundle input",
        path: path.to_owned(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect open source bundle input",
        path: path.to_owned(),
        source,
    })?;
    validate_source_bundle_input_metadata(&opened_metadata, maximum, role)?;
    let opened_identity =
        ArtifactFileIdentity::from_file(&file).map_err(|source| CliError::Io {
            action: "identify open source bundle input",
            path: path.to_owned(),
            source,
        })?;
    let linked_identity = ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
        action: "identify source bundle input path",
        path: path.to_owned(),
        source,
    })?;
    if linked_identity != opened_identity
        || opened_metadata.len() != initial_length
        || opened_metadata.modified().ok() != initial_modified
    {
        return Err(source_bundle_input_changed(role));
    }

    let mut bytes =
        Vec::with_capacity(usize::try_from(initial_length.min(1024 * 1024)).unwrap_or(1024 * 1024));
    (&file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read source bundle input",
            path: path.to_owned(),
            source,
        })?;
    let final_metadata = file.metadata().map_err(|source| CliError::Io {
        action: "reinspect open source bundle input",
        path: path.to_owned(),
        source,
    })?;
    let final_identity = ArtifactFileIdentity::from_file(&file).map_err(|source| CliError::Io {
        action: "reidentify open source bundle input",
        path: path.to_owned(),
        source,
    })?;
    let final_linked = ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
        action: "reidentify source bundle input path",
        path: path.to_owned(),
        source,
    })?;
    if bytes.len() as u64 != initial_length
        || final_metadata.len() != initial_length
        || final_metadata.modified().ok() != initial_modified
        || final_identity != opened_identity
        || final_linked != opened_identity
    {
        return Err(source_bundle_input_changed(role));
    }
    Ok(bytes)
}

fn validate_source_bundle_input_metadata(
    metadata: &fs::Metadata,
    maximum: u64,
    role: &'static str,
) -> Result<(), CliError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(remote_error(
            "invalid_source_bundle_input",
            format!("the {role} is not a bounded regular file"),
            "Use a regular no-link file created by the source bundle command.",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(remote_error(
                "invalid_source_bundle_input",
                format!("the {role} has multiple filesystem links"),
                "Copy it to a new regular file and retry verification.",
            ));
        }
    }
    Ok(())
}

fn source_bundle_input_changed(role: &'static str) -> CliError {
    remote_error(
        "source_bundle_input_changed",
        format!("the {role} changed while it was being read"),
        "Stop concurrent writes and retry with a stable copy.",
    )
}

fn source_bundle_error(code: &'static str, error: &rustferry_remote::SourceError) -> CliError {
    remote_error_with_details(
        code,
        "the deterministic source bundle operation failed safely",
        "Inspect the selected paths and retry from a stable, portable source tree.",
        vec![error.to_string()],
    )
}

fn signing_project_state_changed() -> CliError {
    remote_error(
        "signing_project_state_changed",
        "the project signing inputs changed during manual signing setup",
        "Restore the reviewed ferry.toml, Cargo target, and generated signing target graph, then rerun setup. If upload already began, delete every reported secret name first.",
    )
}

fn signing_project_state_from_inputs(
    ferry_config: rustferry_core::FerryConfig,
    binary_name: String,
) -> Result<SigningProjectState, CliError> {
    let targets = unsigned_signing_plan(&ferry_config, &binary_name)
        .map_err(|_| signing_project_state_changed())?
        .targets;
    Ok(SigningProjectState {
        ferry_config,
        binary_name,
        targets,
    })
}

fn load_signing_project_state(root: &Utf8Path) -> Result<SigningProjectState, CliError> {
    let ferry_config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))
        .map_err(|_| signing_project_state_changed())?;
    let cargo_targets = super::platform_build::read_cargo_targets(root)
        .map_err(|_| signing_project_state_changed())?;
    signing_project_state_from_inputs(ferry_config, cargo_targets.binary().to_owned())
}

fn ensure_signing_project_state_unchanged(
    root: &Utf8Path,
    expected: &SigningProjectState,
) -> Result<(), CliError> {
    if load_signing_project_state(root)? != *expected {
        return Err(signing_project_state_changed());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn prepare_manual_github_signing(
    root: &Utf8Path,
    plan: SigningPlan,
    assets: ManualGithubSigningAssets,
    expected_ferry_config: &rustferry_core::FerryConfig,
    expected_binary_name: &str,
    mutating: bool,
) -> Result<ManualGithubSigningSession<GithubManualSigningRemote>, CliError> {
    validate_manual_assets_match_plan(&plan, &assets)?;
    let expected_project_state = signing_project_state_from_inputs(
        expected_ferry_config.clone(),
        expected_binary_name.to_owned(),
    )?;
    if expected_project_state.targets != plan.targets {
        return Err(signing_project_state_changed());
    }
    ensure_signing_project_state_unchanged(root, &expected_project_state)?;
    let config_lock_path = root.join(CONFIG_LOCK_RELATIVE_PATH);
    let config_lock = provider_config_lock_for_signing(root, &config_lock_path, mutating)?;
    let stored = load_config(root)?;
    if stored.signing.is_some() {
        return Err(remote_error(
            "signing_already_configured",
            "manual-development signing is already configured",
            "Use the existing signing configuration. Secret rotation requires an explicit replacement workflow.",
        ));
    }
    if stored.signing_targets.is_empty() {
        if plan
            .targets
            .iter()
            .filter(|target| {
                matches!(
                    target.kind,
                    SigningTargetKind::Application | SigningTargetKind::Extension
                )
            })
            .count()
            != 1
        {
            return Err(remote_error(
                "legacy_provider_target_map_unsupported",
                "the legacy GitHub provider config supports only one application profile",
                "After confirming the protected Environment is still empty, remove the generated unsigned provider config and workflow, then rerun GitHub remote setup and review the replacement before committing it.",
            ));
        }
    } else if stored.signing_targets != plan.targets {
        return Err(remote_error(
            "signing_target_graph_changed",
            "the current signing target graph differs from the installed workflow map",
            "Rerun GitHub remote setup, review and commit the workflow, then rerun signing setup without changing targets.",
        ));
    }
    let (git, execution) =
        git_context_from_stored(root, &stored, &Reporter::new(false, true, false))?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    if git
        .repository_slug
        .eq_ignore_ascii_case(&execution.repository_slug)
    {
        return Err(remote_error(
            "separate_signing_repository_required",
            "manual-development signing requires a separate private execution repository",
            "Configure distinct public-source and private-execution Git remotes before uploading signing assets.",
        ));
    }

    let paths = GithubPaths::new(root, &git.root);
    let generated = generate_workflow(&workflow_from_stored(&stored)?);
    let expected_workflow = generated.yaml().as_bytes().to_vec();
    if !existing_file_matches(&paths.workflow, &expected_workflow)? {
        return Err(remote_error(
            "workflow_mismatch",
            "the installed GitHub workflow does not match the configured signing policy",
            "Restore the exact generated workflow and commit it before configuring signing assets.",
        ));
    }
    let (original_config_identity, original_config_bytes) =
        capture_config_snapshot(root, &paths.config, &stored)?;

    let environment =
        ProtectedEnvironment::new(stored.protected_environment.clone()).map_err(|_| {
            remote_error(
                "invalid_provider_config",
                "the configured protected Environment is invalid",
                "Remove the generated provider config and rerun GitHub setup.",
            )
        })?;
    let secret_names = if stored.signing_targets.is_empty() {
        SigningSecretNames::goal3_defaults()
    } else {
        SigningSecretNames::for_targets(&plan.targets).map_err(|error| {
            remote_error_with_details(
                "invalid_signing_target_secret_map",
                "the signing plan cannot reproduce the installed static secret map",
                "Rerun GitHub setup and signing setup from one unchanged target graph.",
                vec![error.to_string()],
            )
        })?
    };
    let mut remote = GithubManualSigningRemote {
        transport: GithubTransport::new(make_gh_runner(root)?, TransportLimits::secure_defaults()),
    };
    let existing_names = remote.verify_policy(
        &git.repository,
        &execution.repository,
        &environment,
        &stored,
        "initial_preflight",
    )?;
    if !existing_names.is_empty() {
        return Err(remote_error_with_details(
            "signing_environment_not_empty",
            "the protected signing Environment already contains secrets",
            "Delete the listed secret roles before initial setup. Existing signing material is never replaced implicitly.",
            existing_names
                .into_iter()
                .map(|name| format!("existing_secret={name}"))
                .collect(),
        ));
    }

    let session = ManualGithubSigningSession {
        root: root.to_owned(),
        expected_project_state,
        paths,
        stored,
        original_config_identity: Some(original_config_identity),
        original_config_bytes,
        expected_workflow,
        plan,
        assets,
        source_repository: git.repository,
        execution_repository: execution.repository,
        environment,
        secret_names,
        remote,
        config_lock,
    };
    session.recheck_local_state()?;
    Ok(session)
}

fn validate_manual_assets_match_plan(
    plan: &SigningPlan,
    assets: &ManualGithubSigningAssets,
) -> Result<(), CliError> {
    validate_github_signing_plan(plan)?;
    let signing = plan
        .signing
        .as_ref()
        .expect("validated manual signing plan has an identity");
    let device = plan
        .device
        .as_ref()
        .expect("validated manual signing plan has a device");
    let expected_targets = plan
        .provisioning
        .iter()
        .map(|profile| profile.target.as_str())
        .collect::<BTreeSet<_>>();
    if signing.identity.certificate != assets.certificate
        || assets
            .profiles
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_targets
        || assets.profiles.values().any(|profile| {
            profile.team.id() != assets.certificate.team.id()
                || profile.profile_type != rustferry_remote::ProvisioningProfileType::Development
                || !profile
                    .device_udid_sha256s
                    .iter()
                    .any(|candidate| candidate == device.udid_sha256())
        })
    {
        return Err(remote_error(
            "validated_signing_assets_mismatch",
            "the validated signing assets do not exactly match the public signing plan",
            "Revalidate the development certificate, profile, target, and selected device together before upload.",
        ));
    }
    Ok(())
}

impl<R: ManualSigningRemote> ManualGithubSigningSession<R> {
    pub(super) fn preview(&self, installed: bool, dry_run: bool) -> ManualGithubSigningPreview {
        let signing = self
            .plan
            .signing
            .as_ref()
            .expect("validated manual signing plan has an identity");
        let device = self
            .plan
            .device
            .as_ref()
            .expect("validated manual signing plan has a device");
        let mut target_bundle_identifiers = self
            .plan
            .targets
            .iter()
            .map(|target| target.bundle_identifier.as_str().to_owned())
            .collect::<Vec<_>>();
        target_bundle_identifiers.sort();
        ManualGithubSigningPreview {
            source_repository: self.stored.source_repository.clone(),
            execution_repository: format!(
                "{}/{}",
                self.execution_repository.owner(),
                self.execution_repository.name()
            ),
            protected_environment: self.environment.as_str().to_owned(),
            required_secret_names: required_signing_secret_names(&self.secret_names)
                .into_iter()
                .collect(),
            team_id: signing.identity.certificate.team.id().to_owned(),
            certificate_common_name: self.assets.certificate.common_name.clone(),
            certificate_sha256: signing.identity.certificate.sha256_fingerprint.clone(),
            certificate_expires_at_unix_seconds: signing
                .identity
                .certificate
                .expires_at_unix_seconds,
            profiles: self
                .assets
                .profiles
                .iter()
                .map(|(target, profile)| ManualGithubProfilePreview {
                    target: target.clone(),
                    secret_name: self
                        .secret_names
                        .profile_for_target(target)
                        .expect("validated secret map covers every profile target")
                        .as_str()
                        .to_owned(),
                    uuid: profile.uuid.clone(),
                    name: profile.name.clone(),
                    expires_at_unix_seconds: profile.expires_at_unix_seconds,
                    profile_type: match profile.profile_type {
                        rustferry_remote::ProvisioningProfileType::Development => "development",
                        rustferry_remote::ProvisioningProfileType::AdHoc => "ad-hoc",
                        rustferry_remote::ProvisioningProfileType::AppStore => "app-store",
                    },
                    bundle_identifier_pattern: profile.bundle_identifier_pattern.clone(),
                })
                .collect(),
            device_udid_sha256: device.udid_sha256().to_owned(),
            target_bundle_identifiers,
            installed,
            dry_run,
        }
    }

    pub(super) fn install(
        mut self,
        values: &ManualGithubSecretValues,
    ) -> Result<ManualGithubSigningPreview, CliError> {
        if self.config_lock.is_none() {
            return Err(remote_error(
                "provider_config_lock_required",
                "manual signing installation has no provider-config lock",
                "Restart the mutating signing setup command.",
            ));
        }
        self.recheck_local_state()?;
        let existing_names = self.remote.verify_policy(
            &self.source_repository,
            &self.execution_repository,
            &self.environment,
            &self.stored,
            "before_upload",
        )?;
        if !existing_names.is_empty() {
            return Err(remote_error_with_details(
                "signing_environment_changed",
                "the protected signing Environment changed after validation",
                "Delete the listed secret roles, then rerun setup from a clean protected Environment.",
                existing_names
                    .into_iter()
                    .map(|name| format!("existing_secret={name}"))
                    .collect(),
            ));
        }
        self.recheck_local_state()?;

        let uploaded_secrets = self.upload_signing_values(values)?;

        let actual_names = self
            .remote
            .verify_policy(
                &self.source_repository,
                &self.execution_repository,
                &self.environment,
                &self.stored,
                "after_upload",
            )
            .map_err(|error| signing_post_upload_error(&error, &uploaded_secrets))?;
        if actual_names != required_signing_secret_names(&self.secret_names) {
            let mut details = uploaded_signing_secret_details(&uploaded_secrets);
            details.extend(
                actual_names
                    .into_iter()
                    .map(|name| format!("reported_secret={name}")),
            );
            return Err(remote_error_with_details(
                "github_signing_secret_postcheck_failed",
                "GitHub did not report the exact protected signing secret-name set after upload",
                "The local provider config remains unsigned. Delete every listed uploaded secret name, inspect only secret names in the protected Environment, and retry.",
                details,
            ));
        }
        self.recheck_local_state()
            .map_err(|error| signing_post_upload_error(&error, &uploaded_secrets))?;

        self.stored.signing = Some(self.plan.clone());
        validate_stored_config(&self.stored)
            .map_err(|error| signing_post_upload_error(&error, &uploaded_secrets))?;
        let bytes = encode_stored_config(&self.stored)
            .map_err(|error| signing_post_upload_error(&error, &uploaded_secrets))?;
        let config_lock = self
            .config_lock
            .as_ref()
            .expect("provider-config lock checked before remote mutation");
        let original_config_identity = self
            .original_config_identity
            .take()
            .expect("provider config identity checked before remote mutation");
        match replace_private_config(
            &self.root,
            &self.paths.config,
            &bytes,
            original_config_identity,
            &self.original_config_bytes,
            &self.stored,
            config_lock,
        ) {
            Ok(()) => {}
            Err(ConfigCommitError::NotCommitted(error)) => {
                return Err(signing_post_upload_error(error.as_ref(), &uploaded_secrets));
            }
            Err(ConfigCommitError::CommittedNeedsInspection(error)) => {
                return Err(signing_config_commit_uncertain(
                    error.as_ref(),
                    &uploaded_secrets,
                ));
            }
        }
        Ok(self.preview(true, false))
    }

    fn upload_signing_values(
        &mut self,
        values: &ManualGithubSecretValues,
    ) -> Result<Vec<SigningSecretUpload>, CliError> {
        let mut writes = vec![(
            "certificate_p12".to_owned(),
            self.secret_names.certificate_p12().clone(),
            values.certificate_p12.as_secret(),
        )];
        let mut provisioning = self.plan.provisioning.iter().collect::<Vec<_>>();
        provisioning.sort_by(|left, right| left.target.cmp(&right.target));
        for planned in provisioning {
            let value = values.profiles.get(&planned.target).ok_or_else(|| {
                remote_error_with_details(
                    "signing_secret_value_mismatch",
                    "a validated target profile has no retained upload value",
                    "Do not upload. Restart signing setup from the original stable asset files.",
                    vec![format!("target={}", planned.target)],
                )
            })?;
            let name = rustferry_github::SecretName::new(planned.profile.name()).map_err(|_| {
                remote_error(
                    "invalid_github_signing_secret_name",
                    "a target profile has an invalid protected secret name",
                    "Regenerate the provider workflow and signing plan.",
                )
            })?;
            writes.push((
                format!("provisioning_profile:{}", planned.target),
                name,
                value.as_secret(),
            ));
        }
        // Password last: an interrupted earlier write cannot leave a remotely usable identity.
        writes.push((
            "certificate_password".to_owned(),
            self.secret_names.certificate_password().clone(),
            values.certificate_password.as_secret(),
        ));
        let mut uploaded_secrets = Vec::with_capacity(writes.len());
        for (role, name, value) in writes {
            let upload = SigningSecretUpload {
                role,
                secret_name: name.as_str().to_owned(),
            };
            let request = EnvironmentSecretWriteRequest::new(
                self.execution_repository.clone(),
                self.environment.clone(),
                name,
            );
            if let Err(error) = self.remote.set_secret(&request, value) {
                let mut details = vec![
                    format!("possibly_uploaded_role={}", upload.role),
                    format!("possibly_uploaded_secret={}", upload.secret_name),
                ];
                details.extend(uploaded_signing_secret_details(&uploaded_secrets));
                return Err(remote_error_with_details(
                    "github_signing_secret_upload_indeterminate",
                    "a GitHub signing-secret write did not return a reliable outcome",
                    "The local provider config remains unsigned. Delete every listed uploaded and possibly-uploaded secret name from the protected Environment before retrying.",
                    {
                        details.push(format!("transport={error}"));
                        details
                    },
                ));
            }
            uploaded_secrets.push(upload);
        }
        Ok(uploaded_secrets)
    }

    fn recheck_local_state(&self) -> Result<(), CliError> {
        ensure_signing_project_state_unchanged(&self.root, &self.expected_project_state)?;
        let (identity, bytes) =
            capture_config_snapshot(&self.root, &self.paths.config, &self.stored)?;
        if self
            .original_config_identity
            .as_ref()
            .is_none_or(|expected| &identity != expected)
            || bytes != self.original_config_bytes
        {
            return Err(remote_error(
                "provider_config_changed",
                "the GitHub provider config changed during signing setup",
                "Inspect the concurrent change and rerun signing setup from a stable unsigned config.",
            ));
        }
        if !existing_file_matches(&self.paths.workflow, &self.expected_workflow)? {
            return Err(remote_error(
                "workflow_changed",
                "the generated GitHub workflow changed during signing setup",
                "Restore the exact generated workflow and rerun signing setup.",
            ));
        }
        Ok(())
    }
}

fn required_signing_secret_names(names: &SigningSecretNames) -> BTreeSet<String> {
    names
        .all_names()
        .map(|name| name.as_str().to_owned())
        .collect()
}

fn capture_config_snapshot(
    root: &Utf8Path,
    path: &Utf8Path,
    expected: &StoredGithubConfig,
) -> Result<(ArtifactFileIdentity, Vec<u8>), CliError> {
    let (identity, bytes) = read_private_config_snapshot(root, path)?;
    let decoded = serde_json::from_slice::<StoredGithubConfig>(&bytes).map_err(|_| {
        remote_error(
            "provider_config_changed",
            "the GitHub provider config became malformed during signing setup",
            "Restore the original private provider config and rerun signing setup.",
        )
    })?;
    if &decoded != expected {
        return Err(remote_error(
            "provider_config_changed",
            "the GitHub provider config changed during signing setup",
            "Inspect the concurrent change and rerun signing setup from a stable unsigned config.",
        ));
    }
    Ok((identity, bytes))
}

#[allow(clippy::too_many_arguments)]
fn verify_manual_signing_policy(
    transport: &mut GithubTransport<GhProcessRunner>,
    source_repository: &Repository,
    execution_repository: &Repository,
    environment: &ProtectedEnvironment,
    stored: &StoredGithubConfig,
    phase: &'static str,
) -> Result<BTreeSet<String>, CliError> {
    transport
        .authenticate(execution_repository)
        .map_err(|error| signing_policy_transport_error(phase, "authentication", error))?;
    let source_info = transport
        .repository(source_repository)
        .map_err(|error| signing_policy_transport_error(phase, "source_repository", error))?;
    if source_info.is_private() {
        return Err(remote_error(
            "private_source_repository",
            "manual signing requires the configured source repository to remain public",
            "Use a public source repository and keep all signing execution in the private execution repository.",
        ));
    }
    let execution_info = transport
        .repository(execution_repository)
        .map_err(|error| signing_policy_transport_error(phase, "execution_repository", error))?;
    if !execution_info.is_private() || execution_info.is_archived() || execution_info.is_disabled()
    {
        return Err(remote_error(
            "private_execution_repository_required",
            "manual signing requires an active private execution repository",
            "Use an active private GitHub repository for protected signing execution.",
        ));
    }
    let environment_info = transport
        .environment(execution_repository, environment)
        .map_err(|error| signing_policy_transport_error(phase, "protected_environment", error))?;
    if environment_info.protected_branches()
        || !environment_info.custom_branch_policies()
        || !environment_info.has_required_reviewers()
    {
        return Err(remote_error(
            "signing_environment_not_ready",
            "the protected signing Environment does not enforce the required reviewer and branch policy",
            "Require at least one deployment reviewer and use only the exact RustFerry temporary-branch policy.",
        ));
    }
    let policies = transport
        .list_deployment_branch_policies(execution_repository, environment)
        .map_err(|error| {
            signing_policy_transport_error(phase, "deployment_branch_policy", error)
        })?;
    let expected_policy = format!("{}/*", stored.temporary_namespace);
    if policies.len() != 1 || policies[0].name() != expected_policy {
        return Err(remote_error(
            "signing_environment_not_ready",
            "the protected signing Environment has an unexpected deployment branch policy",
            "Configure exactly the RustFerry temporary-branch wildcard and remove every other deployment policy.",
        ));
    }
    transport
        .list_environment_secrets(execution_repository, environment)
        .map_err(|error| {
            signing_policy_transport_error(phase, "environment_secret_metadata", error)
        })
        .map(|secrets| {
            secrets
                .into_iter()
                .map(|secret| secret.name().as_str().to_owned())
                .collect()
        })
}

fn signing_policy_transport_error(
    phase: &'static str,
    stage: &'static str,
    error: rustferry_github::transport::TransportError,
) -> CliError {
    remote_error_with_details(
        "github_signing_policy_check_failed",
        "GitHub signing policy verification failed",
        "Correct the exact private-repository and protected-Environment configuration, then retry.",
        vec![
            format!("phase={phase}"),
            format!("stage={stage}"),
            error.to_string(),
        ],
    )
}

fn uploaded_signing_secret_details(uploaded: &[SigningSecretUpload]) -> Vec<String> {
    uploaded
        .iter()
        .flat_map(|upload| {
            [
                format!("uploaded_role={}", upload.role),
                format!("uploaded_secret={}", upload.secret_name),
            ]
        })
        .collect()
}

fn signing_post_upload_error(error: &CliError, uploaded: &[SigningSecretUpload]) -> CliError {
    let mut details = uploaded_signing_secret_details(uploaded);
    details.push(format!("cause_code={}", error.code()));
    details.push(format!("cause={error}"));
    remote_error_with_details(
        "github_signing_post_upload_failed",
        "signing secrets changed remotely but setup could not be committed safely",
        "The local provider config remains unsigned. Delete every listed uploaded secret name from the protected Environment, correct the failure, and retry.",
        details,
    )
}

fn signing_config_commit_uncertain(error: &CliError, uploaded: &[SigningSecretUpload]) -> CliError {
    let mut details = uploaded_signing_secret_details(uploaded);
    details.push("config_state=possibly_signed".to_owned());
    details.push(format!("cause_code={}", error.code()));
    details.push(format!("cause={error}"));
    remote_error_with_details(
        "github_signing_config_commit_uncertain",
        "the signing config was replaced but durability or final verification failed",
        "Do not retry or delete secrets yet. Inspect the private provider config and run GitHub status/doctor; reconcile only the exact listed secret names after confirming whether the signing plan is present.",
        details,
    )
}

fn select_requested_artifacts(
    signing_mode: SigningMode,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
) -> Result<BTreeSet<IosArtifactType>, CliError> {
    if signing_mode == SigningMode::UnsignedCompileOnly {
        if !matches!(artifact, None | Some(BuildArtifactSelection::Archive)) {
            return Err(CliError::Unsupported {
                message: "unsigned physical-iPhone builds can return only an XCArchive".to_owned(),
                help: "Remove `--artifact`, or pass `--artifact archive`.".to_owned(),
            });
        }
        if include_dsym {
            return Err(CliError::Unsupported {
                message: "unsigned physical-iPhone builds cannot return a separate dSYM artifact"
                    .to_owned(),
                help: "Remove `--include-dsym`, or configure protected development signing."
                    .to_owned(),
            });
        }
        return Ok(BTreeSet::from([IosArtifactType::Xcarchive]));
    }

    let mut requested = BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport]);
    match artifact {
        None | Some(BuildArtifactSelection::Ipa) => {}
        Some(BuildArtifactSelection::App) => {
            requested.insert(IosArtifactType::AppBundle);
        }
        Some(BuildArtifactSelection::Archive) => {
            requested.insert(IosArtifactType::Xcarchive);
        }
        Some(BuildArtifactSelection::All) => {
            requested.insert(IosArtifactType::AppBundle);
            requested.insert(IosArtifactType::Xcarchive);
        }
    }
    if include_dsym {
        requested.insert(IosArtifactType::Dsym);
    }
    Ok(requested)
}

enum SnapshotConsentAuthority {
    Cli { yes: bool },
    Ide(super::github_snapshot::DecodedIdeSnapshotConsent),
}

impl SnapshotConsentAuthority {
    const fn is_ide(&self) -> bool {
        matches!(self, Self::Ide(_))
    }

    fn operation_identity(&self) -> Result<(String, u64), CliError> {
        match self {
            Self::Cli { .. } => Ok((operation_id(), unix_timestamp_ms()?)),
            Self::Ide(consent) => Ok((consent.operation_id.clone(), consent.source_created_at_ms)),
        }
    }

    fn validate_context(
        &self,
        profile: BuildProfile,
        source_repository: &str,
    ) -> Result<(), CliError> {
        let Self::Ide(consent) = self else {
            return Ok(());
        };
        if consent.profile != profile
            || !super::github_snapshot::ide_source_repository_matches(consent, source_repository)
        {
            return Err(remote_error(
                "snapshot_consent_context_changed",
                "the IDE snapshot consent no longer matches the exact build profile or source repository",
                "Request and approve a new zero-write snapshot preview for this workspace.",
            ));
        }
        Ok(())
    }

    fn approve(
        &self,
        preview: &super::github_snapshot::GithubSnapshotPreviewV1,
        reporter: &Reporter,
        cancellation: &CancellationToken,
    ) -> Result<(), CliError> {
        match self {
            Self::Cli { yes } => {
                super::github_snapshot::require_snapshot_consent(preview, *yes, reporter)
            }
            Self::Ide(_) => {
                cancellation.check().map_err(|error| {
                    provider_failure(
                        &error,
                        "snapshot_consent_cancelled",
                        "the IDE snapshot submission was cancelled before mutation",
                    )
                })?;
                self.validate_existing_preview(preview)
            }
        }
    }

    fn validate_existing_preview(
        &self,
        preview: &super::github_snapshot::GithubSnapshotPreviewV1,
    ) -> Result<(), CliError> {
        let Self::Ide(consent) = self else {
            return Ok(());
        };
        if consent.operation_id != preview.plan.operation_id
            || consent.source_created_at_ms != preview.plan.source_created_at_ms
            || consent.preview_sha256 != preview.consent_sha256
            || !super::github_snapshot::ide_source_repository_matches(
                consent,
                &preview.plan.source_repository,
            )
        {
            return Err(remote_error(
                "snapshot_consent_changed",
                "the IDE snapshot consent does not authorize this exact operation-bound plan",
                "Request and approve a new zero-write snapshot preview; no source archive was created.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SnapshotBuildCompletion {
    record: StoredJobV1,
    preview_sha256: String,
}

/// Deterministic path-level change summary for an explicit current-source retry preview.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct CurrentSnapshotManifestDiffV1 {
    pub(in crate::commands) added_count: u64,
    pub(in crate::commands) modified_count: u64,
    pub(in crate::commands) removed_count: u64,
    pub(in crate::commands) added_paths: Vec<String>,
    pub(in crate::commands) modified_paths: Vec<String>,
    pub(in crate::commands) removed_paths: Vec<String>,
    pub(in crate::commands) unchanged: u64,
    pub(in crate::commands) project_path_changed: bool,
    pub(in crate::commands) paths_truncated: bool,
}

/// Secret-free zero-write preview for one operation-bound current-source retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct CurrentSnapshotRetryPreviewV1 {
    pub(in crate::commands) parent_job_id: LocalJobId,
    pub(in crate::commands) parent_revision: u64,
    pub(in crate::commands) operation_id: String,
    pub(in crate::commands) source_created_at_ms: u64,
    pub(in crate::commands) snapshot_consent_sha256: String,
    pub(in crate::commands) request_template_sha256: String,
    pub(in crate::commands) source_manifest_sha256: String,
    pub(in crate::commands) file_count: u64,
    pub(in crate::commands) total_bytes: u64,
    pub(in crate::commands) source_repository: String,
    pub(in crate::commands) source_repository_visibility: &'static str,
    pub(in crate::commands) source_ref: String,
    pub(in crate::commands) archive_status: &'static str,
    pub(in crate::commands) archive_size: Option<u64>,
    pub(in crate::commands) archive_sha256: Option<String>,
    pub(in crate::commands) remote_source_ref_retention: &'static str,
    pub(in crate::commands) local_keepalive_retention: &'static str,
    pub(in crate::commands) ref_deletion_erases_objects: bool,
    pub(in crate::commands) secret_scan_residual: &'static str,
    pub(in crate::commands) public_object_warning: &'static str,
    pub(in crate::commands) recovery: CurrentSnapshotRetryRecoveryV1,
    pub(in crate::commands) diff: CurrentSnapshotManifestDiffV1,
    pub(in crate::commands) effects: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands) enum CurrentSnapshotRetryRecoveryV1 {
    #[serde(rename = "new_stage")]
    New,
    #[serde(rename = "orphan_stage")]
    Orphan,
    #[serde(rename = "existing_child_stage")]
    ExistingChild,
}

/// Local-only exact current-source plan retained across explicit retry consent.
pub(in crate::commands) struct PreparedCurrentSnapshotRetry {
    parent: StoredJobV1,
    project: ProjectFilesystemBinding,
    config_path: Utf8PathBuf,
    config_identity: ArtifactFileIdentity,
    config_bytes: Vec<u8>,
    stored: StoredGithubConfig,
    approved_source: SourceBundlePlan,
    approved_path_dependencies: Vec<String>,
    approved: super::github_snapshot::GithubSnapshotPreviewV1,
    request_template: IosDeviceBuildRequest,
    preview: CurrentSnapshotRetryPreviewV1,
    durable_owner: Option<LocalJobId>,
}

/// Explicit-consent typestate; no stage write is reachable from an unconfirmed preview.
pub(in crate::commands) struct ConfirmedCurrentSnapshotRetry {
    prepared: PreparedCurrentSnapshotRetry,
}

/// Continuously held store authority required while writing or adopting a private retry stage.
pub(in crate::commands) enum CurrentSnapshotRetryOperationGuard<'lease> {
    Vacant(&'lease VacantSnapshotOperationLease),
    ExistingChild(&'lease JobOperationLease),
}

#[derive(Debug)]
enum CurrentSnapshotRetryStageAuthority {
    SameInvocation(Box<super::github_snapshot::StagedGithubSnapshotV1>),
    FreshReconsent,
}

/// Complete private stage plus the only specialized provider submission authority it permits.
#[derive(Debug)]
pub(in crate::commands) struct StagedCurrentSnapshotRetry {
    parent_job_id: LocalJobId,
    parent_revision: u64,
    parent_request_sha256: String,
    parent_provider: StoredProviderIdentityV1,
    request: IosDeviceBuildRequest,
    source_created_at_ms: u64,
    snapshot_consent_sha256: String,
    source_archive_sha256: String,
    authority: CurrentSnapshotRetryStageAuthority,
}

fn check_snapshot_cancellation(cancellation: &CancellationToken) -> Result<(), CliError> {
    cancellation.check().map_err(|error| {
        provider_failure(
            &error,
            "snapshot_operation_cancelled",
            "the GitHub snapshot operation was cancelled",
        )
    })
}

/// Capture one current-source retry plan without writing source, stage, provider, or `JobStore`
/// state and without accessing GitHub.
#[expect(
    clippy::too_many_lines,
    reason = "the preview binds the parent, project, provider, source, request, and public effects explicitly"
)]
pub(in crate::commands) fn prepare_current_snapshot_retry(
    parent: &StoredJobV1,
    operation_id: String,
    proposed_source_created_at_ms: u64,
) -> Result<PreparedCurrentSnapshotRetry, CliError> {
    parent.validate()?;
    let source_created_at_ms = proposed_source_created_at_ms
        .max(parent.updated_at_ms)
        .max(1);
    if parent.provider.provider != GITHUB_PROVIDER_ID
        || parent.target != "iphone"
        || operation_id == parent.operation_id
    {
        return Err(remote_error(
            "retry_snapshot_parent_invalid",
            "the selected parent cannot authorize a current-source GitHub snapshot retry",
            "Retry an exact GitHub physical-iPhone job with a new operation identifier.",
        ));
    }
    let root = Utf8Path::new(&parent.project.canonical_root);
    let project = ProjectFilesystemBinding::capture(root)?;
    if project.identity_string() != parent.project.filesystem_identity
        || parent.project.application_identifier != parent.request.bundle_identifier
    {
        return Err(remote_error(
            "retry_project_identity_changed",
            "the retry parent no longer matches the exact local project directory",
            "Restore the original project directory or retry from its current durable child.",
        ));
    }
    let config_path = root.join(CONFIG_RELATIVE_PATH);
    let (config_identity, config_bytes) = read_private_config_snapshot(root, &config_path)?;
    let stored = decode_stored_config(&config_bytes)?;
    validate_stored_config(&stored)?;
    let (_, _, execution_repository) = parse_repository_spec(&stored.repository)?;
    if execution_repository != parent.provider.execution_repository {
        return Err(remote_error(
            "retry_provider_identity_changed",
            "the current GitHub execution repository differs from the durable retry parent",
            "Restore the exact provider configuration before recapturing current source.",
        ));
    }

    let reporter = Reporter::new(false, true, false);
    let (_workspace, approved_source, approved_path_dependencies) =
        snapshot_build_source_bundle_plan(root, &reporter)?;
    project.verify()?;
    let approved = super::github_snapshot::GithubSnapshotPreviewV1::new(
        &operation_id,
        source_created_at_ms,
        &stored.source_repository,
        &approved_source,
        &approved_path_dependencies,
    )?;
    let request_template = current_snapshot_retry_request_template(
        parent,
        &operation_id,
        &stored.source_repository,
        approved_source.manifest().clone(),
    )?;
    let request_template_sha256 = canonical_git_snapshot_request_template_sha256(&request_template)
        .map_err(|error| {
            provider_failure(
                &error,
                "retry_snapshot_request_invalid",
                "the current-source retry request template could not be bound canonically",
            )
        })?;
    ensure_config_snapshot_unchanged(root, &config_path, &config_identity, &config_bytes)?;
    project.verify()?;
    let preview = CurrentSnapshotRetryPreviewV1 {
        parent_job_id: parent.local_job_id.clone(),
        parent_revision: parent.revision,
        operation_id,
        source_created_at_ms,
        snapshot_consent_sha256: approved.consent_sha256.clone(),
        request_template_sha256,
        source_manifest_sha256: approved_source.manifest().sha256.clone(),
        file_count: u64::try_from(approved_source.manifest().entries.len()).map_err(|_| {
            remote_error(
                "snapshot_plan_bound_exceeded",
                "the current-source retry contains too many source entries",
                "Reduce the source set before approving this retry.",
            )
        })?,
        total_bytes: approved_source.manifest().total_size,
        source_repository: approved.plan.source_repository.clone(),
        source_repository_visibility: approved.plan.source_repository_visibility,
        source_ref: approved.plan.source_ref.clone(),
        archive_status: approved.plan.archive.status,
        archive_size: approved.plan.archive.size,
        archive_sha256: approved.plan.archive.sha256.clone(),
        remote_source_ref_retention: approved.plan.remote_source_ref_retention,
        local_keepalive_retention: approved.plan.local_keepalive_retention,
        ref_deletion_erases_objects: approved.plan.ref_deletion_erases_objects,
        secret_scan_residual: approved.plan.secret_scan_residual,
        public_object_warning: approved.plan.public_object_warning,
        recovery: CurrentSnapshotRetryRecoveryV1::New,
        diff: current_snapshot_manifest_diff(&parent.request.source, approved_source.manifest())?,
        effects: vec![
            "upload_current_source_snapshot_to_public_github_object_database".to_owned(),
            "create_custom_source_ref_until_terminal_cleanup".to_owned(),
            "retain_local_keepalive_until_explicit_complete_lineage_prune".to_owned(),
            "create_one_atomic_retry_child_before_provider_submission".to_owned(),
        ],
    };
    Ok(PreparedCurrentSnapshotRetry {
        parent: parent.clone(),
        project,
        config_path,
        config_identity,
        config_bytes,
        stored,
        approved_source,
        approved_path_dependencies,
        approved,
        request_template,
        preview,
        durable_owner: None,
    })
}

/// Select one exact durable-child or orphan private stage before allocating a fresh retry
/// operation. This entrypoint reads the `JobStore` and private stage directory but performs no
/// mutation or GitHub request.
pub(in crate::commands) fn prepare_current_snapshot_retry_in_store(
    store: &JobStore,
    parent: &StoredJobV1,
    fresh_operation_id: String,
    fresh_source_created_at_ms: u64,
    cancellation: &CancellationToken,
) -> Result<PreparedCurrentSnapshotRetry, CliError> {
    let fresh =
        prepare_current_snapshot_retry(parent, fresh_operation_id, fresh_source_created_at_ms)?;
    check_snapshot_cancellation(cancellation)?;
    let provider = build_provider(fresh.project.root(), fresh.project.root(), &fresh.stored)?;
    let mut selected = None;
    for candidate in provider
        .discover_uncheckpointed_git_snapshot_stages()
        .map_err(|error| {
            provider_failure(
                &error,
                "snapshot_recovery_discovery_failed",
                "private current-source retry stages could not be inspected safely",
            )
        })?
    {
        let Some(candidate_preview) = current_snapshot_candidate_preview(&fresh, &candidate)?
        else {
            continue;
        };
        let owner = store.snapshot_operation_owner(&candidate.final_request.operation_id)?;
        let durable_owner = if let Some(owner) = owner {
            validate_current_snapshot_retry_owner(parent, &owner.record, &candidate)?;
            Some(owner.local_job_id)
        } else {
            None
        };
        if selected
            .replace((
                candidate.final_request.operation_id.clone(),
                candidate.stage.source_created_at_ms,
                candidate_preview.consent_sha256,
                durable_owner,
            ))
            .is_some()
        {
            return Err(remote_error(
                "snapshot_recovery_ambiguous",
                "more than one complete private stage matches the current-source retry",
                "Preserve the stages and resolve their exact JobStore ownership before retrying.",
            ));
        }
    }
    ensure_config_snapshot_unchanged(
        fresh.project.root(),
        &fresh.config_path,
        &fresh.config_identity,
        &fresh.config_bytes,
    )?;
    fresh.project.verify()?;
    check_snapshot_cancellation(cancellation)?;
    let Some((operation_id, source_created_at_ms, expected_consent_sha256, durable_owner)) =
        selected
    else {
        return Ok(fresh);
    };
    let mut recovered = prepare_current_snapshot_retry(parent, operation_id, source_created_at_ms)?;
    if recovered.preview.snapshot_consent_sha256 != expected_consent_sha256 {
        return Err(remote_error(
            "snapshot_recovery_plan_changed",
            "the recovered private retry stage changed while its exact preview was reconstructed",
            "Preserve the stage and request a new current-source retry preview.",
        ));
    }
    recovered.durable_owner = durable_owner;
    recovered.preview.recovery = if recovered.durable_owner.is_some() {
        CurrentSnapshotRetryRecoveryV1::ExistingChild
    } else {
        CurrentSnapshotRetryRecoveryV1::Orphan
    };
    Ok(recovered)
}

impl PreparedCurrentSnapshotRetry {
    pub(in crate::commands) const fn preview(&self) -> &CurrentSnapshotRetryPreviewV1 {
        &self.preview
    }

    pub(in crate::commands) fn confirm(
        self,
        yes: bool,
        reporter: &Reporter,
    ) -> Result<ConfirmedCurrentSnapshotRetry, CliError> {
        super::github_snapshot::require_snapshot_consent(&self.approved, yes, reporter)?;
        Ok(ConfirmedCurrentSnapshotRetry { prepared: self })
    }
}

impl ConfirmedCurrentSnapshotRetry {
    pub(in crate::commands) fn operation_id(&self) -> &str {
        &self.prepared.preview.operation_id
    }

    pub(in crate::commands) fn parent_job_id(&self) -> &LocalJobId {
        &self.prepared.parent.local_job_id
    }

    pub(in crate::commands) const fn parent_revision(&self) -> u64 {
        self.prepared.parent.revision
    }

    /// Replan after exact consent, then create or classify one complete private stage.
    #[expect(
        clippy::too_many_lines,
        reason = "staging keeps consent, operation authority, config identity, source replan, and stage adoption in one ordered boundary"
    )]
    pub(in crate::commands) fn stage(
        self,
        parent_retry_lease: &JobOperationLease,
        operation_guard: CurrentSnapshotRetryOperationGuard<'_>,
        cancellation: &CancellationToken,
    ) -> Result<StagedCurrentSnapshotRetry, CliError> {
        let self_ = self.prepared;
        check_snapshot_cancellation(cancellation)?;
        validate_current_snapshot_operation_guard(&self_, parent_retry_lease, operation_guard)?;
        self_.project.verify()?;
        let reporter = Reporter::new(false, true, false);
        let (_workspace, current_source, current_path_dependencies) =
            snapshot_build_source_bundle_plan(self_.project.root(), &reporter)?;
        check_snapshot_cancellation(cancellation)?;
        let revalidated = super::github_snapshot::GithubSnapshotPreviewV1::new(
            &self_.preview.operation_id,
            self_.preview.source_created_at_ms,
            &self_.stored.source_repository,
            &current_source,
            &current_path_dependencies,
        )?;
        super::github_snapshot::ensure_same_snapshot_plan(&self_.approved, &revalidated)?;
        if current_source != self_.approved_source
            || current_path_dependencies != self_.approved_path_dependencies
        {
            return Err(remote_error(
                "snapshot_plan_changed",
                "the current-source retry inputs changed after consent",
                "Review a new zero-write retry preview before creating a private stage.",
            ));
        }
        ensure_config_snapshot_unchanged(
            self_.project.root(),
            &self_.config_path,
            &self_.config_identity,
            &self_.config_bytes,
        )?;
        self_.project.verify()?;
        let current_template = current_snapshot_retry_request_template(
            &self_.parent,
            &self_.preview.operation_id,
            &self_.stored.source_repository,
            current_source.manifest().clone(),
        )?;
        if current_template != self_.request_template {
            return Err(remote_error(
                "snapshot_request_changed",
                "the current-source retry request changed after consent",
                "Review a new retry preview before creating or adopting a private stage.",
            ));
        }
        let provider = build_provider(self_.project.root(), self_.project.root(), &self_.stored)?;
        let existing =
            exact_current_snapshot_stage(&provider, &current_template, &revalidated, cancellation)?;
        let recovery_matches = matches!(
            (self_.preview.recovery, existing.is_some()),
            (CurrentSnapshotRetryRecoveryV1::New, false)
                | (
                    CurrentSnapshotRetryRecoveryV1::Orphan
                        | CurrentSnapshotRetryRecoveryV1::ExistingChild,
                    true
                )
        );
        if !recovery_matches {
            return Err(remote_error(
                "snapshot_recovery_changed",
                "the private current-source retry stage changed after its zero-write preview",
                "Preserve the operation and review a new exact retry preview before staging.",
            ));
        }
        let (request, source_archive_sha256, authority) = if let Some(candidate) = existing {
            (
                candidate.final_request,
                candidate.stage.archive.sha256,
                CurrentSnapshotRetryStageAuthority::FreshReconsent,
            )
        } else {
            let staged = super::github_snapshot::stage_same_invocation_snapshot(
                &GithubPaths::new(self_.project.root(), self_.project.root()).git_isolation,
                &current_source,
                current_template,
                self_.preview.source_created_at_ms,
                &revalidated.consent_sha256,
                |inputs, operation_id, created_at_ms| {
                    provider
                        .precompute_git_snapshot_graph(
                            inputs,
                            operation_id,
                            created_at_ms,
                            cancellation,
                        )
                        .map_err(|error| {
                            provider_failure(
                                &error,
                                "snapshot_graph_precompute_failed",
                                "the current-source retry object graph could not be verified without mutation",
                            )
                        })
                },
            )?;
            let archive_sha256 = staged.stage.archive.sha256.clone();
            let request = staged.request.clone();
            (
                request,
                archive_sha256,
                CurrentSnapshotRetryStageAuthority::SameInvocation(Box::new(staged)),
            )
        };
        ensure_config_snapshot_unchanged(
            self_.project.root(),
            &self_.config_path,
            &self_.config_identity,
            &self_.config_bytes,
        )?;
        self_.project.verify()?;
        Ok(StagedCurrentSnapshotRetry {
            parent_job_id: self_.parent.local_job_id,
            parent_revision: self_.parent.revision,
            parent_request_sha256: self_.parent.request_sha256,
            parent_provider: self_.parent.provider,
            request,
            source_created_at_ms: self_.preview.source_created_at_ms,
            snapshot_consent_sha256: revalidated.consent_sha256,
            source_archive_sha256,
            authority,
        })
    }
}

impl StagedCurrentSnapshotRetry {
    pub(in crate::commands) const fn request(&self) -> &IosDeviceBuildRequest {
        &self.request
    }

    pub(in crate::commands) const fn source_created_at_ms(&self) -> u64 {
        self.source_created_at_ms
    }

    pub(in crate::commands) fn retry_lineage_options(
        &self,
        parent_policy: RetryParentPolicyV1,
        parent_before_lineage: &StoredJobV1,
        child_initial: &StoredJobV1,
    ) -> Result<RetryLineageOptionsV1, CliError> {
        if parent_before_lineage.local_job_id != self.parent_job_id
            || parent_before_lineage.revision != self.parent_revision
            || parent_before_lineage.request_sha256 != self.parent_request_sha256
            || child_initial.revision != 1
            || child_initial.provider_resume.is_some()
            || child_initial.provider != self.parent_provider
            || child_initial.request != self.request
            || child_initial.created_at_ms != self.source_created_at_ms
        {
            return Err(remote_error(
                "retry_snapshot_child_mismatch",
                "the proposed current-source retry child differs from its consented private stage",
                "Preserve the stage and rebuild the exact initial child before publishing lineage.",
            ));
        }
        let confirmation_sha256 =
            retry_recapture_confirmation_sha256(parent_before_lineage, child_initial)?;
        Ok(RetryLineageOptionsV1 {
            parent_policy,
            source_policy: RetrySourcePolicyV1::RecapturedGitSnapshot {
                confirmation_sha256,
                snapshot_consent_sha256: self.snapshot_consent_sha256.clone(),
                source_archive_sha256: self.source_archive_sha256.clone(),
            },
        })
    }

    /// Convert only after the caller has durably published the exact child lineage and retained
    /// its Build lease. No generic `BuildProvider::submit` authority is exposed.
    pub(in crate::commands) fn into_provider_submission(
        self,
        parent_before_lineage: &StoredJobV1,
        child_initial: &StoredJobV1,
        binding: &RetryLineageBindingV1,
        durable_identity: GithubDurableIdentityV1,
    ) -> Result<GithubGitSnapshotSubmissionV1, CliError> {
        if StoredProviderIdentityV1::from(durable_identity.clone()) != self.parent_provider {
            return Err(remote_error(
                "retry_provider_identity_changed",
                "the live GitHub provider identity differs from the current-source retry parent",
                "Preserve the private stage and restore the exact provider identity before retrying.",
            ));
        }
        let confirmation_sha256 =
            retry_recapture_confirmation_sha256(parent_before_lineage, child_initial)?;
        let durable_binding_matches = child_initial.revision == 1
            && parent_before_lineage.local_job_id == self.parent_job_id
            && parent_before_lineage.revision == self.parent_revision
            && parent_before_lineage.request_sha256 == self.parent_request_sha256
            && child_initial.provider_resume.is_none()
            && child_initial.provider == self.parent_provider
            && child_initial.created_at_ms == self.source_created_at_ms
            && child_initial.request == self.request
            && child_initial.operation_id == self.request.operation_id
            && binding.child_job_id == child_initial.local_job_id
            && binding.child_operation_id == child_initial.operation_id
            && binding.parent_before_revision == parent_before_lineage.revision
            && matches!(
                &binding.options.source_policy,
                RetrySourcePolicyV1::RecapturedGitSnapshot {
                    confirmation_sha256: stored_confirmation,
                    snapshot_consent_sha256,
                    source_archive_sha256,
                } if stored_confirmation == &confirmation_sha256
                    && snapshot_consent_sha256 == &self.snapshot_consent_sha256
                    && source_archive_sha256 == &self.source_archive_sha256
            );
        if !durable_binding_matches {
            return Err(remote_error(
                "retry_snapshot_lineage_mismatch",
                "the durable retry lineage differs from the freshly consented private stage",
                "Preserve the child and stage; reconcile their exact immutable binding before submission.",
            ));
        }
        match self.authority {
            CurrentSnapshotRetryStageAuthority::SameInvocation(staged) => {
                let staged = *staged;
                GithubGitSnapshotSubmissionV1::same_invocation(
                    durable_identity,
                    staged.request,
                    self.snapshot_consent_sha256,
                    staged.locator,
                    staged.stage,
                )
            }
            CurrentSnapshotRetryStageAuthority::FreshReconsent => {
                GithubGitSnapshotSubmissionV1::after_fresh_reconsent(
                    durable_identity,
                    self.request,
                    self.snapshot_consent_sha256,
                )
            }
        }
        .map_err(|error| {
            provider_failure(
                &error,
                "snapshot_submission_invalid",
                "the current-source retry stage could not form specialized snapshot submission authority",
            )
        })
    }
}

fn validate_current_snapshot_operation_guard(
    prepared: &PreparedCurrentSnapshotRetry,
    parent_retry_lease: &JobOperationLease,
    guard: CurrentSnapshotRetryOperationGuard<'_>,
) -> Result<(), CliError> {
    let parent_valid = parent_retry_lease.kind() == JobOperationKind::Retry
        && parent_retry_lease.local_job_id() == &prepared.parent.local_job_id;
    let operation_valid = match (prepared.durable_owner.as_ref(), guard) {
        (None, CurrentSnapshotRetryOperationGuard::Vacant(vacancy)) => {
            vacancy.operation_id() == prepared.preview.operation_id
        }
        (Some(owner), CurrentSnapshotRetryOperationGuard::ExistingChild(lease)) => {
            lease.kind() == JobOperationKind::Build && lease.local_job_id() == owner
        }
        _ => false,
    };
    if parent_valid && operation_valid {
        return Ok(());
    }
    Err(remote_error(
        "snapshot_retry_operation_guard_mismatch",
        "the current-source retry stage lacks its exact continuous JobStore operation authority",
        "Hold the matching vacant operation reservation or existing child Build lease through staging and durable lineage.",
    ))
}

fn current_snapshot_retry_request_template(
    parent: &StoredJobV1,
    operation_id: &str,
    source_repository: &str,
    source: SourceManifest,
) -> Result<IosDeviceBuildRequest, CliError> {
    let mut request = parent.request.clone();
    operation_id.clone_into(&mut request.operation_id);
    request.source_mode = SourceMode::GitSnapshot;
    request.source_repository = Some(source_repository.to_owned());
    request.source_revision = None;
    request.source = source;
    canonical_git_snapshot_request_template_sha256(&request).map_err(|error| {
        provider_failure(
            &error,
            "retry_snapshot_request_invalid",
            "the current-source retry request template is invalid",
        )
    })?;
    Ok(request)
}

fn current_snapshot_manifest_diff(
    previous: &SourceManifest,
    current: &SourceManifest,
) -> Result<CurrentSnapshotManifestDiffV1, CliError> {
    let previous_entries = previous
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let current_entries = current
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    if previous_entries.len() != previous.entries.len()
        || current_entries.len() != current.entries.len()
    {
        return Err(remote_error(
            "snapshot_manifest_invalid",
            "a retry source manifest contains duplicate paths",
            "Preserve the durable parent and rebuild a canonical current-source preview.",
        ));
    }
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = 0_u64;
    for (path, entry) in &current_entries {
        match previous_entries.get(path) {
            None => added.push((*path).to_owned()),
            Some(previous_entry) if *previous_entry == *entry => {
                unchanged = unchanged.checked_add(1).ok_or_else(|| {
                    remote_error(
                        "snapshot_plan_bound_exceeded",
                        "the retry source diff exceeds its supported count",
                        "Reduce the source set before retrying.",
                    )
                })?;
            }
            Some(_) => modified.push((*path).to_owned()),
        }
    }
    for path in previous_entries.keys() {
        if !current_entries.contains_key(path) {
            removed.push((*path).to_owned());
        }
    }
    let added_count = u64::try_from(added.len()).map_err(|_| snapshot_diff_bound_error())?;
    let modified_count = u64::try_from(modified.len()).map_err(|_| snapshot_diff_bound_error())?;
    let removed_count = u64::try_from(removed.len()).map_err(|_| snapshot_diff_bound_error())?;
    let total_changed = added
        .len()
        .checked_add(modified.len())
        .and_then(|count| count.checked_add(removed.len()))
        .ok_or_else(snapshot_diff_bound_error)?;
    let mut changed_paths = added
        .into_iter()
        .map(|path| (path, 0_u8))
        .chain(modified.into_iter().map(|path| (path, 1_u8)))
        .chain(removed.into_iter().map(|path| (path, 2_u8)))
        .collect::<Vec<_>>();
    changed_paths.sort_by(|left, right| left.0.cmp(&right.0));
    let mut retained_path_bytes = 0_usize;
    let mut retained_count = 0_usize;
    for (path, _) in &changed_paths {
        let Some(next_bytes) = retained_path_bytes.checked_add(path.len()) else {
            break;
        };
        if retained_count == MAX_CURRENT_SNAPSHOT_DIFF_PATHS
            || next_bytes > MAX_CURRENT_SNAPSHOT_DIFF_PATH_BYTES
        {
            break;
        }
        retained_path_bytes = next_bytes;
        retained_count += 1;
    }
    changed_paths.truncate(retained_count);
    let mut added_paths = Vec::new();
    let mut modified_paths = Vec::new();
    let mut removed_paths = Vec::new();
    for (path, kind) in changed_paths {
        match kind {
            0 => added_paths.push(path),
            1 => modified_paths.push(path),
            2 => removed_paths.push(path),
            _ => unreachable!("bounded diff uses fixed internal categories"),
        }
    }
    Ok(CurrentSnapshotManifestDiffV1 {
        added_count,
        modified_count,
        removed_count,
        added_paths,
        modified_paths,
        removed_paths,
        unchanged,
        project_path_changed: previous.project_path != current.project_path,
        paths_truncated: retained_count < total_changed,
    })
}

fn snapshot_diff_bound_error() -> CliError {
    remote_error(
        "snapshot_plan_bound_exceeded",
        "the retry source diff exceeds its supported count",
        "Reduce the source set before retrying.",
    )
}

fn exact_current_snapshot_stage(
    provider: &GithubProvider,
    request_template: &IosDeviceBuildRequest,
    preview: &super::github_snapshot::GithubSnapshotPreviewV1,
    cancellation: &CancellationToken,
) -> Result<Option<GithubGitSnapshotRecoveryCandidateV1>, CliError> {
    check_snapshot_cancellation(cancellation)?;
    let mut matching = None;
    for candidate in provider
        .discover_uncheckpointed_git_snapshot_stages()
        .map_err(|error| {
            provider_failure(
                &error,
                "snapshot_recovery_discovery_failed",
                "private current-source retry stages could not be inspected safely",
            )
        })?
    {
        if candidate.final_request.operation_id != request_template.operation_id {
            continue;
        }
        if matching.is_some() {
            return Err(remote_error(
                "snapshot_recovery_ambiguous",
                "more than one complete private stage claims the current retry operation",
                "Preserve the stages and inspect their exact operation identities before retrying.",
            ));
        }
        let mut expected = request_template.clone();
        expected.source_revision = Some(candidate.stage.graph.commit.as_str().to_owned());
        if candidate.final_request != expected
            || candidate.stage.final_request != expected
            || candidate.stage.source_created_at_ms != preview.plan.source_created_at_ms
            || candidate.stage.consent_sha256 != preview.consent_sha256
            || candidate.stage.manifest_sha256 != preview.plan.source.sha256
        {
            return Err(remote_error(
                "snapshot_recovery_plan_changed",
                "the existing private retry stage differs from the freshly consented source plan",
                "Preserve the stage and create a new operation-bound retry preview.",
            ));
        }
        matching = Some(candidate);
    }
    check_snapshot_cancellation(cancellation)?;
    Ok(matching)
}

fn current_snapshot_candidate_preview(
    prepared: &PreparedCurrentSnapshotRetry,
    candidate: &GithubGitSnapshotRecoveryCandidateV1,
) -> Result<Option<super::github_snapshot::GithubSnapshotPreviewV1>, CliError> {
    if candidate.final_request.operation_id == prepared.parent.operation_id {
        return Ok(None);
    }
    let template = current_snapshot_retry_request_template(
        &prepared.parent,
        &candidate.final_request.operation_id,
        &prepared.stored.source_repository,
        prepared.approved_source.manifest().clone(),
    )?;
    let mut expected = template;
    expected.source_revision = Some(candidate.stage.graph.commit.as_str().to_owned());
    if expected != candidate.final_request || expected != candidate.stage.final_request {
        return Ok(None);
    }
    let preview = super::github_snapshot::GithubSnapshotPreviewV1::new(
        &candidate.final_request.operation_id,
        candidate.stage.source_created_at_ms,
        &prepared.stored.source_repository,
        &prepared.approved_source,
        &prepared.approved_path_dependencies,
    )?;
    if preview.consent_sha256 != candidate.stage.consent_sha256
        || preview.plan.source.sha256 != candidate.stage.manifest_sha256
    {
        return Ok(None);
    }
    Ok(Some(preview))
}

fn validate_current_snapshot_retry_owner(
    parent: &StoredJobV1,
    owner: &StoredJobV1,
    candidate: &GithubGitSnapshotRecoveryCandidateV1,
) -> Result<(), CliError> {
    let exact_child = owner.retry_lineage.parent_job_id.as_ref() == Some(&parent.local_job_id)
        && parent
            .retry_lineage
            .child_job_ids
            .contains(&owner.local_job_id)
        && owner.operation_id == candidate.final_request.operation_id
        && owner.request == candidate.final_request
        && owner.project == parent.project
        && owner.provider == parent.provider;
    if !exact_child {
        return Err(remote_error(
            "snapshot_recovery_foreign_owner",
            "a matching private retry stage belongs to a different durable operation",
            "Preserve both the stage and JobStore owner; do not adopt or overwrite them.",
        ));
    }
    if owner.provider_resume.is_some() {
        return Err(remote_error(
            "snapshot_retry_restore_required",
            "the durable current-source retry child already has a provider checkpoint",
            "Restore and reconcile the exact child; never adopt or resubmit its private stage.",
        ));
    }
    if owner.terminal_outcome.is_some()
        || owner.failure.is_some()
        || !matches!(
            owner.state,
            StoredJobState::SourceReady | StoredJobState::Submitting
        )
    {
        return Err(remote_error(
            "snapshot_retry_child_settled",
            "the private retry stage belongs to a durable child that cannot be newly submitted",
            "Inspect the exact child and preserve its stage for reconciliation.",
        ));
    }
    Ok(())
}

pub(in crate::commands) fn ide_snapshot_preview(
    project_binding: &ProjectFilesystemBinding,
    ferry_config: &rustferry_core::FerryConfig,
    binary_name: &str,
    profile: BuildProfile,
) -> Result<super::github_snapshot::IdeSnapshotPreview, CliError> {
    project_binding.verify()?;
    let root = project_binding.root();
    let config_path = root.join(CONFIG_RELATIVE_PATH);
    let (config_identity, config_bytes) = read_private_config_snapshot(root, &config_path)?;
    let stored = decode_stored_config(&config_bytes)?;
    validate_stored_config(&stored)?;
    let signing = select_signing_plan(&stored, ferry_config, binary_name, None, true)?;
    if signing.mode != SigningMode::UnsignedCompileOnly {
        return Err(remote_error(
            "snapshot_unsigned_required",
            "the IDE GitHub snapshot preview is not unsigned compile-only",
            "Use the unsigned snapshot build mode and remove every signing option.",
        ));
    }
    let reporter = Reporter::new(false, true, false);
    let (_workspace, source, path_dependencies) =
        snapshot_build_source_bundle_plan(root, &reporter)?;
    let operation_id = operation_id();
    let source_created_at_ms = unix_timestamp_ms()?;
    let preview = super::github_snapshot::GithubSnapshotPreviewV1::new(
        &operation_id,
        source_created_at_ms,
        &stored.source_repository,
        &source,
        &path_dependencies,
    )?;
    let request = snapshot_request_template(
        ferry_config,
        binary_name,
        profile == BuildProfile::Release,
        &operation_id,
        &stored.source_repository,
        source.manifest().clone(),
        signing,
        BTreeSet::from([IosArtifactType::Xcarchive]),
    )?;
    canonical_git_snapshot_request_template_sha256(&request).map_err(|error| {
        remote_error_with_details(
            "invalid_snapshot_build_request",
            "the IDE snapshot preview could not form a valid unsigned iPhone build request",
            "Correct the project configuration before requesting snapshot consent.",
            vec![error.to_string()],
        )
    })?;
    ensure_config_snapshot_unchanged(root, &config_path, &config_identity, &config_bytes)?;
    project_binding.verify()?;
    super::github_snapshot::ide_snapshot_preview(
        root,
        &project_binding.identity_string(),
        profile,
        &preview,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the typed IDE boundary binds the exact project, target, consent, and cancellation inputs"
)]
pub(in crate::commands) fn ide_snapshot_submit(
    project_binding: &ProjectFilesystemBinding,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    consent_token: &str,
    preview_sha256: &str,
    approved: bool,
    cancellation: &CancellationToken,
) -> Result<(StoredJobV1, String), CliError> {
    if !approved {
        return Err(remote_error(
            "snapshot_consent_required",
            "the IDE snapshot submission was not explicitly approved",
            "Approve the exact current preview and resubmit its unchanged token and SHA-256.",
        ));
    }
    check_snapshot_cancellation(cancellation)?;
    project_binding.verify()?;
    let consent = super::github_snapshot::decode_ide_snapshot_consent(
        project_binding.root(),
        &project_binding.identity_string(),
        consent_token,
        preview_sha256,
    )?;
    let profile = consent.profile;
    let completion = build_iphone_github_snapshot(
        project_binding,
        ferry_config,
        package_name,
        binary_name,
        None,
        profile == BuildProfile::Release,
        true,
        &SnapshotConsentAuthority::Ide(consent),
        Some(BuildArtifactSelection::Archive),
        false,
        false,
        cancellation,
        &Reporter::new(false, true, false),
    )?
    .ok_or_else(|| {
        remote_error(
            "snapshot_submission_missing",
            "the approved IDE snapshot submission returned no durable job receipt",
            "Request a new preview only after inspecting the JobStore for the exact operation.",
        )
    })?;
    Ok((completion.record, completion.preview_sha256))
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the snapshot route preserves the public build command's validated option boundary"
)]
fn build_iphone_github_snapshot(
    project_binding: &ProjectFilesystemBinding,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    expected_team: Option<&str>,
    release: bool,
    unsigned: bool,
    consent: &SnapshotConsentAuthority,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
    dry_run: bool,
    cancellation: &CancellationToken,
    reporter: &Reporter,
) -> Result<Option<SnapshotBuildCompletion>, CliError> {
    check_snapshot_cancellation(cancellation)?;
    if !unsigned || expected_team.is_some() {
        return Err(remote_error(
            "snapshot_unsigned_required",
            "GitHub snapshot builds are unsigned compile-only builds",
            "Pass --unsigned and remove --team before approving a public source snapshot.",
        ));
    }
    let root = project_binding.root();
    let requested_artifacts =
        select_requested_artifacts(SigningMode::UnsignedCompileOnly, artifact, include_dsym)?;
    let config_path = root.join(CONFIG_RELATIVE_PATH);
    let (approved_config_identity, approved_config_bytes) =
        read_private_config_snapshot(root, &config_path)?;
    let stored = decode_stored_config(&approved_config_bytes)?;
    validate_stored_config(&stored)?;
    let signing = select_signing_plan(&stored, ferry_config, binary_name, None, true)?;
    if signing.mode != SigningMode::UnsignedCompileOnly {
        return Err(remote_error(
            "snapshot_unsigned_required",
            "the GitHub snapshot signing plan is not unsigned compile-only",
            "Pass --unsigned and remove every signing option.",
        ));
    }
    let expected_downloads = expected_artifact_downloads(
        root,
        &ferry_config.app.name,
        release,
        signing.mode,
        &requested_artifacts,
    )?;
    project_binding.verify()?;

    let profile = if release {
        BuildProfile::Release
    } else {
        BuildProfile::Debug
    };
    consent.validate_context(profile, &stored.source_repository)?;
    let (operation_id, source_created_at_ms) = consent.operation_identity()?;
    let (_workspace, approved_source, path_dependencies) =
        snapshot_build_source_bundle_plan(root, reporter)?;
    check_snapshot_cancellation(cancellation)?;
    project_binding.verify()?;
    let approved = super::github_snapshot::GithubSnapshotPreviewV1::new(
        &operation_id,
        source_created_at_ms,
        &stored.source_repository,
        &approved_source,
        &path_dependencies,
    )?;
    if dry_run {
        ensure_config_snapshot_unchanged(
            root,
            &config_path,
            &approved_config_identity,
            &approved_config_bytes,
        )?;
        project_binding.verify()?;
        super::github_snapshot::report_snapshot_preview(&approved, reporter);
        return Ok(None);
    }

    consent.approve(&approved, reporter, cancellation)?;
    project_binding.verify()?;
    let (_workspace, current_source, current_path_dependencies) =
        snapshot_build_source_bundle_plan(root, reporter)?;
    check_snapshot_cancellation(cancellation)?;
    let revalidated = super::github_snapshot::GithubSnapshotPreviewV1::new(
        &operation_id,
        source_created_at_ms,
        &stored.source_repository,
        &current_source,
        &current_path_dependencies,
    )?;
    super::github_snapshot::ensure_same_snapshot_plan(&approved, &revalidated)?;
    ensure_config_snapshot_unchanged(
        root,
        &config_path,
        &approved_config_identity,
        &approved_config_bytes,
    )?;
    project_binding.verify()?;

    let current_template = snapshot_request_template(
        ferry_config,
        binary_name,
        release,
        &operation_id,
        &stored.source_repository,
        current_source.manifest().clone(),
        signing.clone(),
        requested_artifacts.clone(),
    )?;
    let mut preacquired_snapshot_vacancy = None;
    let preopened_job_store = if consent.is_ide() {
        let store = JobStore::open_default()?;
        match store.try_acquire_vacant_snapshot_operation_lease(&operation_id)? {
            SnapshotOperationVacancyV1::Vacant(vacancy) => {
                preacquired_snapshot_vacancy = Some(vacancy);
            }
            SnapshotOperationVacancyV1::Owned(owner) => {
                validate_ide_snapshot_owner(&owner.record, project_binding, &current_template)?;
                if snapshot_job_is_fully_settled(&owner.record) {
                    if owner.record.state == StoredJobState::Succeeded
                        && owner.record.terminal_outcome == Some(StoredBuildOutcome::Succeeded)
                    {
                        return Ok(Some(SnapshotBuildCompletion {
                            record: owner.record,
                            preview_sha256: revalidated.consent_sha256,
                        }));
                    }
                    return Err(remote_error_with_details(
                        "snapshot_operation_already_settled",
                        "the approved IDE snapshot operation already has a terminal durable owner",
                        "Inspect the exact existing job; request a new preview only for a new intentional build.",
                        vec![format!("local_job_id={}", owner.local_job_id.as_str())],
                    ));
                }
            }
        }
        Some(store)
    } else {
        None
    };

    let (locked_stored, config_lock) = load_config_for_build(root)?;
    if locked_stored != stored {
        return Err(provider_config_changed());
    }
    ensure_config_snapshot_unchanged(
        root,
        &config_path,
        &approved_config_identity,
        &approved_config_bytes,
    )?;
    let mut config_lock = Some(config_lock);
    let artifact_path = expected_downloads[0].path.clone();
    let provider = build_provider(root, root, &stored)?;
    handshake_with_source_mode_cancellable(
        &provider,
        SourceMode::GitSnapshot,
        signing.mode,
        &requested_artifacts,
        cancellation,
    )?;
    let readiness = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: format!("{operation_id}-doctor"),
                require_signing: false,
            },
            cancellation.clone(),
        ),
        "provider_doctor_failed",
        "the GitHub provider doctor could not complete",
    )?;
    ensure_doctor_ready(&readiness, false)?;
    let durable_provider_identity = provider.durable_identity().map_err(|error| {
        provider_failure(
            &error,
            "provider_identity_unavailable",
            "the GitHub provider identity could not be bound durably",
        )
    })?;
    project_binding.verify()?;

    let job_store = preopened_job_store.map_or_else(JobStore::open_default, Ok)?;
    let current_provider = StoredProviderIdentityV1::from(durable_provider_identity.clone());
    let resumable = find_resumable_snapshot_job(
        &job_store,
        project_binding,
        &current_provider,
        &current_template,
    )?;
    let mut recovery = None;
    if resumable.is_none() {
        for candidate in provider
            .discover_uncheckpointed_git_snapshot_stages()
            .map_err(|error| {
                provider_failure(
                    &error,
                    "snapshot_recovery_discovery_failed",
                    "complete private Git snapshot stages could not be inspected safely",
                )
            })?
        {
            let expected = snapshot_request_for_candidate(&current_template, &candidate);
            if expected != candidate.final_request {
                continue;
            }
            let candidate_preview = super::github_snapshot::GithubSnapshotPreviewV1::new(
                &candidate.final_request.operation_id,
                candidate.stage.source_created_at_ms,
                &stored.source_repository,
                &current_source,
                &current_path_dependencies,
            )?;
            if candidate_preview.consent_sha256 != candidate.stage.consent_sha256 {
                continue;
            }
            consent.validate_existing_preview(&candidate_preview)?;
            let owner =
                job_store.snapshot_operation_owner(&candidate.final_request.operation_id)?;
            if recovery
                .replace((candidate, candidate_preview, owner))
                .is_some()
            {
                return Err(remote_error(
                    "snapshot_recovery_ambiguous",
                    "more than one complete snapshot stage matches the current build",
                    "Inspect the private snapshot stages and their durable JobStore ownership before retrying.",
                ));
            }
        }
    }

    let execution_plan = if let Some(record) = resumable {
        let operation_lease =
            job_store.try_acquire_operation_lease(&record.local_job_id, JobOperationKind::Build)?;
        let record = job_store.latest_under_operation_lease(
            &record.local_job_id,
            JobOperationKind::Build,
            &operation_lease,
        )?;
        validate_resumable_snapshot_job(
            &record,
            project_binding,
            &current_provider,
            &current_template,
        )?;
        let snapshot = record
            .provider_resume
            .as_ref()
            .and_then(|resume| resume.git_snapshot.as_ref())
            .expect("validated resumable snapshot carries its exact snapshot checkpoint");
        let resume_preview = super::github_snapshot::GithubSnapshotPreviewV1::new(
            &record.operation_id,
            snapshot.stage.source_created_at_ms,
            &stored.source_repository,
            &current_source,
            &current_path_dependencies,
        )?;
        if resume_preview.consent_sha256 != snapshot.stage.consent_sha256 {
            return Err(remote_error(
                "snapshot_resume_consent_mismatch",
                "the durable snapshot resume no longer matches the exact current consent plan",
                "Preserve and inspect the durable job; do not create a replacement operation.",
            ));
        }
        consent.validate_existing_preview(&resume_preview)?;
        SnapshotExecutionPlan {
            request: record.request.clone(),
            consent_sha256: snapshot.stage.consent_sha256.clone(),
            source_created_at_ms: snapshot.stage.source_created_at_ms,
            submission: SnapshotSubmissionAuthority::RestoreExisting,
            owner: SnapshotDurableOwner::Existing {
                record: Box::new(record),
                operation_lease,
            },
        }
    } else if let Some((candidate, candidate_preview, owner)) = recovery {
        if let Some(owner) = owner.as_ref() {
            validate_existing_snapshot_owner(
                owner,
                project_binding,
                &StoredProviderIdentityV1::from(durable_provider_identity.clone()),
                &candidate,
            )?;
        }
        let requires_reconsent = owner
            .as_ref()
            .is_none_or(|owner| owner.record.provider_resume.is_none());
        let recovered_preview = if requires_reconsent {
            consent.approve(&candidate_preview, reporter, cancellation)?;
            let (_workspace, recovered_source, recovered_path_dependencies) =
                snapshot_build_source_bundle_plan(root, reporter)?;
            check_snapshot_cancellation(cancellation)?;
            let recovered_preview = super::github_snapshot::GithubSnapshotPreviewV1::new(
                &candidate.final_request.operation_id,
                candidate.stage.source_created_at_ms,
                &stored.source_repository,
                &recovered_source,
                &recovered_path_dependencies,
            )?;
            super::github_snapshot::ensure_same_snapshot_plan(
                &candidate_preview,
                &recovered_preview,
            )?;
            let recovered_template = snapshot_request_template(
                ferry_config,
                binary_name,
                release,
                &candidate.final_request.operation_id,
                &stored.source_repository,
                recovered_source.manifest().clone(),
                signing.clone(),
                requested_artifacts.clone(),
            )?;
            let recovered_request = snapshot_request_for_candidate(&recovered_template, &candidate);
            if recovered_request != candidate.final_request {
                return Err(remote_error(
                    "snapshot_recovery_plan_changed",
                    "the complete private snapshot stage no longer matches the accepted build plan",
                    "Review a new zero-write plan; do not adopt or delete the preserved stage.",
                ));
            }
            recovered_preview
        } else {
            candidate_preview
        };
        ensure_config_snapshot_unchanged(
            root,
            &config_path,
            &approved_config_identity,
            &approved_config_bytes,
        )?;
        project_binding.verify()?;
        let (submission, durable_owner) = if let Some(owner) = owner {
            let operation_lease = job_store
                .try_acquire_operation_lease(&owner.local_job_id, JobOperationKind::Build)?;
            let submission = existing_snapshot_submission_authority(&owner.record);
            (
                submission,
                SnapshotDurableOwner::Existing {
                    record: Box::new(owner.record),
                    operation_lease,
                },
            )
        } else {
            let vacancy = snapshot_vacancy_for_operation(
                &job_store,
                &mut preacquired_snapshot_vacancy,
                &candidate.final_request.operation_id,
            )?;
            (
                SnapshotSubmissionAuthority::FreshReconsent,
                SnapshotDurableOwner::Vacant(vacancy),
            )
        };
        SnapshotExecutionPlan {
            request: candidate.final_request.clone(),
            consent_sha256: recovered_preview.consent_sha256,
            source_created_at_ms: candidate.stage.source_created_at_ms,
            submission,
            owner: durable_owner,
        }
    } else {
        check_snapshot_cancellation(cancellation)?;
        let vacancy = snapshot_vacancy_for_operation(
            &job_store,
            &mut preacquired_snapshot_vacancy,
            &operation_id,
        )?;
        let staged = super::github_snapshot::stage_same_invocation_snapshot(
            &GithubPaths::new(root, root).git_isolation,
            &current_source,
            current_template,
            source_created_at_ms,
            &revalidated.consent_sha256,
            |inputs, operation_id, created_at_ms| {
                provider
                    .precompute_git_snapshot_graph(
                        inputs,
                        operation_id,
                        created_at_ms,
                        cancellation,
                    )
                    .map_err(|error| {
                        provider_failure(
                            &error,
                            "snapshot_graph_precompute_failed",
                            "the staged snapshot object graph could not be verified without mutation",
                        )
                    })
            },
        )?;
        SnapshotExecutionPlan {
            request: staged.request.clone(),
            consent_sha256: revalidated.consent_sha256.clone(),
            source_created_at_ms,
            submission: SnapshotSubmissionAuthority::SameInvocation(Box::new(staged)),
            owner: SnapshotDurableOwner::Vacant(vacancy),
        }
    };

    let SnapshotExecutionPlan {
        request,
        consent_sha256,
        source_created_at_ms: source_stage_created_at_ms,
        submission: authority,
        owner,
    } = execution_plan;
    let (local_job_id, mut operation_lease, existing_record) = match owner {
        SnapshotDurableOwner::Vacant(vacancy) => {
            let local_job_id = LocalJobId::generate();
            let initial_job = snapshot_initial_job(
                project_binding,
                StoredProviderIdentityV1::from(durable_provider_identity.clone()),
                local_job_id.clone(),
                request.clone(),
                source_stage_created_at_ms,
                unix_timestamp_ms()?,
            )?;
            let created = job_store.create_with_operation_lease(vacancy, &initial_job)?;
            if created.revision.local_job_id != local_job_id || created.revision.revision != 1 {
                return Err(remote_error(
                    "snapshot_job_creation_uncertain",
                    "the durable snapshot job creation receipt did not match its exact initial revision",
                    "Preserve the JobStore and private stage for inspection before retrying.",
                ));
            }
            (local_job_id, Some(created.operation_lease), None)
        }
        SnapshotDurableOwner::Existing {
            record,
            operation_lease,
        } => {
            let record = *record;
            (
                record.local_job_id.clone(),
                Some(operation_lease),
                Some(record),
            )
        }
    };
    let destinations_are_unbound = existing_record.as_ref().is_none_or(|record| {
        record
            .artifacts
            .iter()
            .all(|artifact| artifact.download_destination.is_none())
    });
    if !matches!(&authority, SnapshotSubmissionAuthority::RestoreExisting)
        || destinations_are_unbound
    {
        for download in &expected_downloads {
            ensure_config_snapshot_unchanged(
                root,
                &config_path,
                &approved_config_identity,
                &approved_config_bytes,
            )?;
            project_binding.verify()?;
            prepare_artifact_destination(root, &download.path)?;
        }
    }
    let submission = match authority {
        SnapshotSubmissionAuthority::SameInvocation(staged) => {
            let staged = *staged;
            Some(GithubGitSnapshotSubmissionV1::same_invocation(
                durable_provider_identity.clone(),
                staged.request,
                consent_sha256.clone(),
                staged.locator,
                staged.stage,
            ))
        }
        SnapshotSubmissionAuthority::FreshReconsent => {
            Some(GithubGitSnapshotSubmissionV1::after_fresh_reconsent(
                durable_provider_identity.clone(),
                request.clone(),
                consent_sha256.clone(),
            ))
        }
        SnapshotSubmissionAuthority::RestoreExisting => None,
    }
    .transpose()
    .map_err(|error| {
        provider_failure(
            &error,
            "snapshot_submission_invalid",
            "the durable snapshot submission authority is invalid",
        )
    })?;
    let provider = provider.with_checkpoint_sink(GithubJobStoreCheckpointSink::new(
        job_store.clone(),
        local_job_id.clone(),
    ));
    project_binding.verify()?;
    reporter.progress(format!(
        "Preparing GitHub snapshot build {} for {} at {}",
        local_job_id.as_str(),
        package_name,
        request
            .source_revision
            .as_deref()
            .unwrap_or("<unresolved-snapshot>")
    ));
    let build_deadline = Instant::now() + BUILD_TIMEOUT;
    let job_id = if let Some(submission) = submission {
        let (provider_job_hint, submit_error) =
            match provider.submit_git_snapshot(submission, cancellation) {
                Ok(handle) => (Some(handle.job_id), None),
                Err(error) => (None, Some(error)),
            };
        reconcile_submit_attempt_with_cancellation(
            &provider,
            &job_store,
            &local_job_id,
            project_binding,
            provider_job_hint.as_deref(),
            submit_error.as_ref(),
            cancellation,
        )?
    } else {
        let resume = existing_record
            .as_ref()
            .and_then(|record| record.provider_resume.clone())
            .ok_or_else(|| {
                remote_error(
                    "snapshot_resume_missing",
                    "the existing snapshot job lost its durable provider checkpoint",
                    "Preserve the JobStore and private stage for inspection; do not adopt or resubmit it.",
                )
            })?;
        let job_id = resume.job_id.clone();
        provider
            .restore_job_resumes_offline(vec![resume], &durable_provider_identity)
            .and_then(|()| provider.revalidate_restored_job_live(&job_id, cancellation))
            .and_then(|()| {
                provider
                    .reconcile_restored_job(&job_id, cancellation)
                    .map(drop)
            })
            .map_err(|error| {
                provider_failure(
                    &error,
                    "snapshot_resume_failed",
                    "the exact checkpointed snapshot job could not be restored and reconciled",
                )
            })?;
        job_id
    };
    require_bound_provider_job(
        &job_store,
        &local_job_id,
        &job_id,
        provider.workflow_run_trigger(),
    )?;
    release_build_wait_guards(&mut config_lock, &mut operation_lease);
    let terminal = poll_job(
        &provider,
        &job_store,
        &local_job_id,
        &job_id,
        build_deadline,
        cancellation,
        reporter,
    );
    let reacquired_operation_lease =
        acquire_build_mutation_lease(&job_store, &local_job_id, cancellation)?;
    let post_wait_rebind = (|| {
        let (current_stored, reacquired_config_lock) = load_config_for_build(root)?;
        if current_stored != stored {
            return Err(provider_config_changed());
        }
        ensure_config_snapshot_unchanged(
            root,
            &config_path,
            &approved_config_identity,
            &approved_config_bytes,
        )?;
        project_binding.verify()?;
        Ok(reacquired_config_lock)
    })();
    let reacquired_config_lock = match post_wait_rebind {
        Ok(config_lock) => config_lock,
        Err(error) => {
            return Err(reconcile_post_wait_rebind_failure(
                &provider,
                &job_store,
                &local_job_id,
                &job_id,
                project_binding,
                &terminal,
                &error,
            ));
        }
    };
    let completed_downloads = complete_submitted_job(
        &provider,
        &job_store,
        &local_job_id,
        &job_id,
        project_binding,
        &request,
        &expected_downloads,
        &artifact_path,
        build_deadline,
        terminal,
        reporter,
    )?;
    for guard in &completed_downloads.validation_guards {
        guard.verify()?;
    }
    for binding in completed_downloads.destinations.values() {
        binding.verify(project_binding)?;
    }
    project_binding.verify()?;
    let record = job_store.latest_under_operation_lease(
        &local_job_id,
        JobOperationKind::Build,
        &reacquired_operation_lease,
    )?;
    if record.state != StoredJobState::Succeeded
        || record.terminal_outcome != Some(StoredBuildOutcome::Succeeded)
        || record.cleanup_status != StoredCleanupStatus::Confirmed
    {
        return Err(remote_error(
            "snapshot_completion_not_durable",
            "the snapshot build completed without an exact durable success and cleanup receipt",
            "Preserve the local job and resume its exact completion before reporting success.",
        ));
    }
    let output = RemoteBuildOutput {
        project: root.to_string(),
        provider: "github",
        profile: profile_name(release),
        signing_mode: signing_mode_name(signing.mode),
        source_revision: request
            .source_revision
            .clone()
            .unwrap_or_else(|| "<missing>".to_owned()),
        source_sha256: request.source.sha256.clone(),
        source_files: request.source.entries.len(),
        expected_artifact: artifact_path.to_string(),
        artifact: Some(artifact_path.to_string()),
        artifact_sha256: Some(completed_downloads.primary_sha256),
        supporting_artifacts: Vec::new(),
        local_job_id: Some(local_job_id.as_str().to_owned()),
        job_id: Some(job_id),
        validated: true,
        cleanup_confirmed: true,
        dry_run: false,
    };
    let mut warnings = unsigned_warning(signing.mode);
    warnings.extend(super::github_snapshot::snapshot_warnings(&consent_sha256));
    reporter.success(
        "build",
        &output,
        || {
            format!(
                "Remote GitHub snapshot build completed and verified\n\nLocal job:\n  {}\n\nArtifact:\n  {}\n\nSHA-256:\n  {}",
                output.local_job_id.as_deref().unwrap_or("<missing>"),
                output.artifact.as_deref().unwrap_or("<missing>"),
                output.artifact_sha256.as_deref().unwrap_or("<missing>")
            )
        },
        &warnings,
    );
    drop(reacquired_config_lock);
    drop(reacquired_operation_lease);
    Ok(Some(SnapshotBuildCompletion {
        record,
        preview_sha256: consent_sha256,
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the request constructor keeps every consent-bound snapshot field explicit"
)]
fn snapshot_request_template(
    ferry_config: &rustferry_core::FerryConfig,
    binary_name: &str,
    release: bool,
    operation_id: &str,
    source_repository: &str,
    source: SourceManifest,
    signing: SigningPlan,
    requested_artifacts: BTreeSet<IosArtifactType>,
) -> Result<IosDeviceBuildRequest, CliError> {
    Ok(IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: operation_id.to_owned(),
        product_name: ferry_config.app.name.clone(),
        bundle_identifier: ferry_config.app.identifier.clone(),
        minimum_ios_version: ferry_config.ios.min_version.clone(),
        product: rustferry_apple::derive_ios_device_product_expectation(ferry_config, binary_name)?,
        profile: if release {
            BuildProfile::Release
        } else {
            BuildProfile::Debug
        },
        source_mode: SourceMode::GitSnapshot,
        source_repository: Some(source_repository.to_owned()),
        source_revision: None,
        source,
        signing,
        requested_artifacts,
    })
}

fn snapshot_request_for_candidate(
    template: &IosDeviceBuildRequest,
    candidate: &GithubGitSnapshotRecoveryCandidateV1,
) -> IosDeviceBuildRequest {
    let mut request = template.clone();
    candidate
        .final_request
        .operation_id
        .clone_into(&mut request.operation_id);
    request.source_revision = Some(candidate.stage.graph.commit.as_str().to_owned());
    request
}

fn find_resumable_snapshot_job(
    store: &JobStore,
    project_binding: &ProjectFilesystemBinding,
    provider: &StoredProviderIdentityV1,
    current_template: &IosDeviceBuildRequest,
) -> Result<Option<StoredJobV1>, CliError> {
    let summaries = store.list_latest_for_project(
        project_binding.root.as_str(),
        project_binding.identity.as_ref(),
        MAX_LISTED_JOBS,
    )?;
    if summaries.len() == MAX_LISTED_JOBS {
        return Err(remote_error(
            "snapshot_resume_scan_bound",
            "the exact project has too many durable jobs to prove snapshot resume uniqueness",
            "Prune completed lineages before starting another snapshot build; no new operation was created.",
        ));
    }
    let mut matching = None;
    for summary in summaries {
        let record = store.latest_for_project(
            &summary.local_job_id,
            project_binding.root.as_str(),
            project_binding.identity.as_ref(),
        )?;
        if !resumable_snapshot_job_matches(&record, provider, current_template) {
            continue;
        }
        if matching.replace(record).is_some() {
            return Err(remote_error(
                "snapshot_resume_ambiguous",
                "more than one unfinished durable snapshot job matches the current exact source plan",
                "Inspect and complete the matching jobs before starting another snapshot operation.",
            ));
        }
    }
    Ok(matching)
}

fn validate_resumable_snapshot_job(
    record: &StoredJobV1,
    project_binding: &ProjectFilesystemBinding,
    provider: &StoredProviderIdentityV1,
    current_template: &IosDeviceBuildRequest,
) -> Result<(), CliError> {
    if record.project.canonical_root != project_binding.root.as_str()
        || record.project.filesystem_identity != project_binding.identity.to_string()
        || !resumable_snapshot_job_matches(record, provider, current_template)
    {
        return Err(remote_error(
            "snapshot_resume_changed",
            "the durable snapshot job changed before its exact Build lease was acquired",
            "Inspect the job and rerun only after its project, provider, source, and cleanup state are stable.",
        ));
    }
    Ok(())
}

fn resumable_snapshot_job_matches(
    record: &StoredJobV1,
    provider: &StoredProviderIdentityV1,
    current_template: &IosDeviceBuildRequest,
) -> bool {
    if &record.provider != provider
        || record.request.source_mode != SourceMode::GitSnapshot
        || record.provider_resume.is_none()
        || snapshot_job_is_fully_settled(record)
    {
        return false;
    }
    let mut expected = current_template.clone();
    expected.operation_id.clone_from(&record.operation_id);
    expected
        .source_revision
        .clone_from(&record.request.source_revision);
    expected == record.request
}

fn snapshot_job_is_fully_settled(record: &StoredJobV1) -> bool {
    record.cleanup_status == StoredCleanupStatus::Confirmed
        && matches!(
            record.state,
            StoredJobState::Succeeded
                | StoredJobState::Failed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
}

enum SnapshotSubmissionAuthority {
    SameInvocation(Box<super::github_snapshot::StagedGithubSnapshotV1>),
    FreshReconsent,
    RestoreExisting,
}

fn existing_snapshot_submission_authority(record: &StoredJobV1) -> SnapshotSubmissionAuthority {
    if record.provider_resume.is_some() {
        SnapshotSubmissionAuthority::RestoreExisting
    } else {
        SnapshotSubmissionAuthority::FreshReconsent
    }
}

enum SnapshotDurableOwner {
    Vacant(cargo_ferry::job_store::VacantSnapshotOperationLease),
    Existing {
        record: Box<StoredJobV1>,
        operation_lease: JobOperationLease,
    },
}

struct SnapshotExecutionPlan {
    request: IosDeviceBuildRequest,
    consent_sha256: String,
    source_created_at_ms: u64,
    submission: SnapshotSubmissionAuthority,
    owner: SnapshotDurableOwner,
}

fn require_snapshot_vacancy(
    outcome: SnapshotOperationVacancyV1,
) -> Result<cargo_ferry::job_store::VacantSnapshotOperationLease, CliError> {
    match outcome {
        SnapshotOperationVacancyV1::Vacant(vacancy) => Ok(vacancy),
        SnapshotOperationVacancyV1::Owned(owner) => Err(snapshot_stage_already_owned(&owner)),
    }
}

fn snapshot_vacancy_for_operation(
    store: &JobStore,
    preacquired: &mut Option<cargo_ferry::job_store::VacantSnapshotOperationLease>,
    operation_id: &str,
) -> Result<cargo_ferry::job_store::VacantSnapshotOperationLease, CliError> {
    if let Some(vacancy) = preacquired.take() {
        if vacancy.operation_id() != operation_id {
            return Err(remote_error(
                "snapshot_operation_changed",
                "the approved snapshot operation changed before durable ownership",
                "Preserve private stages and request a new exact preview; do not reuse either operation identifier.",
            ));
        }
        return Ok(vacancy);
    }
    require_snapshot_vacancy(store.try_acquire_vacant_snapshot_operation_lease(operation_id)?)
}

fn validate_ide_snapshot_owner(
    record: &StoredJobV1,
    project_binding: &ProjectFilesystemBinding,
    current_template: &IosDeviceBuildRequest,
) -> Result<(), CliError> {
    let mut expected = current_template.clone();
    expected
        .source_revision
        .clone_from(&record.request.source_revision);
    if record.operation_id != current_template.operation_id
        || record.project.canonical_root != project_binding.root.as_str()
        || record.project.filesystem_identity != project_binding.identity.to_string()
        || record.request.source_mode != SourceMode::GitSnapshot
        || record.request != expected
    {
        return Err(remote_error_with_details(
            "snapshot_operation_owned",
            "the approved IDE snapshot operation belongs to a different durable build identity",
            "Inspect the exact existing job; do not adopt, resubmit, or replace its snapshot stage.",
            vec![format!("local_job_id={}", record.local_job_id.as_str())],
        ));
    }
    Ok(())
}

fn snapshot_stage_already_owned(
    owner: &cargo_ferry::job_store::SnapshotOperationOwnerV1,
) -> CliError {
    let provider_state = if owner.record.provider_resume.is_some() {
        "checkpointed"
    } else {
        "pre_checkpoint"
    };
    remote_error_with_details(
        "snapshot_operation_owned",
        "the complete private snapshot stage already has a durable local job owner",
        "Resume or inspect the exact existing job; never adopt its stage into a second job.",
        vec![
            format!("local_job_id={}", owner.local_job_id.as_str()),
            format!("provider_state={provider_state}"),
        ],
    )
}

fn validate_existing_snapshot_owner(
    owner: &cargo_ferry::job_store::SnapshotOperationOwnerV1,
    project_binding: &ProjectFilesystemBinding,
    provider: &StoredProviderIdentityV1,
    candidate: &GithubGitSnapshotRecoveryCandidateV1,
) -> Result<(), CliError> {
    let record = &owner.record;
    if record.local_job_id != owner.local_job_id
        || record.operation_id != candidate.final_request.operation_id
        || record.request != candidate.final_request
        || &record.provider != provider
        || record.project.canonical_root != project_binding.root.as_str()
        || record.project.filesystem_identity != project_binding.identity.to_string()
    {
        return Err(snapshot_stage_already_owned(owner));
    }
    if let Some(resume) = &record.provider_resume {
        let snapshot_matches = resume.git_snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.stage_locator == candidate.stage_locator && snapshot.stage == candidate.stage
        });
        if resume.request != candidate.final_request || !snapshot_matches {
            return Err(snapshot_stage_already_owned(owner));
        }
    } else if record.revision != 1
        || record.state != StoredJobState::SourceReady
        || record.last_confirmed_state != Some(StoredJobState::SourceReady)
        || record.provider_job_id.is_some()
        || record.provider_run_id.is_some()
        || record.terminal_outcome.is_some()
        || record.cleanup_status != StoredCleanupStatus::NotStarted
    {
        return Err(snapshot_stage_already_owned(owner));
    }
    Ok(())
}

fn snapshot_initial_job(
    project_binding: &ProjectFilesystemBinding,
    provider: StoredProviderIdentityV1,
    local_job_id: LocalJobId,
    request: IosDeviceBuildRequest,
    created_at_ms: u64,
    updated_at_ms: u64,
) -> Result<StoredJobV1, CliError> {
    request.validate().map_err(|error| {
        remote_error_with_details(
            "invalid_snapshot_build_request",
            "the consented GitHub snapshot request failed final validation",
            "Preserve the private stage and inspect the exact request before retrying.",
            vec![error.to_string()],
        )
    })?;
    let request_sha256 = canonical_request_sha256(&request).map_err(|error| {
        provider_failure(
            &error,
            "request_identity_unavailable",
            "the validated snapshot request could not be hashed canonically",
        )
    })?;
    let semantic_retry_sha256 = canonical_retry_template_sha256_v1(&request).map_err(|error| {
        provider_failure(
            &error,
            "retry_identity_unavailable",
            "the validated snapshot request could not be bound to a retry identity",
        )
    })?;
    let application_identifier = request.bundle_identifier.clone();
    let operation_id = request.operation_id.clone();
    let source_revision = request.source_revision.clone();
    let manifest_sha256 = request.source.sha256.clone();
    let profile = request.profile;
    let signing_mode = request.signing.mode;
    Ok(StoredJobV1 {
        schema_version: JOB_STORE_SCHEMA_VERSION,
        local_job_id,
        revision: 1,
        project: StoredProjectIdentityV1 {
            canonical_root: project_binding.root.to_string(),
            filesystem_identity: project_binding.identity.to_string(),
            application_identifier,
        },
        provider,
        provider_job_id: None,
        provider_run_id: None,
        operation_id,
        request,
        request_sha256,
        semantic_retry_sha256,
        source: StoredSourceIdentityV1 {
            revision: source_revision,
            manifest_sha256,
        },
        target: "iphone".to_owned(),
        profile,
        signing_mode,
        created_at_ms,
        submitted_at_ms: None,
        updated_at_ms: updated_at_ms.max(created_at_ms),
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
    })
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(super) fn build_iphone(
    project_binding: &ProjectFilesystemBinding,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    provider: RemoteProviderChoice,
    expected_team: Option<&str>,
    release: bool,
    unsigned: bool,
    snapshot: bool,
    snapshot_yes: bool,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    project_binding.verify()?;
    let root = project_binding.root();
    let RemoteProviderChoice::Github = provider;
    if snapshot {
        return build_iphone_github_snapshot(
            project_binding,
            ferry_config,
            package_name,
            binary_name,
            expected_team,
            release,
            unsigned,
            &SnapshotConsentAuthority::Cli { yes: snapshot_yes },
            artifact,
            include_dsym,
            dry_run,
            &CancellationToken::new(),
            reporter,
        )
        .map(drop);
    }
    if unsigned {
        select_requested_artifacts(SigningMode::UnsignedCompileOnly, artifact, include_dsym)?;
    }
    let (stored, config_lock) = load_config_for_build(root)?;
    let config_path = root.join(CONFIG_RELATIVE_PATH);
    let (config_identity, config_bytes) = read_private_config_snapshot(root, &config_path)?;
    if decode_stored_config(&config_bytes)? != stored {
        return Err(provider_config_changed());
    }
    let mut config_lock = Some(config_lock);
    project_binding.verify()?;
    let signing = select_signing_plan(&stored, ferry_config, binary_name, expected_team, unsigned)?;
    project_binding.verify()?;
    let (git, execution) = git_context_from_stored(root, &stored, reporter)?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    ensure_clean(&git, reporter)?;
    project_binding.verify()?;
    let mut source = source_manifest(root, &git, reporter)?;
    bind_manifest_to_revision(&git, &mut source, reporter)?;
    ensure_clean_revision(&git, reporter)?;
    project_binding.verify()?;
    let product =
        rustferry_apple::derive_ios_device_product_expectation(ferry_config, binary_name)?;
    let signing_mode = signing.mode;
    let requested_artifacts = match signing_mode {
        SigningMode::UnsignedCompileOnly | SigningMode::ManualDevelopment => {
            select_requested_artifacts(signing_mode, artifact, include_dsym)?
        }
        _ => {
            return Err(remote_error(
                "unsupported_signing_mode",
                "the GitHub worker supports only manual-development and unsigned compile-only builds",
                "Configure a manual-development signing plan, or pass `--unsigned` for a non-installable smoke build.",
            ));
        }
    };
    let operation_id = operation_id();
    let request = IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: operation_id.clone(),
        product_name: ferry_config.app.name.clone(),
        bundle_identifier: ferry_config.app.identifier.clone(),
        minimum_ios_version: ferry_config.ios.min_version.clone(),
        product,
        profile: if release {
            BuildProfile::Release
        } else {
            BuildProfile::Debug
        },
        source_mode: SourceMode::Git,
        source_repository: Some(stored.source_repository.clone()),
        source_revision: Some(git.revision.clone()),
        source,
        signing,
        requested_artifacts,
    };
    request.validate().map_err(|error| {
        remote_error_with_details(
            "invalid_remote_build_request",
            "the physical-iPhone build request failed local validation",
            "Check ferry.toml, Cargo targets, the signing plan, and the selected Git revision.",
            vec![error.to_string()],
        )
    })?;
    project_binding.verify()?;

    let expected_downloads = expected_artifact_downloads(
        root,
        &request.product_name,
        release,
        signing_mode,
        &request.requested_artifacts,
    )?;
    project_binding.verify()?;
    let artifact_path = expected_downloads[0].path.clone();
    let planned = RemoteBuildOutput {
        project: root.to_string(),
        provider: "github",
        profile: profile_name(release),
        signing_mode: signing_mode_name(signing_mode),
        source_revision: git.revision.clone(),
        source_sha256: request.source.sha256.clone(),
        source_files: request.source.entries.len(),
        expected_artifact: artifact_path.to_string(),
        artifact: None,
        artifact_sha256: None,
        supporting_artifacts: expected_downloads
            .iter()
            .skip(1)
            .map(|download| download.path.to_string())
            .collect(),
        local_job_id: None,
        job_id: None,
        validated: false,
        cleanup_confirmed: false,
        dry_run: true,
    };
    if dry_run {
        project_binding.verify()?;
        reporter.success(
            "build",
            &planned,
            || {
                format!(
                    "Remote iPhone build plan\n\nProvider:\n  GitHub Actions\n\nRevision:\n  {}\n\nExpected artifact:\n  {}",
                    planned.source_revision, planned.expected_artifact
                )
            },
            &unsigned_warning(signing_mode),
        );
        return Ok(());
    }

    for download in &expected_downloads {
        project_binding.verify()?;
        prepare_artifact_destination(root, &download.path)?;
        project_binding.verify()?;
    }
    let provider = build_provider(root, &git.root, &stored)?;
    project_binding.verify()?;
    handshake(&provider, signing_mode, &request.requested_artifacts)?;
    project_binding.verify()?;
    let readiness = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: format!("{operation_id}-doctor"),
                require_signing: signing_mode.is_signed(),
            },
            CancellationToken::new(),
        ),
        "provider_doctor_failed",
        "the GitHub provider doctor could not complete",
    )?;
    ensure_doctor_ready(&readiness, signing_mode.is_signed())?;
    project_binding.verify()?;

    let canonical_root = project_binding.root.clone();
    let project_filesystem_identity = project_binding.identity.clone();
    let durable_provider_identity = provider.durable_identity().map_err(|error| {
        provider_failure(
            &error,
            "provider_identity_unavailable",
            "the GitHub provider identity could not be bound durably",
        )
    })?;
    let request_sha256 = canonical_request_sha256(&request).map_err(|error| {
        provider_failure(
            &error,
            "request_identity_unavailable",
            "the validated remote build request could not be hashed canonically",
        )
    })?;
    let semantic_retry_sha256 = canonical_retry_template_sha256_v1(&request).map_err(|error| {
        provider_failure(
            &error,
            "retry_identity_unavailable",
            "the validated remote build request could not be bound to a retry identity",
        )
    })?;
    let created_at_ms = unix_timestamp_ms()?;
    let local_job_id = LocalJobId::generate();
    let job_store = JobStore::open_default()?;
    project_binding.verify()?;
    let initial_job = StoredJobV1 {
        schema_version: JOB_STORE_SCHEMA_VERSION,
        local_job_id: local_job_id.clone(),
        revision: 1,
        project: StoredProjectIdentityV1 {
            canonical_root: canonical_root.to_string(),
            filesystem_identity: project_filesystem_identity.to_string(),
            application_identifier: request.bundle_identifier.clone(),
        },
        provider: StoredProviderIdentityV1::from(durable_provider_identity),
        provider_job_id: None,
        provider_run_id: None,
        operation_id: operation_id.clone(),
        request: request.clone(),
        request_sha256,
        semantic_retry_sha256,
        source: StoredSourceIdentityV1 {
            revision: request.source_revision.clone(),
            manifest_sha256: request.source.sha256.clone(),
        },
        target: "iphone".to_owned(),
        profile: request.profile,
        signing_mode,
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
            attempt: 0,
            parent_job_id: None,
            child_job_ids: Vec::new(),
        },
        cancellation_status: StoredCancellationStatus::NotRequested,
        failure: None,
        provider_resume: None,
    };
    project_binding.verify()?;
    job_store.create(&initial_job)?;
    let mut operation_lease =
        Some(job_store.try_acquire_operation_lease(&local_job_id, JobOperationKind::Build)?);
    let provider = provider.with_checkpoint_sink(GithubJobStoreCheckpointSink::new(
        job_store.clone(),
        local_job_id.clone(),
    ));
    if let Err(error) = project_binding.verify() {
        persist_controller_failure(
            &job_store,
            &local_job_id,
            "controller.project_identity_changed",
            false,
        )?;
        return Err(error);
    }

    reporter.progress(format!(
        "Submitting GitHub iPhone build {} for {} at {}",
        local_job_id.as_str(),
        package_name,
        git.revision
    ));
    let build_deadline = Instant::now() + BUILD_TIMEOUT;
    let (provider_job_hint, submit_error) =
        match poll_provider_once(provider.submit(request.clone(), CancellationToken::new())) {
            ImmediateProviderResult::Ready(Ok(handle)) => (Some(handle.job_id), None),
            ImmediateProviderResult::Ready(Err(error)) => (None, Some(error)),
            ImmediateProviderResult::Pending => {
                persist_submit_uncertain(&job_store, &local_job_id)?;
                return Err(provider_runtime_required());
            }
        };
    let job_id = reconcile_submit_attempt(
        &provider,
        &job_store,
        &local_job_id,
        project_binding,
        provider_job_hint.as_deref(),
        submit_error.as_ref(),
    )?;
    if let Err(error) = project_binding.verify() {
        persist_submit_uncertain(&job_store, &local_job_id)?;
        return Err(error);
    }
    if let Err(error) = require_bound_provider_job(
        &job_store,
        &local_job_id,
        &job_id,
        provider.workflow_run_trigger(),
    ) {
        persist_submit_uncertain(&job_store, &local_job_id)?;
        return Err(error);
    }
    release_build_wait_guards(&mut config_lock, &mut operation_lease);
    let terminal = poll_job(
        &provider,
        &job_store,
        &local_job_id,
        &job_id,
        build_deadline,
        &CancellationToken::new(),
        reporter,
    );
    let reacquire_cancellation = CancellationToken::new();
    let reacquired_operation_lease =
        acquire_build_mutation_lease(&job_store, &local_job_id, &reacquire_cancellation)?;
    let post_wait_rebind = (|| {
        let (current_stored, reacquired_config_lock) = load_config_for_build(root)?;
        if current_stored != stored {
            return Err(provider_config_changed());
        }
        ensure_config_snapshot_unchanged(root, &config_path, &config_identity, &config_bytes)?;
        project_binding.verify()?;
        git.caller_git.head_revision().map_err(|_| {
            remote_error(
                "caller_repository_identity_changed",
                "the sealed caller Git repository changed identity while the remote build ran",
                "Restore the exact caller repository before completing local artifact publication.",
            )
        })?;
        Ok(reacquired_config_lock)
    })();
    let reacquired_config_lock = match post_wait_rebind {
        Ok(config_lock) => config_lock,
        Err(error) => {
            return Err(reconcile_post_wait_rebind_failure(
                &provider,
                &job_store,
                &local_job_id,
                &job_id,
                project_binding,
                &terminal,
                &error,
            ));
        }
    };
    let completed_downloads = complete_submitted_job(
        &provider,
        &job_store,
        &local_job_id,
        &job_id,
        project_binding,
        &request,
        &expected_downloads,
        &artifact_path,
        build_deadline,
        terminal,
        reporter,
    )?;
    let artifact_sha256 = completed_downloads.primary_sha256.clone();
    let output = RemoteBuildOutput {
        project: root.to_string(),
        provider: "github",
        profile: profile_name(release),
        signing_mode: signing_mode_name(signing_mode),
        source_revision: git.revision,
        source_sha256: request.source.sha256,
        source_files: request.source.entries.len(),
        expected_artifact: artifact_path.to_string(),
        artifact: Some(artifact_path.to_string()),
        artifact_sha256: Some(artifact_sha256),
        supporting_artifacts: expected_downloads
            .iter()
            .skip(1)
            .map(|download| download.path.to_string())
            .collect(),
        local_job_id: Some(local_job_id.as_str().to_owned()),
        job_id: Some(job_id),
        validated: true,
        cleanup_confirmed: true,
        dry_run: false,
    };
    for guard in &completed_downloads.validation_guards {
        guard.verify()?;
    }
    for binding in completed_downloads.destinations.values() {
        binding.verify(project_binding)?;
    }
    project_binding.verify()?;
    drop(reacquired_config_lock);
    drop(reacquired_operation_lease);
    reporter.success(
        "build",
        &output,
        || {
            let supporting = if output.supporting_artifacts.is_empty() {
                String::new()
            } else {
                format!(
                    "\n\nSupporting artifacts:\n{}",
                    output
                        .supporting_artifacts
                        .iter()
                        .map(|path| format!("  {path}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };
            format!(
                "✓ Remote iPhone build completed and verified\n\nLocal job:\n  {}\n\nArtifact:\n  {}\n\nSHA-256:\n  {}{}",
                output.local_job_id.as_deref().unwrap_or("<missing>"),
                output.artifact.as_deref().unwrap_or("<missing>"),
                output.artifact_sha256.as_deref().unwrap_or("<missing>"),
                supporting
            )
        },
        &unsigned_warning(signing_mode),
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "terminal tracking, artifact publication, local validation, and cleanup form one durable completion transaction"
)]
fn complete_submitted_job(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    job_id: &str,
    project_binding: &ProjectFilesystemBinding,
    request: &IosDeviceBuildRequest,
    expected_downloads: &[ExpectedDownload],
    artifact_path: &Utf8Path,
    deadline: Instant,
    terminal: Result<JobTerminal, CliError>,
    reporter: &Reporter,
) -> Result<CompletedArtifactDownloads, CliError> {
    let build_deadline = deadline;
    let operation_id = request.operation_id.as_str();
    let source_revision = request.source_revision.as_deref().ok_or_else(|| {
        remote_error(
            "source_revision_missing",
            "the durable GitHub request has no exact source revision",
            "Preserve the job and inspect its immutable request before completion.",
        )
    })?;
    let terminal = match terminal {
        Ok(terminal) => terminal,
        Err(error) => {
            let cleanup =
                cleanup_job_durably(provider, store, local_job_id, job_id, project_binding);
            if matches!(error, CliError::CommandInterrupted { .. }) {
                let latest = store.latest(local_job_id).ok();
                reporter.progress(interrupted_cleanup_progress_for_job(
                    latest.as_ref(),
                    job_id,
                ));
                return Err(error);
            }
            if cleanup.is_ok() {
                persist_controller_failure(
                    store,
                    local_job_id,
                    "controller.tracking_failed",
                    true,
                )?;
                return Err(error);
            }
            return Err(remote_error_with_details(
                "remote_job_tracking_failed",
                "the GitHub job could not be tracked and cleaned to a verified terminal state",
                "Preserve the exact job ID and inspect the provider-created temporary ref before retrying.",
                vec![
                    format!("job_id={job_id}"),
                    error.to_string(),
                    format!(
                        "cleanup={}",
                        cleanup.expect_err("failed cleanup was checked above")
                    ),
                ],
            ));
        }
    };
    if terminal.state != JobState::Succeeded {
        let cleanup = cleanup_job_durably(provider, store, local_job_id, job_id, project_binding);
        let mut details = vec![
            format!("provider=github"),
            format!("job_id={job_id}"),
            format!("state={}", state_name(terminal.state)),
        ];
        details.extend(terminal.diagnostics);
        if let Err(error) = cleanup {
            details.push(format!("cleanup={error}"));
        } else {
            details.push("cleanup=confirmed".to_owned());
        }
        return Err(remote_error_with_details(
            if terminal.state == JobState::Cancelled {
                "remote_job_cancelled"
            } else {
                "remote_job_failed"
            },
            "the GitHub macOS iPhone build did not succeed",
            "Inspect the GitHub Actions job, correct the reported build or signing problem, then rerun the same cargo ferry build command.",
            details,
        ));
    }

    let download: Result<CompletedArtifactDownloads, ArtifactProcessingFailure> = (|| {
        let manifests =
            list_artifacts_with_retry(provider, job_id, build_deadline, reporter, project_binding)?;
        project_binding.verify()?;
        if manifests.len() != 1 {
            return Err(remote_error(
                "artifact_manifest_ambiguous",
                "the GitHub job did not produce exactly one verified artifact manifest",
                "Retain the job and inspect its uploaded artifact set before retrying.",
            )
            .into());
        }
        let manifest = &manifests[0];
        if manifest.operation_id != operation_id
            || manifest.job_id != job_id
            || manifest.source_revision.as_deref() != Some(source_revision)
        {
            return Err(remote_error(
                "artifact_identity_mismatch",
                "the verified artifact manifest does not match this exact build request",
                "Do not use the artifact; retain the job metadata for investigation and retry with a new operation ID.",
            )
            .into());
        }
        for artifact_type in &request.requested_artifacts {
            require_one_artifact(manifest, artifact_type.artifact_kind())?;
        }
        let mut destinations = BTreeMap::new();
        for expected in expected_downloads {
            let artifact = require_one_artifact(manifest, expected.kind)?;
            let destination = DownloadDestinationBinding::capture(&expected.path, project_binding)?;
            if destinations
                .insert(artifact.artifact_id.clone(), destination)
                .is_some()
            {
                return Err(remote_error(
                    "artifact_identity_duplicated",
                    "the verified artifact manifest reused an artifact identifier",
                    "Preserve the exact job and inspect its verified artifact manifest before retrying.",
                )
                .into());
            }
        }
        persist_or_verify_download_destinations(store, local_job_id, &destinations)?;

        let mut primary_sha256 = None;
        for expected in expected_downloads {
            let artifact = require_one_artifact(manifest, expected.kind)?;
            let destination_binding = destinations
                .get(&artifact.artifact_id)
                .ok_or_else(|| {
                    remote_error(
                        "artifact_destination_intent_missing",
                        "a verified artifact has no durable destination binding",
                        "Preserve the local job and inspect its exact download intents before retrying.",
                    )
                })?;
            download_or_resume_artifact(
                provider,
                store,
                local_job_id,
                job_id,
                manifest,
                artifact,
                destination_binding,
                project_binding,
            )?;
            if expected.path == artifact_path {
                primary_sha256 = Some(artifact.sha256.clone());
            }
        }
        match store.latest(local_job_id).map_err(CliError::from)?.state {
            StoredJobState::Downloading => persist_downloads_complete(store, local_job_id)?,
            StoredJobState::Downloaded
            | StoredJobState::Validating
            | StoredJobState::CleanupPending
            | StoredJobState::Succeeded => {}
            _ => {
                return Err(ArtifactProcessingFailure::from(remote_error(
                    "artifact_download_phase_mismatch",
                    "the durable job cannot resume artifact completion from its current state",
                    "Preserve the job and reconcile its exact provider and artifact checkpoints.",
                )));
            }
        }
        let primary_sha256 = primary_sha256.ok_or_else(|| {
            ArtifactProcessingFailure::from(remote_error(
                "artifact_missing",
                "the primary iPhone artifact was not downloaded",
                "Inspect the verified manifest and retry after correcting the provider output.",
            ))
        })?;
        Ok(CompletedArtifactDownloads {
            primary_sha256,
            destinations,
            validation_guards: Vec::new(),
        })
    })();

    let completed_downloads = match download {
        Ok(mut downloads) => {
            downloads.validation_guards = match finish_completed_downloads(
                provider,
                store,
                local_job_id,
                job_id,
                project_binding,
                &downloads.destinations,
            ) {
                Ok(guards) => guards,
                Err(error) => {
                    let latest = store.latest(local_job_id)?;
                    if latest.cleanup_status == StoredCleanupStatus::Confirmed
                        && latest.state != StoredJobState::Succeeded
                    {
                        persist_controller_failure(
                            store,
                            local_job_id,
                            "controller.final_artifact_validation_failed",
                            false,
                        )?;
                    }
                    return Err(error);
                }
            };
            downloads
        }
        Err(download_failure) => {
            let state_checkpoint = if download_failure.local_publication_uncertain {
                persist_artifact_publication_uncertain(
                    store,
                    local_job_id,
                    "controller.artifact_publication_uncertain",
                )
            } else {
                persist_controller_failure(
                    store,
                    local_job_id,
                    "controller.artifact_processing_failed",
                    false,
                )
            };
            let cleanup =
                cleanup_job_durably(provider, store, local_job_id, job_id, project_binding);
            match (state_checkpoint, cleanup) {
                (Ok(()), Ok(())) => return Err(*download_failure.error),
                (Err(state_error), Ok(())) => {
                    return Err(remote_error_with_details(
                        "artifact_retrieval_checkpoint_failed",
                        "artifact retrieval failed and its durable local reconciliation state could not be confirmed",
                        "Preserve the exact local job ID and intended destinations before any retry.",
                        vec![
                            format!("local_job_id={}", local_job_id.as_str()),
                            format!("job_id={job_id}"),
                            download_failure.error.to_string(),
                            state_error.to_string(),
                        ],
                    ));
                }
                (state_checkpoint, Err(cleanup_error)) => {
                    let mut details = vec![
                        format!("local_job_id={}", local_job_id.as_str()),
                        format!("job_id={job_id}"),
                        download_failure.error.to_string(),
                        cleanup_error.to_string(),
                    ];
                    if let Err(state_error) = state_checkpoint {
                        details.push(state_error.to_string());
                    }
                    return Err(remote_error_with_details(
                        "artifact_retrieval_and_cleanup_failed",
                        "artifact retrieval failed and remote cleanup was not confirmed",
                        "Preserve the exact local and provider job IDs, then reconcile the intended artifact destinations and temporary ref before retrying.",
                        details,
                    ));
                }
            }
        }
    };
    for guard in &completed_downloads.validation_guards {
        guard.verify()?;
    }
    for binding in completed_downloads.destinations.values() {
        binding.verify(project_binding)?;
    }
    project_binding.verify()?;

    Ok(completed_downloads)
}

fn release_build_wait_guards(
    config_lock: &mut Option<ProviderConfigLock>,
    operation_lease: &mut Option<JobOperationLease>,
) {
    drop(config_lock.take());
    drop(operation_lease.take());
}

fn acquire_build_mutation_lease(
    store: &JobStore,
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
) -> Result<JobOperationLease, CliError> {
    acquire_build_mutation_lease_until(
        store,
        local_job_id,
        cancellation,
        Instant::now() + BUILD_LEASE_REACQUIRE_TIMEOUT,
    )
}

fn acquire_build_mutation_lease_until(
    store: &JobStore,
    local_job_id: &LocalJobId,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<JobOperationLease, CliError> {
    loop {
        if cancellation.is_cancelled() || rustferry_core::process_control::interrupt_requested() {
            return Err(CliError::CommandInterrupted {
                tool: "GitHub Actions job".to_owned(),
                stage: "reacquire local artifact mutation lease",
            });
        }
        match store.try_acquire_operation_lease(local_job_id, JobOperationKind::Build) {
            Ok(lease) => return Ok(lease),
            Err(JobStoreError::JobBusy { .. }) if Instant::now() < deadline => {
                thread::sleep(BUILD_LEASE_REACQUIRE_POLL);
            }
            Err(JobStoreError::JobBusy { .. }) => {
                return Err(remote_error_with_details(
                    "job_build_reacquire_busy",
                    "the durable job remained busy after its bounded remote wait",
                    "Preserve the job and rerun completion after the active cancel, log, retry, or artifact operation finishes.",
                    vec![format!("local_job_id={}", local_job_id.as_str())],
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn reconcile_post_wait_rebind_failure(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    provider_job_id: &str,
    project_binding: &ProjectFilesystemBinding,
    observation: &Result<JobTerminal, CliError>,
    rebind_error: &CliError,
) -> CliError {
    let cleanup = cleanup_job_durably(
        provider,
        store,
        local_job_id,
        provider_job_id,
        project_binding,
    );
    let checkpoint = persist_controller_failure(
        store,
        local_job_id,
        "controller.post_wait_rebind_failed",
        cleanup.is_ok(),
    );
    let observation = match observation {
        Ok(terminal) => format!("observed_state={}", state_name(terminal.state)),
        Err(error) => format!("observation_error_code={}", error.code()),
    };
    let mut details = vec![
        format!("local_job_id={}", local_job_id.as_str()),
        format!("provider_job_id={provider_job_id}"),
        observation,
        format!("rebind_error_code={}", rebind_error.code()),
    ];
    details.push(match cleanup {
        Ok(()) => "cleanup=confirmed".to_owned(),
        Err(error) => format!("cleanup_error_code={}", error.code()),
    });
    if let Err(error) = checkpoint {
        details.push(format!("checkpoint_error_code={}", error.code()));
    }
    remote_error_with_details(
        "post_wait_rebind_failed",
        "the durable job could not rebind its exact local mutation boundary after remote observation",
        "Preserve the job and reconcile its exact cleanup state before retrying local artifact completion.",
        details,
    )
}

#[allow(clippy::too_many_lines)]
fn setup(arguments: RemoteSetupArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = arguments.provider;
    require_secure_git_publication_platform()?;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let git = git_context(&root, &arguments.source_remote_name, reporter)?;
    let execution = if arguments.source_remote_name == arguments.execution_remote_name {
        GitRemoteContext {
            repository: git.repository.clone(),
            repository_slug: git.repository_slug.clone(),
            source_repository: git.source_repository.clone(),
            fetch_endpoint: git.fetch_endpoint.clone(),
            push_endpoint: git.push_endpoint.clone(),
        }
    } else {
        git_remote_context(&git.caller_git, &arguments.execution_remote_name, reporter)?
    };
    validate_execution_endpoint_transports(&execution.fetch_endpoint, &execution.push_endpoint)?;
    let repository = match arguments.execution_repository.as_deref() {
        Some(specification) => {
            let (_, slug, source) = parse_repository_spec(specification)?;
            if source != execution.source_repository {
                return Err(remote_error(
                    "remote_repository_mismatch",
                    "--execution-repository does not match the selected execution Git remote",
                    "Use the exact owner/repository from the selected execution GitHub remote.",
                ));
            }
            slug
        }
        None => execution.repository_slug.clone(),
    };
    let (worker_repository_identity, _, worker_repository) =
        parse_repository_spec(&arguments.worker_repository)?;
    if worker_repository == execution.source_repository
        && execution.source_repository != git.source_repository
    {
        return Err(remote_error(
            "private_execution_identity_exposure",
            "the worker source repository cannot be the execution repository",
            "Use a public worker source repository distinct from the private execution repository.",
        ));
    }
    let trusted_source_ref = match arguments.trusted_ref {
        Some(value) => value,
        None => format!("refs/heads/{}", current_branch(&git, reporter)?),
    };
    let worker_revision = arguments
        .worker_revision
        .or_else(|| option_env!("RUSTFERRY_WORKER_REVISION").map(ToOwned::to_owned))
        .ok_or_else(|| {
            remote_error(
                "worker_revision_required",
                "GitHub setup needs the exact RustFerry worker source revision",
                "Pass `--worker-revision` with the trusted lowercase 40-hex commit containing the compatible ferry-worker-macos source.",
            )
        })?;
    let ferry_config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let cargo_targets = super::platform_build::read_cargo_targets(&root)?;
    let signing_targets = unsigned_signing_plan(&ferry_config, cargo_targets.binary())?.targets;
    SigningSecretNames::for_targets(&signing_targets).map_err(|error| {
        remote_error_with_details(
            "invalid_signing_target_secret_map",
            "the current iPhone target graph cannot form a static protected-secret map",
            "Correct duplicate or unsupported application and extension targets before GitHub setup.",
            vec![error.to_string()],
        )
    })?;
    let stored = StoredGithubConfig {
        schema_version: CONFIG_SCHEMA_VERSION,
        repository,
        source_repository: git.source_repository.clone(),
        source_fetch_endpoint: git.fetch_endpoint.clone(),
        source_push_endpoint: git.push_endpoint.clone(),
        execution_fetch_endpoint: execution.fetch_endpoint.clone(),
        execution_push_endpoint: execution.push_endpoint.clone(),
        trusted_source_ref,
        workflow_file: WORKFLOW_FILE.to_owned(),
        protected_environment: PROTECTED_ENVIRONMENT.to_owned(),
        temporary_namespace: TEMPORARY_NAMESPACE.to_owned(),
        worker_repository: worker_repository.clone(),
        worker_revision,
        worker_version: arguments.worker_version,
        run_trigger: arguments.run_trigger.into(),
        signing_targets,
        signing: None,
    };
    validate_stored_config(&stored)?;
    let workflow = workflow_from_stored(&stored)?;
    let generated = generate_workflow(&workflow);
    let paths = GithubPaths::new(&root, &git.root);
    let config_bytes = encode_stored_config(&stored)?;
    reject_linked_components(&git.root, Utf8Path::new(".github/workflows"), true)?;
    reject_linked_components(&root, Utf8Path::new("target/ferry/github"), true)?;
    ensure_provider_metadata_ignored(&git, &paths.config, reporter)?;

    let mut transport =
        GithubTransport::new(make_gh_runner(&root)?, TransportLimits::secure_defaults());
    let authenticated = transport.authenticate(&execution.repository).map_err(|error| {
        remote_error_with_details(
            "github_authentication_required",
            "GitHub authentication could not be verified",
            "Authenticate GitHub API access with `gh auth login` or GH_TOKEN, configure separate SSH or credential-manager Git authentication for temporary refs, then rerun setup.",
            vec![error.to_string()],
        )
    })?;
    let source_repository_info = transport.repository(&git.repository).map_err(|error| {
        remote_error_with_details(
            "github_source_repository_unavailable",
            "the exact public GitHub source repository could not be inspected",
            "Check source repository identity and token access, then rerun setup.",
            vec![error.to_string()],
        )
    })?;
    if source_repository_info.is_private() {
        return Err(remote_error(
            "private_source_repository",
            "the configured project source repository is not public",
            "Use a public GitHub repository for trusted project source; keep signing execution and secrets in the separate private execution repository.",
        ));
    }
    let worker_repository_info = if worker_repository == git.source_repository {
        source_repository_info.clone()
    } else {
        transport
            .repository(&worker_repository_identity)
            .map_err(|error| {
                remote_error_with_details(
                    "github_worker_repository_unavailable",
                    "the exact public GitHub worker source repository could not be inspected",
                    "Check worker repository identity and token access, then rerun setup.",
                    vec![error.to_string()],
                )
            })?
    };
    if worker_repository_info.is_private() {
        return Err(remote_error(
            "private_worker_repository",
            "the configured worker source repository is not public",
            "Use a public immutable RustFerry worker source repository; public workflow files must not expose a private repository identity.",
        ));
    }
    let repository_info = transport
        .repository(&execution.repository)
        .map_err(|error| {
            remote_error_with_details(
                "github_repository_unavailable",
                "the exact GitHub execution repository could not be inspected",
                "Check execution repository identity and token access, then rerun setup.",
                vec![error.to_string()],
            )
        })?;
    if repository_info.is_archived() || repository_info.is_disabled() {
        return Err(remote_error(
            "github_repository_read_only",
            "the configured GitHub execution repository cannot run new builds",
            "Use an active, non-archived GitHub execution repository.",
        ));
    }
    if stored.signing.is_some() && !repository_info.is_private() {
        return Err(remote_error(
            "public_signing_repository",
            "signed iPhone artifacts cannot be published through a public GitHub repository",
            "Configure a private GitHub execution repository before installing the protected signing workflow.",
        ));
    }
    let setup_warnings = selected_environment_token().map_or_else(Vec::new, |(_, name)| {
        vec![format!(
            "{name} authenticates GitHub API calls only. Temporary-ref publication separately requires existing SSH or credential-manager Git authentication; `cargo ferry remote doctor github` verifies it before mutation."
        )]
    });

    let workflow_state = preflight_file(&paths.workflow, generated.yaml().as_bytes(), false)?;
    let config_state = preflight_file(&paths.config, &config_bytes, true)?;
    let unchanged =
        workflow_state == ExistingFile::Identical && config_state == ExistingFile::Identical;
    let preview = dry_run || arguments.preview;
    if !preview {
        ensure_workflow_directory(&git.root)?;
        ensure_provider_directories(&root, &paths)?;
        let _config_lock = acquire_provider_config_lock(&root, &paths.config_lock)?;
        write_create_only(&paths.workflow, generated.yaml().as_bytes(), false)?;
        write_create_only(&paths.config, &config_bytes, true)?;
    }

    let output = SetupOutput {
        source_repository: stored.source_repository.clone(),
        execution_repository: stored.repository.clone(),
        authenticated_as: authenticated.label().to_owned(),
        workflow: paths.workflow.to_string(),
        provider_config: paths.config.to_string(),
        trusted_source_ref: stored.trusted_source_ref.clone(),
        worker_revision: stored.worker_revision.clone(),
        signing_mode: configured_signing_mode(&stored),
        installed: !preview,
        unchanged,
        workflow_preview: preview.then(|| generated.yaml().to_owned()),
    };
    reporter.success(
        "remote-setup",
        &output,
        || {
            if preview {
                format!(
                    "GitHub remote setup preview\n\nPublic source:\n  {}\n\nExecution:\n  {}\n\nWorkflow:\n  {}\n\n{}",
                    output.source_repository,
                    output.execution_repository,
                    output.workflow,
                    output.workflow_preview.as_deref().unwrap_or_default()
                )
            } else if unchanged {
                format!(
                    "GitHub remote setup is unchanged\n\nWorkflow:\n  {}\n\nProvider config:\n  {}",
                    output.workflow, output.provider_config
                )
            } else {
                format!(
                    "✓ Installed GitHub remote build configuration\n\nWorkflow:\n  {}\n\nProvider config:\n  {}\n\nNext:\n  Commit and push the workflow to {}\n  cargo ferry remote doctor github",
                    output.workflow, output.provider_config, output.trusted_source_ref
                )
            }
        },
        &setup_warnings,
    );
    Ok(())
}

fn doctor(arguments: &RemoteDoctorArgs, reporter: &Reporter) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let stored = load_config(&root)?;
    let (git, execution) = git_context_from_stored(&root, &stored, reporter)?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    let provider = build_provider(&root, &git.root, &stored)?;
    let operation_id = format!("{}-doctor", operation_id());
    let report = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id,
                require_signing: stored.signing.is_some(),
            },
            CancellationToken::new(),
        ),
        "provider_doctor_failed",
        "the GitHub provider doctor could not complete",
    )?;
    ensure_doctor_ready(&report, stored.signing.is_some())?;
    let checks = report
        .checks
        .into_iter()
        .map(|mut check| {
            check.code = safe_public_text(&check.code);
            check.message = safe_public_text(&check.message);
            check.help = check.help.map(|help| safe_public_text(&help));
            check
        })
        .collect::<Vec<_>>();
    let warnings = checks
        .iter()
        .filter(|check| check.status == rustferry_remote::ProviderCheckStatus::Warning)
        .map(|check| check.message.clone())
        .collect::<Vec<_>>();
    let output = DoctorOutput {
        provider: safe_public_text(&report.provider),
        ready: report.ready,
        checks,
        signing_mode: configured_signing_mode(&stored),
    };
    reporter.success(
        "remote-doctor",
        &output,
        || {
            let checks = output
                .checks
                .iter()
                .map(|check| {
                    let marker = match check.status {
                        rustferry_remote::ProviderCheckStatus::Ready => "✓",
                        rustferry_remote::ProviderCheckStatus::Warning => "!",
                        rustferry_remote::ProviderCheckStatus::Error => "×",
                    };
                    format!("  {marker} {}: {}", check.code, check.message)
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("GitHub remote builder is ready\n\n{checks}")
        },
        &warnings,
    );
    Ok(())
}

pub(in crate::commands) fn ide_signing_readiness(
    project_binding: &ProjectFilesystemBinding,
) -> Result<IdeSigningReadiness, CliError> {
    map_ide_signing_readiness(signing_readiness_inner(project_binding))
}

fn map_ide_signing_readiness(
    readiness: Result<IdeSigningReadiness, CliError>,
) -> Result<IdeSigningReadiness, CliError> {
    readiness.map_err(|_| {
        remote_error(
            "ide_signing_readiness_unavailable",
            "GitHub signing readiness could not be established safely",
            "Run `cargo ferry remote doctor github` for operator diagnostics, then retry the IDE readiness check.",
        )
    })
}

pub(in crate::commands) fn github_signing_readiness(
    project_binding: &ProjectFilesystemBinding,
) -> Result<IdeSigningReadiness, CliError> {
    signing_readiness_inner(project_binding).map_err(|error| {
        remote_error(
            error.code(),
            "GitHub iPhone-signing readiness could not be established safely",
            "Verify the exact project and GitHub remote configuration, then retry the signing doctor.",
        )
    })
}

fn signing_readiness_inner(
    project_binding: &ProjectFilesystemBinding,
) -> Result<IdeSigningReadiness, CliError> {
    project_binding.verify()?;
    let root = project_binding.root();
    let stored = load_config(root)?;
    let local_checks = local_signing_readiness_checks(root, &stored)?;
    let reporter = Reporter::new(false, true, false);
    let (git, execution) = git_context_from_stored(root, &stored, &reporter)?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    let provider = build_provider(root, &git.root, &stored)?;
    let report = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: format!("{}-ide-signing-doctor", operation_id()),
                require_signing: true,
            },
            CancellationToken::new(),
        ),
        "provider_doctor_failed",
        "the GitHub provider doctor could not complete",
    )?;
    project_binding.verify()?;
    Ok(signing_readiness_from_report(local_checks, report))
}

fn signing_readiness_from_report(
    local_checks: Vec<IdeSigningReadinessCheck>,
    report: rustferry_remote::ProviderDoctorReport,
) -> IdeSigningReadiness {
    let reviewer_check_present = report
        .checks
        .iter()
        .any(|check| check.code == "github.signing_environment.reviewers");
    let mut checks = Vec::with_capacity(
        report
            .checks
            .len()
            .saturating_add(local_checks.len())
            .saturating_add(1),
    );
    checks.extend(report.checks.into_iter().map(|check| {
        let reviewer_gate = check.code == "github.signing_environment.reviewers";
        let ready = check.status == rustferry_remote::ProviderCheckStatus::Ready;
        IdeSigningReadinessCheck {
            code: safe_ide_readiness_code(&check.code),
            required: reviewer_gate
                || check.status != rustferry_remote::ProviderCheckStatus::Warning,
            ready,
            reason_code: (!ready).then_some(if reviewer_gate {
                "required_reviewer_gate_unproven"
            } else if check.status == rustferry_remote::ProviderCheckStatus::Warning {
                "optional_provider_check_degraded"
            } else {
                "required_provider_check_failed"
            }),
        }
    }));
    if !reviewer_check_present {
        checks.push(readiness_check(
            "github.signing_environment.reviewers",
            false,
            "required_reviewer_gate_unproven",
        ));
    }
    checks.extend(local_checks);
    let ready = checks.iter().all(|check| !check.required || check.ready);
    IdeSigningReadiness { ready, checks }
}

fn local_signing_readiness_checks(
    root: &Utf8Path,
    stored: &StoredGithubConfig,
) -> Result<Vec<IdeSigningReadinessCheck>, CliError> {
    let signing_configured = stored.signing.is_some();
    let ferry_config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    let cargo_targets = super::platform_build::read_cargo_targets(root)?;
    let current_targets = unsigned_signing_plan(&ferry_config, cargo_targets.binary())?.targets;
    let target_graph_ready = current_targets == stored.signing_targets;
    let secret_names =
        SigningSecretNames::for_targets(&stored.signing_targets).map_err(|error| {
            remote_error_with_details(
                "invalid_signing_target_secret_map",
                "the configured signing target graph cannot form its static secret-name map",
                "Rerun GitHub remote setup from the unchanged project target graph.",
                vec![error.to_string()],
            )
        })?;
    let public_metadata_only = stored
        .signing
        .as_ref()
        .is_none_or(signing_reference_kinds_are_github_actions);
    let team_ready = stored
        .signing
        .as_ref()
        .and_then(|plan| plan.team.as_ref())
        .is_some();
    let profile_map_ready = stored
        .signing
        .as_ref()
        .is_some_and(|plan| signing_reference_names_match(plan, &secret_names));
    let workflow = workflow_from_stored(stored)?;
    let namespace_prefix = format!(
        "refs/heads/{}/",
        workflow.temporary_branch_namespace().as_str()
    );
    let namespace_ready = workflow.temporary_branch_namespace().as_str()
        == stored.temporary_namespace
        && !workflow
            .trusted_source_ref()
            .as_str()
            .starts_with(&namespace_prefix);
    let generated = generate_workflow(&workflow);
    let (compile_secret_isolated, signing_source_absent) =
        signing_workflow_phase_policy(generated.yaml());

    Ok(vec![
        readiness_check(
            "github_actions_ios_signing.configured",
            signing_configured,
            "signing_not_configured",
        ),
        readiness_check(
            "github.signing_config.public_metadata_only",
            public_metadata_only,
            "signing_config_contains_unsupported_reference",
        ),
        readiness_check(
            "github.signing_team",
            team_ready,
            "signing_team_not_configured",
        ),
        readiness_check(
            "github.signing_target_graph",
            target_graph_ready,
            "signing_target_graph_changed",
        ),
        readiness_check(
            "github.signing_profile_map",
            profile_map_ready,
            "signing_profile_map_not_configured",
        ),
        readiness_check(
            "github.temporary_ref_namespace",
            namespace_ready,
            "temporary_ref_namespace_invalid",
        ),
        readiness_check(
            "github.workflow.phase_a_secret_isolation",
            compile_secret_isolated,
            "phase_a_secret_isolation_unproven",
        ),
        readiness_check(
            "github.workflow.phase_b_no_source_execution",
            signing_source_absent,
            "phase_b_source_isolation_unproven",
        ),
    ])
}

fn readiness_check(
    code: &'static str,
    ready: bool,
    failure_reason: &'static str,
) -> IdeSigningReadinessCheck {
    IdeSigningReadinessCheck {
        code: code.to_owned(),
        required: true,
        ready,
        reason_code: (!ready).then_some(failure_reason),
    }
}

fn signing_reference_kinds_are_github_actions(plan: &SigningPlan) -> bool {
    plan.signing.as_ref().is_some_and(|signing| {
        signing.identity.private_key.reference.kind()
            == rustferry_remote::SecretReferenceKind::GithubActions
            && signing.password.as_ref().is_some_and(|reference| {
                reference.kind() == rustferry_remote::SecretReferenceKind::GithubActions
            })
    }) && plan.provisioning.iter().all(|provisioning| {
        provisioning.profile.kind() == rustferry_remote::SecretReferenceKind::GithubActions
    })
}

fn signing_reference_names_match(plan: &SigningPlan, names: &SigningSecretNames) -> bool {
    signing_reference_kinds_are_github_actions(plan)
        && plan.signing.as_ref().is_some_and(|signing| {
            signing.identity.private_key.reference.name() == names.certificate_p12().as_str()
                && signing.password.as_ref().is_some_and(|reference| {
                    reference.name() == names.certificate_password().as_str()
                })
        })
        && plan.provisioning.iter().all(|provisioning| {
            names
                .profile_for_target(&provisioning.target)
                .is_some_and(|name| provisioning.profile.name() == name.as_str())
        })
}

fn signing_workflow_phase_policy(yaml: &str) -> (bool, bool) {
    let Some((_, after_compile)) = yaml.split_once("  compile:\n") else {
        return (false, false);
    };
    let Some((compile, sign)) = after_compile.split_once("\n  sign:\n") else {
        return (false, false);
    };
    let compile_secret_isolated = !compile.contains("${{ secrets")
        && !compile.contains("RUSTFERRY_GOAL3_IOS_")
        && !compile
            .lines()
            .any(|line| line.starts_with("    environment:"));
    let signing_source_absent = [
        "actions/checkout@",
        "cargo ",
        "xcodebuild ",
        "codesign ",
        "security ",
        "pull_request",
    ]
    .iter()
    .all(|forbidden| !sign.contains(forbidden))
        && sign.contains("Verify sealed handoff digest before signing")
        && sign.contains("run-job \\\n")
        && sign.contains("--phase sign");
    (compile_secret_isolated, signing_source_absent)
}

fn safe_ide_readiness_code(code: &str) -> String {
    if !code.is_empty()
        && code.len() <= 128
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        code.to_owned()
    } else {
        "github.readiness.unknown".to_owned()
    }
}

fn status(arguments: &RemoteStatusArgs, reporter: &Reporter) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = arguments.provider;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let stored = load_config(&root)?;
    let (git, execution) = git_context_from_stored(&root, &stored, reporter)?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    let generated = generate_workflow(&workflow_from_stored(&stored)?);
    let paths = GithubPaths::new(&root, &git.root);
    reject_linked_components(&git.root, Utf8Path::new(".github/workflows"), true)?;
    let workflow_matches = existing_file_matches(&paths.workflow, generated.yaml().as_bytes())?;
    let output = StatusOutput {
        source_repository: stored.source_repository.clone(),
        execution_repository: stored.repository.clone(),
        provider_config: paths.config.to_string(),
        workflow: paths.workflow.to_string(),
        workflow_matches,
        trusted_source_ref: stored.trusted_source_ref.clone(),
        worker_revision: stored.worker_revision.clone(),
        signing_mode: configured_signing_mode(&stored),
    };
    reporter.success(
        "remote-status",
        &output,
        || {
            format!(
                "GitHub remote configuration\n\nPublic source:\n  {}\n\nExecution:\n  {}\n\nWorkflow exact:\n  {}\n\nTrusted ref:\n  {}\n\nSigning:\n  {}",
                output.source_repository,
                output.execution_repository,
                if output.workflow_matches { "yes" } else { "no" },
                output.trusted_source_ref,
                output.signing_mode
            )
        },
        &[],
    );
    Ok(())
}

fn select_signing_plan(
    stored: &StoredGithubConfig,
    ferry_config: &rustferry_core::FerryConfig,
    binary_name: &str,
    expected_team: Option<&str>,
    unsigned: bool,
) -> Result<SigningPlan, CliError> {
    if unsigned {
        if expected_team.is_some() {
            return Err(remote_error(
                "team_forbidden_for_unsigned",
                "--team cannot be combined with an unsigned compile-only build",
                "Remove `--team`, or remove `--unsigned` and configure manual-development signing.",
            ));
        }
        return unsigned_signing_plan(ferry_config, binary_name);
    }
    let plan = stored.signing.clone().ok_or_else(|| {
        remote_error(
            "signing_not_configured",
            "manual-development signing is not configured for the GitHub provider",
            "Run `cargo ferry signing setup manual --certificate <development.p12> --profile <app.mobileprovision> --remote github`, or pass `--unsigned` for a non-installable smoke build.",
        )
    })?;
    validate_github_signing_plan(&plan)?;
    let current_targets = unsigned_signing_plan(ferry_config, binary_name)?.targets;
    if plan.targets != current_targets
        || (!stored.signing_targets.is_empty() && stored.signing_targets != current_targets)
    {
        return Err(remote_error(
            "signing_target_graph_changed",
            "the current project target graph differs from the configured signing plan and workflow",
            "Rerun GitHub remote setup and manual signing setup after reviewing the exact changed targets.",
        ));
    }
    if let Some(expected_team) = expected_team
        && plan.team.as_ref().map(|team| team.expected.id()) != Some(expected_team)
    {
        return Err(remote_error(
            "signing_team_mismatch",
            "--team does not match the configured signing plan",
            "Use the configured Apple Team ID, or create a new validated public signing plan.",
        ));
    }
    Ok(plan)
}

pub(super) fn unsigned_signing_plan(
    ferry_config: &rustferry_core::FerryConfig,
    binary_name: &str,
) -> Result<SigningPlan, CliError> {
    let product =
        rustferry_apple::derive_ios_device_product_expectation(ferry_config, binary_name)?;
    let mut targets = vec![SigningTarget {
        name: binary_name.to_owned(),
        bundle_identifier: BundleIdentifier::new(ferry_config.app.identifier.clone()).map_err(
            |error| {
                remote_error_with_details(
                    "invalid_signing_target",
                    "the application signing target is invalid",
                    "Correct the application identifier in ferry.toml.",
                    vec![error.to_string()],
                )
            },
        )?,
        kind: SigningTargetKind::Application,
    }];
    for nested in product.nested_bundles {
        targets.push(SigningTarget {
            name: nested.executable,
            bundle_identifier: BundleIdentifier::new(nested.bundle_identifier).map_err(
                |error| {
                    remote_error_with_details(
                        "invalid_signing_target",
                        "a generated nested signing target is invalid",
                        "Validate the iOS extension configuration in ferry.toml.",
                        vec![error.to_string()],
                    )
                },
            )?,
            kind: match nested.kind {
                UnsignedNestedBundleKind::AppExtension => SigningTargetKind::Extension,
                UnsignedNestedBundleKind::Framework => SigningTargetKind::Framework,
            },
        });
    }
    let plan = SigningPlan {
        mode: SigningMode::UnsignedCompileOnly,
        signing: None,
        team: None,
        device: None,
        targets,
        provisioning: Vec::new(),
        entitlements: Vec::new(),
        allow_provisioning_updates: false,
    };
    plan.validate().map_err(|error| {
        remote_error_with_details(
            "invalid_unsigned_signing_plan",
            "the generated unsigned target graph is invalid",
            "Validate the application and extension bundle identifiers.",
            vec![error.to_string()],
        )
    })?;
    Ok(plan)
}

fn validate_github_signing_plan(plan: &SigningPlan) -> Result<(), CliError> {
    plan.validate().map_err(|error| {
        remote_error_with_details(
            "invalid_signing_plan",
            "the public GitHub signing plan is invalid",
            "Regenerate the plan with exact certificate, team, hashed device, target, profile, and entitlement metadata.",
            vec![error.to_string()],
        )
    })?;
    if plan.mode != SigningMode::ManualDevelopment {
        return Err(remote_error(
            "unsupported_signing_mode",
            "stored GitHub signing must use manual-development mode",
            "Use manual-development signing references, or omit the plan and pass `--unsigned` for smoke builds.",
        ));
    }
    if plan.provisioning.is_empty() || plan.provisioning.len() > MAX_SIGNING_PROFILES {
        return Err(remote_error(
            "unsupported_signing_target_graph",
            "the GitHub manual-signing worker accepts at most the app, Widget, and Live Activity profiles",
            "Use the exact generated target graph with no more than three profile-bearing targets.",
        ));
    }
    let names = SigningSecretNames::for_targets(&plan.targets).map_err(|error| {
        remote_error_with_details(
            "unsupported_signing_target_graph",
            "the signing target graph cannot form an exact protected-secret map",
            "Regenerate the target graph and GitHub provider configuration.",
            vec![error.to_string()],
        )
    })?;
    if plan.signing.is_none() {
        return Err(remote_error(
            "invalid_signing_plan",
            "the public signing plan has no certificate reference",
            "Regenerate the manual-development signing plan.",
        ));
    }
    if !signing_reference_names_match(plan, &names) {
        return Err(remote_error(
            "signing_secret_reference_mismatch",
            "the signing plan does not use the configured protected GitHub secret names",
            "Regenerate the exact certificate, password, and per-target profile references from the installed GitHub target map.",
        ));
    }
    Ok(())
}

fn source_manifest(
    project_root: &Utf8Path,
    git: &GitContext,
    reporter: &Reporter,
) -> Result<SourceManifest, CliError> {
    let cargo = executable("cargo")?;
    let output = checked_output(
        &cargo,
        &[
            OsString::from("metadata"),
            OsString::from("--format-version"),
            OsString::from("1"),
            OsString::from("--locked"),
        ],
        project_root,
        "read Cargo metadata",
        reporter,
    )?;
    let metadata = serde_json::from_slice::<CargoMetadata>(&output).map_err(|_| {
        remote_error(
            "invalid_cargo_metadata",
            "Cargo returned malformed or unsupported project metadata",
            "Run `cargo metadata --format-version 1 --locked` and correct the manifest error.",
        )
    })?;
    let mut request = SourceBundleRequest::new(&git.root, project_root);
    let mut included = HashSet::new();
    for package in metadata
        .packages
        .into_iter()
        .filter(|package| package.source.is_none())
    {
        let Some(parent) = package.manifest_path.parent() else {
            return Err(remote_error(
                "invalid_local_dependency",
                "a local Cargo package manifest has no parent directory",
                "Correct the local package manifest path.",
            ));
        };
        let canonical = parent.canonicalize_utf8().map_err(|source| CliError::Io {
            action: "resolve local Cargo package",
            path: parent.to_owned(),
            source,
        })?;
        let relative = canonical.strip_prefix(&git.root).map_err(|_| {
            remote_error(
                "local_dependency_outside_repository",
                "a local Cargo path dependency is outside the Git repository",
                "Move the dependency inside the repository, publish it, or use a future explicit snapshot provider.",
            )
        })?;
        if relative.as_str().is_empty() || relative == Utf8Path::new(".") {
            if canonical != project_root {
                return Err(remote_error(
                    "repository_root_dependency_unsupported",
                    "a nested RustFerry project depends on a Cargo package rooted at the repository root",
                    "Move the shared package into a named repository subdirectory, or place the RustFerry project at the repository root so its complete source can be selected safely.",
                ));
            }
            continue;
        }
        if relative != project_root.strip_prefix(&git.root).unwrap_or(project_root)
            && included.insert(relative.to_owned())
        {
            request = request.include_workspace_path(relative.to_owned());
        }
    }
    let plan = plan_source_bundle(&request).map_err(|error| {
        remote_error_with_details(
            "source_manifest_failed",
            "the deterministic project source manifest could not be created",
            "Remove unsafe links or sensitive paths and ensure all local dependencies are inside the Git repository.",
            vec![error.to_string()],
        )
    })?;
    Ok(plan.manifest().clone())
}

fn git_context(
    project_root: &Utf8Path,
    remote_name: &str,
    reporter: &Reporter,
) -> Result<GitContext, CliError> {
    let caller_git = CallerGitRepository::open(project_root).map_err(caller_git_policy_error)?;
    let (root, revision) = git_repository_state(&caller_git, reporter)?;
    let remote = git_remote_context(&caller_git, remote_name, reporter)?;
    Ok(GitContext {
        caller_git,
        root,
        repository: remote.repository,
        repository_slug: remote.repository_slug,
        source_repository: remote.source_repository,
        fetch_endpoint: remote.fetch_endpoint,
        push_endpoint: remote.push_endpoint,
        revision,
    })
}

fn git_repository_state(
    caller_git: &CallerGitRepository,
    reporter: &Reporter,
) -> Result<(Utf8PathBuf, String), CliError> {
    reporter.verbose("git (sealed offline reader) rev-parse --verify HEAD");
    let root =
        Utf8PathBuf::from_path_buf(caller_git.root().to_owned()).map_err(CliError::NonUtf8Path)?;
    let output =
        checked_caller_git_output(caller_git.head_revision(), "resolve exact Git revision")?;
    let revision = utf8_line(&output, "Git revision")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(remote_error(
            "invalid_git_revision",
            "Git did not return an exact lowercase 40-hex commit revision",
            "Commit the project in a SHA-1 Git repository before using the GitHub provider.",
        ));
    }
    Ok((root, revision))
}

fn git_remote_context(
    caller_git: &CallerGitRepository,
    remote_name: &str,
    reporter: &Reporter,
) -> Result<GitRemoteContext, CliError> {
    validate_git_remote_name(remote_name)?;
    reporter.verbose(format!(
        "git (sealed offline reader) config --local --no-includes remote.{remote_name}"
    ));
    let snapshot = caller_git.discover_remote(remote_name).map_err(|error| {
        remote_error_with_details(
            "git_remote_discovery_failed",
            "the selected local Git remote could not be captured safely",
            "Configure exactly one local URL and at most one push URL for the selected GitHub remote, without includes or rewrites.",
            vec![error.to_string()],
        )
    })?;
    let repository = snapshot.fetch().repository().clone();
    let repository_slug = snapshot.fetch().repository_slug();
    let source_repository = format!("https://github.com/{repository_slug}");
    Ok(GitRemoteContext {
        repository,
        repository_slug,
        source_repository,
        fetch_endpoint: snapshot.fetch().clone(),
        push_endpoint: snapshot.push().clone(),
    })
}

fn stored_remote_snapshot(
    fetch: &GithubGitEndpoint,
    push: &GithubGitEndpoint,
) -> Result<GithubRemoteSnapshot, CliError> {
    GithubRemoteSnapshot::new(fetch.clone(), push.clone()).map_err(|_| {
        remote_error(
            "invalid_provider_config",
            "the stored Git fetch and push endpoints identify different repositories",
            "Remove the generated provider config and rerun GitHub setup.",
        )
    })
}

fn validate_execution_endpoint_transports(
    fetch: &GithubGitEndpoint,
    push: &GithubGitEndpoint,
) -> Result<(), CliError> {
    if fetch.repository() != push.repository() {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored Git fetch and push endpoints identify different repositories",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
    #[cfg(unix)]
    if fetch.transport() != GithubGitTransport::Ssh || push.transport() != GithubGitTransport::Ssh {
        return Err(remote_error(
            "secure_git_execution_transport_unsupported",
            "secure GitHub execution fetch and push require SSH on this platform",
            "Configure both execution remote fetch and push URLs as git@github.com:owner/repository, then rerun setup.",
        ));
    }
    Ok(())
}

fn git_context_from_stored(
    project_root: &Utf8Path,
    stored: &StoredGithubConfig,
    reporter: &Reporter,
) -> Result<(GitContext, GitRemoteContext), CliError> {
    let caller_git = CallerGitRepository::open(project_root).map_err(caller_git_policy_error)?;
    let (root, revision) = git_repository_state(&caller_git, reporter)?;
    let source =
        stored_remote_snapshot(&stored.source_fetch_endpoint, &stored.source_push_endpoint)?;
    let execution = stored_remote_snapshot(
        &stored.execution_fetch_endpoint,
        &stored.execution_push_endpoint,
    )?;
    let source_slug = source.fetch().repository_slug();
    let execution_slug = execution.fetch().repository_slug();
    let git = GitContext {
        caller_git,
        root,
        repository: source.fetch().repository().clone(),
        repository_slug: source_slug.clone(),
        source_repository: format!("https://github.com/{source_slug}"),
        fetch_endpoint: source.fetch().clone(),
        push_endpoint: source.push().clone(),
        revision,
    };
    let execution = GitRemoteContext {
        repository: execution.fetch().repository().clone(),
        repository_slug: execution_slug.clone(),
        source_repository: format!("https://github.com/{execution_slug}"),
        fetch_endpoint: execution.fetch().clone(),
        push_endpoint: execution.push().clone(),
    };
    Ok((git, execution))
}

fn require_secure_git_publication_platform() -> Result<(), CliError> {
    if !cfg!(any(unix, windows)) {
        return Err(remote_error(
            "secure_git_platform_unsupported",
            "secure GitHub ref publication is unsupported on this platform",
            "Run GitHub setup and publication on a supported Unix or Windows installation.",
        ));
    }
    Ok(())
}

fn validate_git_remote_name(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(remote_error(
            "invalid_git_remote_name",
            "the selected Git remote name is invalid",
            "Use a 1-64 character Git remote name containing only letters, digits, dot, underscore, or hyphen.",
        ));
    }
    Ok(())
}

fn ensure_clean(git: &GitContext, reporter: &Reporter) -> Result<(), CliError> {
    reporter.verbose("git (sealed offline reader) status --porcelain=v1");
    let output = checked_caller_git_output(
        git.caller_git.working_tree_status(),
        "inspect Git working tree",
    )?;
    if output.is_empty() {
        Ok(())
    } else {
        Err(remote_error(
            "dirty_working_tree",
            "your working tree contains uncommitted changes",
            "Commit and push the intended source, or cancel. Explicit GitHub snapshot mode is not implemented by this thin client and is never selected automatically.",
        ))
    }
}

fn ensure_clean_revision(git: &GitContext, reporter: &Reporter) -> Result<(), CliError> {
    ensure_clean(git, reporter)?;
    reporter.verbose("git (sealed offline reader) rev-parse --verify HEAD");
    let output =
        checked_caller_git_output(git.caller_git.head_revision(), "recheck exact Git revision")?;
    let current = utf8_line(&output, "Git revision")?;
    if current == git.revision {
        Ok(())
    } else {
        Err(remote_error(
            "source_changed_during_planning",
            "the Git revision changed while the remote build request was being planned",
            "Rerun the build from a stable, clean working tree.",
        ))
    }
}

#[derive(Clone, Debug)]
struct GitTreeBlob {
    object_id: String,
    size: u64,
    executable: bool,
}

fn bind_manifest_to_revision(
    git: &GitContext,
    manifest: &mut SourceManifest,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let tree = git_tree_blobs(git, &manifest.entries, reporter)?;
    let limits = SourceLimits::default();
    let mut unique_blobs = BTreeMap::new();
    let mut exact_total_size = 0_u64;
    for entry in &manifest.entries {
        let blob = tree.get(&entry.path).ok_or_else(|| {
            remote_error_with_details(
                "source_not_committed",
                "the deterministic source manifest includes a file absent from the exact Git revision",
                "Commit every required project, workspace, and local path-dependency file, or exclude non-source files with .ferryignore.",
                vec![format!("path={}", entry.path)],
            )
        })?;
        exact_total_size = exact_total_size.checked_add(blob.size).ok_or_else(|| {
            remote_error(
                "source_manifest_failed",
                "the exact-revision source size overflowed",
                "Reduce the selected source tree and retry.",
            )
        })?;
        if blob.size > limits.max_file_size || exact_total_size > limits.max_total_size {
            return Err(remote_error_with_details(
                "source_limit_exceeded",
                "the exact Git revision exceeds the remote source size limits",
                "Reduce committed source inputs or exclude non-source files with .ferryignore.",
                vec![format!("path={}", entry.path)],
            ));
        }
        unique_blobs
            .entry(blob.object_id.clone())
            .or_insert(blob.size);
    }
    let digests = hash_git_blobs(git, &unique_blobs, reporter)?;
    for entry in &mut manifest.entries {
        let blob = &tree[&entry.path];
        entry.size = blob.size;
        entry.sha256 = digests[&blob.object_id].clone();
        entry.executable = blob.executable;
    }
    manifest.total_size = exact_total_size;
    manifest.sha256 = source_manifest_digest(
        &manifest.project_path,
        &manifest.entries,
        manifest.total_size,
    );
    validate_source_manifest(manifest, limits).map_err(|error| {
        remote_error_with_details(
            "source_manifest_failed",
            "the exact Git revision produced an invalid source manifest",
            "Commit a portable, bounded source tree and retry.",
            vec![error.to_string()],
        )
    })
}

fn git_tree_blobs(
    git: &GitContext,
    entries: &[SourceManifestEntry],
    reporter: &Reporter,
) -> Result<BTreeMap<String, GitTreeBlob>, CliError> {
    let mut tree = BTreeMap::new();
    let mut start = 0;
    while start < entries.len() {
        let mut end = start;
        let mut argument_bytes: usize = 0;
        while end < entries.len()
            && end - start < GIT_BLOB_BATCH_COUNT
            && argument_bytes.saturating_add(entries[end].path.len() + 1)
                <= GIT_PATHSPEC_ARGUMENT_BYTES
        {
            argument_bytes += entries[end].path.len() + 1;
            end += 1;
        }
        if end == start {
            end += 1;
        }
        let paths = entries[start..end]
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        reporter.verbose("git (sealed offline reader) ls-tree");
        let output = checked_caller_git_output(
            git.caller_git.tree_entries(&git.revision, &paths),
            "read exact Git tree",
        )?;
        parse_git_tree(&output, &mut tree)?;
        start = end;
    }
    Ok(tree)
}

fn parse_git_tree(output: &[u8], tree: &mut BTreeMap<String, GitTreeBlob>) -> Result<(), CliError> {
    for record in output
        .split(|byte| *byte == b'\0')
        .filter(|row| !row.is_empty())
    {
        let record = std::str::from_utf8(record).map_err(|_| {
            remote_error(
                "invalid_git_tree",
                "Git returned a non-UTF-8 tree entry",
                "Use portable UTF-8 repository paths.",
            )
        })?;
        let (metadata, path) = record.split_once('\t').ok_or_else(|| {
            remote_error(
                "invalid_git_tree",
                "Git returned malformed tree metadata",
                "Inspect the exact source revision and retry.",
            )
        })?;
        let columns = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        let [mode, kind, object_id, size] = columns.as_slice() else {
            return Err(remote_error(
                "invalid_git_tree",
                "Git returned malformed tree columns",
                "Inspect the exact source revision and retry.",
            ));
        };
        if *kind != "blob" || !matches!(*mode, "100644" | "100755") {
            return Err(remote_error_with_details(
                "unsupported_git_entry",
                "the selected source contains a linked or unsupported Git entry",
                "Replace links and submodules with regular committed source files.",
                vec![format!("path={path}")],
            ));
        }
        if object_id.len() != 40
            || !object_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(remote_error(
                "invalid_git_tree",
                "Git returned an invalid blob identifier",
                "Use a SHA-1 Git repository for this provider.",
            ));
        }
        let size = size.parse::<u64>().map_err(|_| {
            remote_error(
                "invalid_git_tree",
                "Git returned an invalid blob size",
                "Inspect the exact source revision and retry.",
            )
        })?;
        if tree
            .insert(
                path.to_owned(),
                GitTreeBlob {
                    object_id: (*object_id).to_owned(),
                    size,
                    executable: *mode == "100755",
                },
            )
            .is_some()
        {
            return Err(remote_error(
                "invalid_git_tree",
                "Git returned a duplicate source path",
                "Inspect the exact source revision and retry.",
            ));
        }
    }
    Ok(())
}

fn hash_git_blobs(
    git: &GitContext,
    blobs: &BTreeMap<String, u64>,
    reporter: &Reporter,
) -> Result<BTreeMap<String, String>, CliError> {
    let all = blobs.iter().collect::<Vec<_>>();
    let mut digests = BTreeMap::new();
    let mut start = 0;
    while start < all.len() {
        let mut end = start;
        let mut batch_size = 0_u64;
        while end < all.len() && end - start < GIT_BLOB_BATCH_COUNT {
            let next = batch_size.saturating_add(*all[end].1);
            if end > start && next > GIT_BLOB_BATCH_BYTES {
                break;
            }
            batch_size = next;
            end += 1;
        }
        let batch = &all[start..end];
        let mut input = Vec::with_capacity(batch.len() * 41);
        for (object_id, _) in batch {
            input.extend_from_slice(object_id.as_bytes());
            input.push(b'\n');
        }
        let framing = batch.len().saturating_mul(128).saturating_add(1024);
        let output_limit = usize::try_from(batch_size)
            .ok()
            .and_then(|size| size.checked_add(framing))
            .ok_or_else(|| {
                remote_error(
                    "source_manifest_failed",
                    "the exact Git blob batch exceeded local limits",
                    "Reduce the selected source tree and retry.",
                )
            })?;
        reporter.verbose("git (sealed offline reader) cat-file --batch");
        let output = git
            .caller_git
            .blob_batch(&input, output_limit)
            .map_err(|_| caller_git_command_error("hash exact Git blobs", None))?;
        if !output.success() {
            return Err(remote_error(
                "git_blob_read_failed",
                "Git could not read the exact source blobs",
                "Verify the repository object database and retry.",
            ));
        }
        parse_git_blob_batch(output.stdout(), batch, &mut digests)?;
        start = end;
    }
    Ok(digests)
}

fn parse_git_blob_batch(
    output: &[u8],
    batch: &[(&String, &u64)],
    digests: &mut BTreeMap<String, String>,
) -> Result<(), CliError> {
    let mut cursor = 0;
    for (object_id, expected_size) in batch {
        let header_end = output[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| cursor + offset)
            .ok_or_else(invalid_git_blob_output)?;
        if header_end.saturating_sub(cursor) > 128 {
            return Err(invalid_git_blob_output());
        }
        let header = std::str::from_utf8(&output[cursor..header_end])
            .map_err(|_| invalid_git_blob_output())?;
        let expected_header = format!("{object_id} blob {expected_size}");
        if header != expected_header {
            return Err(invalid_git_blob_output());
        }
        let content_start = header_end + 1;
        let content_size =
            usize::try_from(**expected_size).map_err(|_| invalid_git_blob_output())?;
        let content_end = content_start
            .checked_add(content_size)
            .ok_or_else(invalid_git_blob_output)?;
        if output.get(content_end) != Some(&b'\n') {
            return Err(invalid_git_blob_output());
        }
        let content = output
            .get(content_start..content_end)
            .ok_or_else(invalid_git_blob_output)?;
        digests.insert((*object_id).clone(), sha256_bytes(content));
        cursor = content_end + 1;
    }
    if cursor != output.len() {
        return Err(invalid_git_blob_output());
    }
    Ok(())
}

fn invalid_git_blob_output() -> CliError {
    remote_error(
        "invalid_git_blob_output",
        "Git returned malformed exact-blob output",
        "Verify the repository object database and retry.",
    )
}

fn source_manifest_digest(
    project_path: &str,
    entries: &[SourceManifestEntry],
    total_size: u64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rustferry-source-manifest-v1\0");
    update_digest_string(&mut digest, project_path);
    digest.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        update_digest_string(&mut digest, &entry.path);
        digest.update(entry.size.to_be_bytes());
        update_digest_string(&mut digest, &entry.sha256);
        digest.update([u8::from(entry.executable)]);
    }
    digest.update(total_size.to_be_bytes());
    sha256_hex(digest.finalize())
}

fn update_digest_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn sha256_bytes(bytes: &[u8]) -> String {
    sha256_hex(Sha256::digest(bytes))
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn current_branch(git: &GitContext, reporter: &Reporter) -> Result<String, CliError> {
    reporter.verbose("git (sealed offline reader) symbolic-ref --short HEAD");
    let output = checked_caller_git_output(
        git.caller_git.current_branch(),
        "resolve trusted Git branch",
    )?;
    utf8_line(&output, "Git branch")
}

fn ensure_provider_metadata_ignored(
    git: &GitContext,
    config_path: &Utf8Path,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let relative = config_path.strip_prefix(&git.root).map_err(|_| {
        remote_error(
            "provider_config_outside_repository",
            "the project-local provider config is outside the Git repository",
            "Keep the RustFerry project inside its selected Git repository.",
        )
    })?;
    let pathspec = repository_relative_git_pathspec(relative)?;
    reporter.verbose("git (sealed offline reader) check-ignore");
    let output = git.caller_git.check_ignore(&pathspec).map_err(|_| {
        caller_git_command_error("verify private provider metadata is ignored", None)
    })?;
    match output.exit_code() {
        Some(0) => Ok(()),
        Some(1) => Err(remote_error_with_details(
            "provider_config_not_ignored",
            "the private project-local GitHub provider directory is not ignored by Git",
            "Add target/ (or this exact target/ferry/github path) to the repository ignore rules before setup; never commit provider metadata or caches.",
            vec![format!("path={pathspec}")],
        )),
        status => Err(CliError::CommandFailed {
            tool: "git".to_owned(),
            stage: "verify private provider metadata is ignored",
            status,
            stderr: String::new(),
            log: None,
            help: "Correct the Git repository configuration and retry setup.".to_owned(),
        }),
    }
}

fn repository_relative_git_pathspec(path: &Utf8Path) -> Result<String, CliError> {
    const MAX_GIT_PATHSPEC_BYTES: usize = 4_096;

    let invalid_path = || {
        remote_error(
            "invalid_provider_git_pathspec",
            "the repository-relative provider path cannot be represented as a safe Git pathspec",
            "Keep provider metadata under a normal repository-relative target/ferry path.",
        )
    };
    let raw = path.as_str();
    if raw.is_empty()
        || raw.chars().any(char::is_control)
        || raw
            .split(['/', '\\'])
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid_path());
    }

    let mut pathspec = String::new();
    for (index, component) in path.components().enumerate() {
        let Utf8Component::Normal(component) = component else {
            return Err(invalid_path());
        };
        if component.is_empty()
            || component.contains(['/', '\\'])
            || component.chars().any(char::is_control)
            || (index == 0 && component.starts_with('-'))
        {
            return Err(invalid_path());
        }
        let separator_bytes = usize::from(!pathspec.is_empty());
        if pathspec
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(component.len())
            > MAX_GIT_PATHSPEC_BYTES
        {
            return Err(invalid_path());
        }
        if separator_bytes != 0 {
            pathspec.push('/');
        }
        pathspec.push_str(component);
    }
    if pathspec.is_empty() {
        return Err(invalid_path());
    }
    Ok(pathspec)
}

fn parse_repository_spec(value: &str) -> Result<(Repository, String, String), CliError> {
    let trimmed = value.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = if let Some(path) = trimmed.strip_prefix("https://github.com/") {
        path
    } else if let Some(path) = trimmed.strip_prefix("git@github.com:") {
        path
    } else if let Some(path) = trimmed.strip_prefix("ssh://git@github.com/") {
        path
    } else if !trimmed.contains(':') && !trimmed.contains('@') {
        trimmed
    } else {
        return Err(remote_error(
            "unsupported_github_remote",
            "the selected Git remote is not a credential-free GitHub repository URL",
            "Use owner/repository, https://github.com/owner/repository, or git@github.com:owner/repository.",
        ));
    };
    if path.contains(['?', '#', '%']) {
        return Err(remote_error(
            "unsupported_github_remote",
            "the selected GitHub repository URL contains unsupported URL syntax",
            "Use a credential-free GitHub repository URL without a query, fragment, or percent escapes.",
        ));
    }
    let mut components = path.split('/');
    let owner = components.next().unwrap_or_default();
    let name = components.next().unwrap_or_default();
    if components.next().is_some() {
        return Err(remote_error(
            "unsupported_github_remote",
            "the selected GitHub repository URL has an invalid path",
            "Use exactly owner/repository.",
        ));
    }
    let owner = owner.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    let repository = Repository::new(owner.clone(), name.clone()).map_err(|error| {
        remote_error_with_details(
            "invalid_github_repository",
            "the selected GitHub owner or repository name is invalid",
            "Use an exact GitHub owner/repository identifier.",
            vec![error.to_string()],
        )
    })?;
    let slug = format!("{owner}/{name}");
    let source = format!("https://github.com/{slug}");
    Ok((repository, slug, source))
}

#[allow(
    clippy::too_many_lines,
    reason = "provider restoration keeps every persisted identity and endpoint binding explicit"
)]
fn build_provider(
    project_root: &Utf8Path,
    repository_root: &Utf8Path,
    stored: &StoredGithubConfig,
) -> Result<GithubProvider, CliError> {
    validate_stored_config(stored)?;
    let paths = GithubPaths::new(project_root, repository_root);
    reject_linked_components(project_root, Utf8Path::new(CACHE_RELATIVE_PATH), false)?;
    reject_linked_components(
        project_root,
        Utf8Path::new(GIT_ISOLATION_RELATIVE_PATH),
        false,
    )?;
    require_private_directory(&paths.cache, "GitHub artifact cache")?;
    require_private_directory(&paths.git_isolation, "Git publisher isolation")?;
    let (repository, _, _) = parse_repository_spec(&stored.repository)?;
    let workflow = workflow_from_stored(stored)?;
    let generated = generate_workflow(&workflow);
    let fingerprint = WorkflowFingerprint::for_workflow(&generated);
    let worker_version = Version::parse(&stored.worker_version).map_err(|error| {
        remote_error_with_details(
            "invalid_worker_version",
            "the configured worker version is invalid",
            "Rerun GitHub setup with a canonical semantic version.",
            vec![error.to_string()],
        )
    })?;
    let source_endpoints =
        stored_remote_snapshot(&stored.source_fetch_endpoint, &stored.source_push_endpoint)?;
    let execution_endpoints = stored_remote_snapshot(
        &stored.execution_fetch_endpoint,
        &stored.execution_push_endpoint,
    )?;
    validate_execution_endpoint_transports(
        execution_endpoints.fetch(),
        execution_endpoints.push(),
    )?;
    let config = GithubProviderConfig::new(
        repository,
        stored.source_repository.clone(),
        workflow,
        fingerprint,
        GithubPollingPolicy::secure_defaults(),
        GithubMutationAuthorization {
            publish_temporary_ref: true,
            cancel_run: true,
            delete_temporary_ref: true,
            publish_git_snapshot_source: true,
            delete_git_snapshot_source: true,
            manage_git_snapshot_keepalive: true,
        },
        &worker_version,
        8,
    )
    .and_then(|config| {
        config.bind_git_endpoints(source_endpoints.clone(), execution_endpoints.clone())
    })
    .map_err(|error| {
        remote_error_with_details(
            "invalid_provider_config",
            "the stored GitHub provider configuration is invalid",
            "Remove the generated provider config and rerun GitHub setup.",
            vec![error.to_string()],
        )
    })?;
    let gh_runner = make_gh_runner(project_root)?;
    let transport = GithubTransport::new(gh_runner.clone(), TransportLimits::secure_defaults());
    let artifact_transport = GithubTransport::new(gh_runner, TransportLimits::secure_defaults());
    let artifact_store = GithubVerifiedArtifactStore::new(artifact_transport, &paths.cache)
        .map_err(|error| {
            remote_error_with_details(
                "artifact_store_invalid",
                "the private GitHub artifact cache is not usable",
                "Rerun GitHub setup and ensure the generated cache is a private, non-symlink directory.",
                vec![error.to_string()],
            )
        })?;
    let trusted_git = rustferry_github::git_process::trusted_git_executable().map_err(|error| {
        remote_error_with_details(
            "trusted_git_unavailable",
            "the standard trusted Git toolchain is unavailable",
            "Install the supported standard Git toolchain and retry.",
            vec![error.to_string()],
        )
    })?;
    let git_runner = GitProcessRunner::new(trusted_git, &paths.git_isolation).map_err(|error| {
            remote_error_with_details(
                "git_publisher_invalid",
                "the local Git publisher could not be configured",
                "Use the standard Git-for-Windows installation and the private generated publisher directory.",
                vec![error.to_string()],
            )
        })?;
    let publisher = GitTemporaryRefPublisher::new_with_endpoints(
        git_runner,
        &paths.git_isolation,
        &source_endpoints,
        &execution_endpoints,
        Duration::from_mins(2),
    )
    .map_err(|error| {
        remote_error_with_details(
            "git_publisher_invalid",
            "the temporary Git ref publisher could not be configured",
            "Rerun GitHub setup to capture canonical endpoints into a private generated directory.",
            vec![error.to_string()],
        )
    })?;
    Ok(GithubBuildProvider::with_artifact_store_and_clock(
        config,
        transport,
        publisher,
        artifact_store,
        SystemProviderClock,
    ))
}

fn handshake(
    provider: &GithubProvider,
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> Result<(), CliError> {
    handshake_with_source_mode(provider, SourceMode::Git, signing_mode, requested_artifacts)
}

fn handshake_with_source_mode(
    provider: &GithubProvider,
    source_mode: SourceMode,
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> Result<(), CliError> {
    handshake_with_source_mode_cancellable(
        provider,
        source_mode,
        signing_mode,
        requested_artifacts,
        &CancellationToken::new(),
    )
}

fn handshake_with_source_mode_cancellable(
    provider: &GithubProvider,
    source_mode: SourceMode,
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
    cancellation: &CancellationToken,
) -> Result<(), CliError> {
    let required_features =
        required_build_features_for_source(source_mode, signing_mode, requested_artifacts);
    provider_call(
        provider.handshake(
            HandshakeRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("cargo package version is semantic version syntax"),
                required_features,
            },
            cancellation.clone(),
        ),
        "provider_handshake_failed",
        "the GitHub worker/provider contract is incompatible with this client",
    )?;
    Ok(())
}

fn required_build_features_for_source(
    source_mode: SourceMode,
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> Vec<ProviderFeature> {
    let mut required_features = vec![
        ProviderFeature::SourceMode(source_mode),
        ProviderFeature::IosDeviceBuild,
        ProviderFeature::SigningMode(signing_mode),
        ProviderFeature::LiveEvents,
        ProviderFeature::Cancellation,
        ProviderFeature::ArtifactListing,
        ProviderFeature::ArtifactDownload,
        ProviderFeature::Cleanup,
    ];
    required_features.extend(
        requested_artifacts
            .iter()
            .copied()
            .map(ProviderFeature::ArtifactType),
    );
    required_features
}

#[derive(Debug)]
struct JobTerminal {
    state: JobState,
    diagnostics: Vec<String>,
}

fn unix_timestamp_ms() -> Result<u64, CliError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        remote_error(
            "system_clock_invalid",
            "the system clock is earlier than the Unix epoch",
            "Correct the system clock before creating a durable remote job.",
        )
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        remote_error(
            "system_clock_invalid",
            "the system clock cannot be represented by the durable job schema",
            "Correct the system clock before creating a durable remote job.",
        )
    })
}

fn update_stored_job(
    store: &JobStore,
    local_job_id: &LocalJobId,
    update: impl FnOnce(&StoredJobV1, &mut StoredJobV1) -> Result<(), JobStoreError>,
) -> Result<(), CliError> {
    let timestamp_ms = unix_timestamp_ms()?;
    store.update(local_job_id, |previous| {
        let mut next = previous.clone();
        next.revision = previous
            .revision
            .checked_add(1)
            .ok_or(JobStoreError::InvalidRecord {
                reason: "job revision cannot advance beyond the supported range",
            })?;
        next.updated_at_ms = previous.updated_at_ms.max(timestamp_ms);
        update(previous, &mut next)?;
        Ok(next)
    })?;
    Ok(())
}

fn require_bound_provider_job(
    store: &JobStore,
    local_job_id: &LocalJobId,
    provider_job_id: &str,
    run_trigger: WorkflowRunTrigger,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.provider_job_id.as_deref() != Some(provider_job_id)
        || latest
            .provider_resume
            .as_ref()
            .is_none_or(|resume| !provider_resume_is_bound(resume, provider_job_id, run_trigger))
    {
        return Err(remote_error(
            "provider_checkpoint_missing",
            "the accepted GitHub job is missing its durable resume checkpoint",
            "Preserve the local job ID and inspect its immutable revisions before retrying.",
        ));
    }
    Ok(())
}

fn provider_resume_is_bound(
    resume: &rustferry_github::provider::GithubJobResumeV1,
    provider_job_id: &str,
    run_trigger: WorkflowRunTrigger,
) -> bool {
    resume.job_id == provider_job_id
        && resume.dispatch_commit.is_some()
        && !resume.publication_uncertain
        && !resume.publication_absent
        && !resume.publication_not_attempted
        && resume.validate_trigger_binding().is_ok()
        && match run_trigger {
            WorkflowRunTrigger::Push => resume.workflow_dispatch.is_none(),
            WorkflowRunTrigger::WorkflowDispatch => resume
                .workflow_dispatch
                .as_ref()
                .is_some_and(|dispatch| dispatch.receipt.is_some() && resume.run.is_some()),
        }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubmitPublicationEvidence {
    Mapped,
    Absent,
    Conflict,
    Pending,
}

fn submit_publication_evidence(
    resume: &rustferry_github::provider::GithubJobResumeV1,
    provider_job_id: &str,
    run_trigger: WorkflowRunTrigger,
) -> SubmitPublicationEvidence {
    if resume.job_id != provider_job_id {
        return SubmitPublicationEvidence::Pending;
    }
    if resume.dispatch_commit.is_some()
        && !resume.publication_uncertain
        && !resume.publication_absent
        && !resume.publication_not_attempted
        && resume.validate_trigger_binding().is_ok()
        && match run_trigger {
            WorkflowRunTrigger::Push => resume.workflow_dispatch.is_none(),
            WorkflowRunTrigger::WorkflowDispatch => {
                resume
                    .workflow_dispatch
                    .as_ref()
                    .is_some_and(|dispatch| dispatch.receipt.is_some())
                    && resume.run.is_some()
            }
        }
    {
        return SubmitPublicationEvidence::Mapped;
    }
    if resume.publication_not_attempted
        || resume.publication_absent
            && resume.publication_absence_observations >= 2
            && resume.publication_process_fenced
            && resume.temporary_ref_deleted
    {
        return SubmitPublicationEvidence::Absent;
    }
    if resume.state == JobState::Failed
        && resume.dispatch_commit.is_none()
        && resume.publication_uncertain
        && !resume.publication_absent
        && !resume.publication_not_attempted
        && resume.publication_process_fenced
        && resume.publication_absence_first_observed_at_ms != 0
        && resume.publication_absence_observations >= 2
    {
        return SubmitPublicationEvidence::Conflict;
    }
    SubmitPublicationEvidence::Pending
}

fn reconcile_submit_publication_with_cancellation(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    provider_job_id: &str,
    cancellation: &CancellationToken,
) -> Result<SubmitPublicationEvidence, CliError> {
    let run_trigger = provider.workflow_run_trigger();
    let mut backoff = SUBMIT_RECONCILIATION_INITIAL_BACKOFF;
    let mut post_deadline_attempts = 0_u8;
    loop {
        let latest = store.latest(local_job_id)?;
        let resume = latest.provider_resume.as_ref().ok_or_else(|| {
            remote_error(
                "submit_reconciliation_checkpoint_missing",
                "the GitHub submission lost its durable reconciliation checkpoint",
                "Preserve the local job ID and reconcile its exact publication intent before retrying.",
            )
        })?;
        let evidence = submit_publication_evidence(resume, provider_job_id, run_trigger);
        if evidence != SubmitPublicationEvidence::Pending {
            return Ok(evidence);
        }
        if cancellation.is_cancelled() || rustferry_core::process_control::interrupt_requested() {
            return Err(CliError::CommandInterrupted {
                tool: "GitHub publication reconciliation".to_owned(),
                stage: "remote iPhone build",
            });
        }
        project_binding.verify()?;
        let reconciliation = provider.reconcile_restored_job(provider_job_id, cancellation);
        project_binding.verify()?;
        let reconciled = store.latest(local_job_id)?;
        let resume = reconciled.provider_resume.as_ref().ok_or_else(|| {
            remote_error(
                "submit_reconciliation_checkpoint_missing",
                "the GitHub submission lost its durable reconciliation checkpoint",
                "Preserve the local job ID and reconcile its exact publication intent before retrying.",
            )
        })?;
        let evidence = submit_publication_evidence(resume, provider_job_id, run_trigger);
        if evidence != SubmitPublicationEvidence::Pending {
            return Ok(evidence);
        }
        let retryable = match reconciliation {
            Ok(GithubJobReconciliation::Missing | GithubJobReconciliation::Conflict) => true,
            Ok(
                GithubJobReconciliation::NotStarted
                | GithubJobReconciliation::AlreadyMapped
                | GithubJobReconciliation::Recovered
                | GithubJobReconciliation::ConflictResolved,
            ) => false,
            Err(error) => error.retryable(),
        };
        if !retryable {
            return Ok(SubmitPublicationEvidence::Pending);
        }
        let now_ms = unix_timestamp_ms()?;
        if now_ms >= resume.publication_quiescence_deadline_ms {
            post_deadline_attempts = post_deadline_attempts.saturating_add(1);
            if post_deadline_attempts >= SUBMIT_RECONCILIATION_POST_DEADLINE_ATTEMPTS {
                return Ok(SubmitPublicationEvidence::Pending);
            }
            sleep_interruptibly_with_cancellation(
                SUBMIT_RECONCILIATION_INITIAL_BACKOFF,
                cancellation,
            );
            continue;
        }
        post_deadline_attempts = 0;
        let until_deadline = Duration::from_millis(
            resume
                .publication_quiescence_deadline_ms
                .saturating_sub(now_ms),
        );
        sleep_interruptibly_with_cancellation(backoff.min(until_deadline), cancellation);
        backoff = backoff
            .saturating_mul(2)
            .min(SUBMIT_RECONCILIATION_MAX_BACKOFF);
    }
}

fn reconcile_submit_attempt(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    provider_job_hint: Option<&str>,
    submit_error: Option<&rustferry_remote::RemoteBuildError>,
) -> Result<String, CliError> {
    reconcile_submit_attempt_with_cancellation(
        provider,
        store,
        local_job_id,
        project_binding,
        provider_job_hint,
        submit_error,
        &CancellationToken::new(),
    )
}

fn reconcile_submit_attempt_with_cancellation(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    provider_job_hint: Option<&str>,
    submit_error: Option<&rustferry_remote::RemoteBuildError>,
    cancellation: &CancellationToken,
) -> Result<String, CliError> {
    let latest = store.latest(local_job_id)?;
    let Some(resume) = latest.provider_resume.as_ref() else {
        if let Some(submit_error) = submit_error {
            persist_controller_failure(
                store,
                local_job_id,
                "controller.submit_failed_before_publication",
                submit_error.retryable(),
            )?;
            return Err(provider_failure(
                submit_error,
                "remote_submit_failed",
                "the GitHub provider did not accept the iPhone build",
            ));
        }
        persist_submit_uncertain(store, local_job_id)?;
        return Err(remote_error(
            "provider_checkpoint_missing",
            "the acknowledged GitHub job is missing its durable publication checkpoint",
            "Preserve the local job ID and reconcile the exact submission before retrying.",
        ));
    };
    let provider_job_id = resume.job_id.clone();
    if provider_job_hint.is_some_and(|hint| hint != provider_job_id) {
        persist_submit_uncertain(store, local_job_id)?;
        return Err(remote_error(
            "provider_job_identity_mismatch",
            "the acknowledged GitHub job differs from its durable publication checkpoint",
            "Preserve the local job ID and reconcile the exact provider job before retrying.",
        ));
    }
    let evidence = match reconcile_submit_publication_with_cancellation(
        provider,
        store,
        local_job_id,
        project_binding,
        &provider_job_id,
        cancellation,
    ) {
        Ok(evidence) => evidence,
        Err(error) => {
            persist_submit_uncertain(store, local_job_id)?;
            return Err(error);
        }
    };
    if evidence == SubmitPublicationEvidence::Mapped {
        return Ok(provider_job_id);
    }
    if evidence == SubmitPublicationEvidence::Absent {
        persist_controller_failure(
            store,
            local_job_id,
            "controller.submit_failed_without_publication",
            submit_error.is_some_and(rustferry_remote::RemoteBuildError::retryable),
        )?;
        return Err(submit_error.map_or_else(
            || {
                remote_error(
                    "remote_submit_not_published",
                    "the GitHub provider acknowledged a build whose exact publication is proven absent",
                    "Preserve the local job ID and retry with a new operation only after reviewing the durable absence proof.",
                )
            },
            |error| {
                provider_failure(
                    error,
                    "remote_submit_failed",
                    "the GitHub provider did not accept the iPhone build",
                )
            },
        ));
    }
    if evidence == SubmitPublicationEvidence::Conflict {
        return Err(remote_error_with_details(
            "remote_submit_conflict",
            "the GitHub submission resolved to a conflicting temporary ref without an exact matching run",
            "Preserve the local and provider job IDs; do not retry this operation or alter the conflicting ref automatically.",
            vec![
                format!("local_job_id={}", local_job_id.as_str()),
                format!("job_id={provider_job_id}"),
            ],
        ));
    }
    persist_submit_uncertain(store, local_job_id)?;
    Err(remote_error_with_details(
        "remote_submit_uncertain",
        "the GitHub submission outcome could not be reconciled to an exact publication or absence proof",
        "Preserve the local and provider job IDs; reconcile this exact publication intent before retrying.",
        vec![
            format!("local_job_id={}", local_job_id.as_str()),
            format!("job_id={provider_job_id}"),
        ],
    ))
}

fn persist_submit_uncertain(store: &JobStore, local_job_id: &LocalJobId) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.cleanup_status == StoredCleanupStatus::Uncertain
        && matches!(
            latest.state,
            StoredJobState::Unknown | StoredJobState::Failed
        )
    {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |previous, next| {
        next.cleanup_status = StoredCleanupStatus::Uncertain;
        if previous.failure.is_none()
            && !matches!(
                previous.state,
                StoredJobState::Failed | StoredJobState::CleanupFailed
            )
        {
            next.state = StoredJobState::Unknown;
            next.last_confirmed_state = Some(effective_local_phase(previous));
        }
        Ok(())
    })
}

fn persist_downloading(
    store: &JobStore,
    local_job_id: &LocalJobId,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
) -> Result<(), CliError> {
    update_stored_job(store, local_job_id, |_previous, next| {
        if next.artifacts.len() != destinations.len()
            || destinations
                .values()
                .map(|destination| &destination.path)
                .collect::<BTreeSet<_>>()
                .len()
                != destinations.len()
        {
            return Err(JobStoreError::InvalidRecord {
                reason: "download destinations do not exactly cover durable artifacts",
            });
        }
        for artifact in &mut next.artifacts {
            let destination = destinations.get(&artifact.record.artifact_id).ok_or(
                JobStoreError::InvalidRecord {
                    reason: "download destination is missing for a durable artifact",
                },
            )?;
            if artifact.download_destination.is_some()
                || artifact.download_parent_identity.is_some()
                || artifact.local_path.is_some()
                || artifact.local_file_identity.is_some()
            {
                return Err(JobStoreError::InvalidRecord {
                    reason: "artifact download destination or result was already bound",
                });
            }
            artifact.download_destination = Some(destination.path.clone());
            artifact.download_parent_identity = Some(destination.parent_identity.to_string());
        }
        next.state = StoredJobState::Downloading;
        Ok(())
    })
}

fn persist_or_verify_download_destinations(
    store: &JobStore,
    local_job_id: &LocalJobId,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    let has_intent = latest
        .artifacts
        .iter()
        .any(|artifact| artifact.download_destination.is_some());
    if !has_intent {
        return persist_downloading(store, local_job_id, destinations);
    }
    let exact = latest.artifacts.len() == destinations.len()
        && latest.artifacts.iter().all(|artifact| {
            destinations
                .get(&artifact.record.artifact_id)
                .is_some_and(|binding| {
                    artifact.download_destination.as_deref() == Some(binding.path.as_str())
                        && artifact.download_parent_identity.as_deref()
                            == Some(binding.parent_identity.as_str())
                })
        });
    if !exact {
        return Err(remote_error(
            "artifact_destination_intent_mismatch",
            "the durable artifact destinations differ from the exact reconstructed bindings",
            "Preserve the job and intended paths; do not overwrite or redirect its artifacts.",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one crash-recovery boundary validates existing publication or performs one create-only provider download"
)]
fn download_or_resume_artifact(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    job_id: &str,
    manifest: &rustferry_remote::ArtifactManifest,
    artifact: &rustferry_remote::ArtifactRecord,
    destination_binding: &DownloadDestinationBinding,
    project_binding: &ProjectFilesystemBinding,
) -> Result<ValidatedLocalArtifact, ArtifactProcessingFailure> {
    project_binding
        .verify()
        .map_err(ArtifactProcessingFailure::from)?;
    destination_binding
        .verify(project_binding)
        .map_err(ArtifactProcessingFailure::from)?;
    let path = Utf8Path::new(&destination_binding.path);
    let latest = store.latest(local_job_id).map_err(CliError::from)?;
    let durable = latest
        .artifacts
        .iter()
        .find(|stored| stored.record.artifact_id == artifact.artifact_id)
        .ok_or_else(|| {
            ArtifactProcessingFailure::from(remote_error(
                "artifact_destination_intent_missing",
                "a verified artifact has no durable destination intent",
                "Preserve the local job and inspect its immutable artifact records.",
            ))
        })?;
    if path.exists() {
        let validated =
            independently_validate_download(store, local_job_id, &artifact.artifact_id, path)
                .map_err(|error| ArtifactProcessingFailure {
                    error: Box::new(error),
                    local_publication_uncertain: true,
                })?;
        if let Some(identity) = durable.local_file_identity.as_deref() {
            let expected = identity
                .parse::<RegularFileFilesystemIdentity>()
                .map_err(|error| {
                    ArtifactProcessingFailure::from(remote_error_with_details(
                        "durable_artifact_identity_invalid",
                        "the durable artifact identity is invalid",
                        "Preserve the local job and inspect its immutable artifact record.",
                        vec![error.to_string()],
                    ))
                })?;
            if durable.local_path.as_deref() != Some(destination_binding.path.as_str())
                || validated.file_identity != expected
            {
                return Err(ArtifactProcessingFailure::from(remote_error(
                    "durable_artifact_identity_changed",
                    "the existing artifact differs from its durable path or filesystem identity",
                    "Do not use the artifact; preserve the local job for inspection.",
                )));
            }
            return Ok(validated);
        }
        persist_downloaded_artifact(store, local_job_id, &artifact.artifact_id, &validated)
            .map_err(|failure| ArtifactProcessingFailure {
                error: Box::new(failure.error),
                local_publication_uncertain: true,
            })?;
        return Ok(validated);
    }
    if durable.local_path.is_some() || durable.local_file_identity.is_some() {
        return Err(ArtifactProcessingFailure::from(remote_error(
            "durable_artifact_missing",
            "a durable downloaded artifact is missing from its exact local path",
            "Do not redownload over the durable record; preserve the job for inspection.",
        )));
    }
    let destination = ProtocolPath::new(
        ProtocolPathSemantics::ClientAbsolute,
        destination_binding.path.clone(),
    )
    .map_err(|error| {
        ArtifactProcessingFailure::from(remote_error_with_details(
            "artifact_destination_invalid",
            "a local artifact destination is invalid",
            "Choose a project location with a canonical absolute target directory.",
            vec![error.to_string()],
        ))
    })?;
    let result = match poll_provider_once(provider.download_artifact(
        ArtifactDownloadRequest {
            job_id: job_id.to_owned(),
            artifact_id: artifact.artifact_id.clone(),
            destination,
        },
        CancellationToken::new(),
    )) {
        ImmediateProviderResult::Ready(Ok(result)) => result,
        ImmediateProviderResult::Ready(Err(error)) => {
            return Err(ArtifactProcessingFailure {
                error: Box::new(provider_failure(
                    &error,
                    "artifact_download_failed",
                    "an independently verified iPhone build artifact could not be downloaded",
                )),
                local_publication_uncertain: true,
            });
        }
        ImmediateProviderResult::Pending => {
            return Err(ArtifactProcessingFailure {
                error: Box::new(provider_runtime_required()),
                local_publication_uncertain: true,
            });
        }
    };
    project_binding
        .verify()
        .map_err(|error| ArtifactProcessingFailure {
            error: Box::new(error),
            local_publication_uncertain: true,
        })?;
    destination_binding
        .verify(project_binding)
        .map_err(|error| ArtifactProcessingFailure {
            error: Box::new(error),
            local_publication_uncertain: true,
        })?;
    if result.local_path.value != destination_binding.path.as_str()
        || result.manifest != downloaded_manifest(manifest)
    {
        return Err(ArtifactProcessingFailure {
            error: Box::new(remote_error(
                "artifact_destination_mismatch",
                "the provider returned different artifact identity or local path metadata",
                "Do not use the downloaded artifacts; preserve the job ID for investigation.",
            )),
            local_publication_uncertain: true,
        });
    }
    let provider_file_identity = result
        .local_file_identity
        .parse::<RegularFileFilesystemIdentity>()
        .map_err(|error| ArtifactProcessingFailure {
            error: Box::new(remote_error_with_details(
                "artifact_publisher_identity_invalid",
                "the provider returned an invalid publisher-captured artifact identity",
                "Preserve the intended destination and reconcile the exact local job before retrying.",
                vec![error.to_string()],
            )),
            local_publication_uncertain: true,
        })?;
    let validated =
        independently_validate_download(store, local_job_id, &artifact.artifact_id, path).map_err(
            |error| ArtifactProcessingFailure {
                error: Box::new(error),
                local_publication_uncertain: true,
            },
        )?;
    if validated.file_identity != provider_file_identity {
        return Err(ArtifactProcessingFailure {
            error: Box::new(remote_error(
                "artifact_publisher_identity_changed",
                "the downloaded artifact path no longer names the provider-published file",
                "Preserve the intended destination and reconcile the exact local job before retrying.",
            )),
            local_publication_uncertain: true,
        });
    }
    persist_downloaded_artifact(store, local_job_id, &artifact.artifact_id, &validated).map_err(
        |failure| ArtifactProcessingFailure {
            error: Box::new(failure.error),
            local_publication_uncertain: true,
        },
    )?;
    Ok(validated)
}

fn independently_validate_download(
    store: &JobStore,
    local_job_id: &LocalJobId,
    artifact_id: &str,
    path: &Utf8Path,
) -> Result<ValidatedLocalArtifact, CliError> {
    let latest = store.latest(local_job_id)?;
    let artifact = latest
        .artifacts
        .iter()
        .find(|artifact| artifact.record.artifact_id == artifact_id)
        .ok_or_else(|| {
            remote_error(
                "artifact_binding_incomplete",
                "a downloaded artifact has no exact durable manifest record",
                "Preserve the destination intent and inspect the exact verified manifest before reconciliation.",
            )
        })?;
    if artifact.download_destination.as_deref() != Some(path.as_str())
        || artifact.download_parent_identity.is_none()
        || artifact.local_path.is_some()
        || artifact.local_file_identity.is_some()
    {
        return Err(remote_error(
            "artifact_binding_incomplete",
            "a downloaded artifact differs from its durable destination intent",
            "Preserve the destination intent and inspect the exact verified manifest before reconciliation.",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        remote_error(
            "artifact_destination_invalid",
            "a downloaded artifact has no destination parent",
            "Preserve the local job and inspect its exact download intent before reconciliation.",
        )
    })?;
    let parent_identity = artifact
        .download_parent_identity
        .as_deref()
        .expect("download parent identity was checked above")
        .parse::<DirectoryFilesystemIdentity>()
        .map_err(|error| {
            remote_error_with_details(
                "artifact_parent_identity_invalid",
                "a durable artifact destination parent has an invalid filesystem identity",
                "Preserve the local job and inspect its immutable destination intent.",
                vec![error.to_string()],
            )
        })?;
    verify_directory_identity(parent.as_std_path(), &parent_identity).map_err(|error| {
        remote_error_with_details(
            "artifact_parent_identity_changed",
            "a downloaded artifact destination parent changed filesystem identity",
            "Preserve the local job and reconcile its exact intended destination before retrying.",
            vec![error.to_string()],
        )
    })?;
    let file_identity = independently_validate_artifact_file(artifact, path)?;
    verify_directory_identity(parent.as_std_path(), &parent_identity).map_err(|error| {
        remote_error_with_details(
            "artifact_parent_identity_changed",
            "a downloaded artifact destination parent changed during validation",
            "Preserve the local job and reconcile its exact intended destination before retrying.",
            vec![error.to_string()],
        )
    })?;
    Ok(ValidatedLocalArtifact {
        path: path.to_string(),
        file_identity,
    })
}

#[allow(clippy::too_many_lines)]
fn independently_validate_artifact_file(
    artifact: &StoredArtifactV1,
    path: &Utf8Path,
) -> Result<RegularFileFilesystemIdentity, CliError> {
    let persistent_identity = RegularFileFilesystemIdentity::capture(path.as_std_path()).map_err(
        |error| {
            remote_error_with_details(
                "artifact_validation_failed",
                "a downloaded artifact is not a stable single-link regular file",
                "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
                vec![
                    format!("artifact_id={}", artifact.record.artifact_id),
                    error.to_string(),
                ],
            )
        },
    )?;
    let path_identity = ArtifactFileIdentity::capture(path).map_err(|error| {
        remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact could not be bound to its final filesystem identity",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![
                format!("artifact_id={}", artifact.record.artifact_id),
                error.to_string(),
            ],
        )
    })?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| CliError::Io {
            action: "open downloaded artifact for independent validation",
            path: path.to_owned(),
            source,
        })?;
    let open_identity = ArtifactFileIdentity::from_file(&file).map_err(|error| {
        remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact handle is not a stable regular file",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![
                format!("artifact_id={}", artifact.record.artifact_id),
                error.to_string(),
            ],
        )
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect downloaded artifact for independent validation",
        path: path.to_owned(),
        source,
    })?;
    if path_identity != open_identity || metadata.len() != artifact.record.size {
        return Err(remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact changed identity or length before independent validation",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![format!("artifact_id={}", artifact.record.artifact_id)],
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes_read = 0_u64;
    loop {
        let count = file.read(buffer.as_mut()).map_err(|source| CliError::Io {
            action: "hash downloaded artifact independently",
            path: path.to_owned(),
            source,
        })?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if bytes_read > artifact.record.size {
            return Err(remote_error(
                "artifact_validation_failed",
                "a downloaded artifact exceeded its verified byte length while hashing",
                "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            ));
        }
        digest.update(&buffer[..count]);
    }
    let final_identity = ArtifactFileIdentity::capture(path).map_err(|error| {
        remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact changed while independent validation completed",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![
                format!("artifact_id={}", artifact.record.artifact_id),
                error.to_string(),
            ],
        )
    })?;
    if bytes_read != artifact.record.size
        || sha256_hex(digest.finalize()) != artifact.record.sha256
        || final_identity != open_identity
    {
        return Err(remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact failed independent size, SHA-256, or identity validation",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![format!("artifact_id={}", artifact.record.artifact_id)],
        ));
    }
    verify_regular_file_identity(path.as_std_path(), &persistent_identity).map_err(|error| {
        remote_error_with_details(
            "artifact_validation_failed",
            "a downloaded artifact changed persistent filesystem identity while it was validated",
            "Do not use the artifact; keep the rollback guard active and retry with a new local job.",
            vec![
                format!("artifact_id={}", artifact.record.artifact_id),
                error.to_string(),
            ],
        )
    })?;
    Ok(persistent_identity)
}

#[derive(Debug)]
struct ArtifactPathPersistenceFailure {
    error: CliError,
}

#[derive(Debug)]
struct ArtifactProcessingFailure {
    error: Box<CliError>,
    local_publication_uncertain: bool,
}

impl From<CliError> for ArtifactProcessingFailure {
    fn from(error: CliError) -> Self {
        Self {
            error: Box::new(error),
            local_publication_uncertain: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactPathReconciliation {
    Persisted,
    NotPersisted,
    Uncertain,
}

fn reconcile_artifact_path_publication(
    previous_revision: u64,
    latest: Option<&StoredJobV1>,
    artifact_id: &str,
    validated: &ValidatedLocalArtifact,
) -> ArtifactPathReconciliation {
    let Some(latest) = latest else {
        return ArtifactPathReconciliation::Uncertain;
    };
    let artifact = latest
        .artifacts
        .iter()
        .find(|artifact| artifact.record.artifact_id == artifact_id);
    if artifact.is_some_and(|artifact| {
        artifact.download_destination.as_ref() == Some(&validated.path)
            && artifact.download_parent_identity.is_some()
            && artifact.local_path.as_ref() == Some(&validated.path)
            && artifact.local_file_identity.as_deref() == Some(validated.file_identity.as_str())
    }) {
        ArtifactPathReconciliation::Persisted
    } else if latest.revision == previous_revision
        && artifact.is_some_and(|artifact| {
            artifact.local_path.is_none() && artifact.local_file_identity.is_none()
        })
    {
        ArtifactPathReconciliation::NotPersisted
    } else {
        ArtifactPathReconciliation::Uncertain
    }
}

fn persist_downloaded_artifact(
    store: &JobStore,
    local_job_id: &LocalJobId,
    artifact_id: &str,
    validated: &ValidatedLocalArtifact,
) -> Result<(), ArtifactPathPersistenceFailure> {
    let before = store
        .latest(local_job_id)
        .map_err(|error| ArtifactPathPersistenceFailure {
            error: error.into(),
        })?;
    let update = update_stored_job(store, local_job_id, |_previous, next| {
        if next.state != StoredJobState::Downloading {
            return Err(JobStoreError::InvalidRecord {
                reason: "artifact result can only bind while downloading",
            });
        }
        let artifact = next
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.record.artifact_id == artifact_id)
            .ok_or(JobStoreError::InvalidRecord {
                reason: "local artifact result has no durable artifact record",
            })?;
        if artifact.download_destination.as_ref() != Some(&validated.path)
            || artifact.local_path.is_some()
            || artifact.local_file_identity.is_some()
        {
            return Err(JobStoreError::InvalidRecord {
                reason: "local artifact result differs from its durable destination intent",
            });
        }
        artifact.local_path = Some(validated.path.clone());
        artifact.local_file_identity = Some(validated.file_identity.to_string());
        artifact.locally_validated = false;
        Ok(())
    });
    let Err(error) = update else {
        return Ok(());
    };
    let latest = store.latest(local_job_id).ok();
    match reconcile_artifact_path_publication(
        before.revision,
        latest.as_ref(),
        artifact_id,
        validated,
    ) {
        ArtifactPathReconciliation::Persisted => Ok(()),
        ArtifactPathReconciliation::NotPersisted | ArtifactPathReconciliation::Uncertain => {
            Err(ArtifactPathPersistenceFailure { error })
        }
    }
}

fn persist_downloads_complete(store: &JobStore, local_job_id: &LocalJobId) -> Result<(), CliError> {
    update_stored_job(store, local_job_id, |_previous, next| {
        if next.state != StoredJobState::Downloading
            || next.artifacts.is_empty()
            || next.artifacts.iter().any(|artifact| {
                artifact.download_destination.is_none()
                    || artifact.download_parent_identity.is_none()
                    || artifact.local_path.as_deref() != artifact.download_destination.as_deref()
                    || artifact.local_file_identity.is_none()
            })
        {
            return Err(JobStoreError::InvalidRecord {
                reason: "download completion lacks an exact path and identity for every artifact",
            });
        }
        next.state = StoredJobState::Downloaded;
        Ok(())
    })
}

fn persist_validating(store: &JobStore, local_job_id: &LocalJobId) -> Result<(), CliError> {
    update_stored_job(store, local_job_id, |_previous, next| {
        next.state = StoredJobState::Validating;
        Ok(())
    })
}

fn persist_validation_ready_for_cleanup(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), CliError> {
    update_stored_job(store, local_job_id, |previous, next| {
        if previous.state != StoredJobState::Validating {
            return Err(JobStoreError::InvalidRecord {
                reason: "cleanup intent must preserve the exact validating phase",
            });
        }
        next.state = StoredJobState::CleanupPending;
        next.last_confirmed_state = Some(StoredJobState::Validating);
        next.cleanup_status = StoredCleanupStatus::Pending;
        Ok(())
    })
}

fn persist_controller_failure(
    store: &JobStore,
    local_job_id: &LocalJobId,
    code: &'static str,
    retryable: bool,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.failure.is_some()
        || matches!(
            latest.state,
            StoredJobState::Succeeded
                | StoredJobState::CleanupFailed
                | StoredJobState::Cancelled
                | StoredJobState::Expired
        )
        || matches!(
            latest.terminal_outcome,
            Some(StoredBuildOutcome::Cancelled | StoredBuildOutcome::Expired)
        )
    {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |_previous, next| {
        next.state = StoredJobState::Failed;
        next.last_confirmed_state = Some(StoredJobState::Failed);
        next.failure = Some(StoredFailureV1 {
            code: code.to_owned(),
            retryable,
        });
        Ok(())
    })
}

fn persist_artifact_publication_uncertain(
    store: &JobStore,
    local_job_id: &LocalJobId,
    code: &'static str,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest
        .failure
        .as_ref()
        .is_some_and(|failure| failure.code == code)
        && latest.state == StoredJobState::Unknown
    {
        return Ok(());
    }
    if latest.failure.is_some() {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |previous, next| {
        next.state = StoredJobState::Unknown;
        next.last_confirmed_state = Some(effective_local_phase(previous));
        next.failure = Some(StoredFailureV1 {
            code: code.to_owned(),
            retryable: false,
        });
        Ok(())
    })
}

fn persist_cancellation_requested(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<bool, CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.terminal_outcome.is_some()
        || latest.failure.is_some()
        || latest.cancellation_status == StoredCancellationStatus::Confirmed
    {
        return Ok(false);
    }
    if matches!(
        latest.cancellation_status,
        StoredCancellationStatus::Requested
            | StoredCancellationStatus::Dispatched
            | StoredCancellationStatus::Uncertain
    ) {
        return Ok(true);
    }
    update_stored_job(store, local_job_id, |_previous, next| {
        next.state = StoredJobState::CancellationRequested;
        next.cancellation_status = StoredCancellationStatus::Requested;
        Ok(())
    })?;
    Ok(true)
}

fn persist_cancellation_uncertain(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.terminal_outcome.is_some()
        || latest.failure.is_some()
        || latest.cancellation_status == StoredCancellationStatus::Confirmed
        || latest.state == StoredJobState::Unknown
            && latest.cancellation_status == StoredCancellationStatus::Uncertain
    {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |previous, next| {
        next.state = StoredJobState::Unknown;
        next.last_confirmed_state = Some(effective_local_phase(previous));
        next.cancellation_status = StoredCancellationStatus::Uncertain;
        Ok(())
    })
}

fn persist_terminal_cancellation_result(
    store: &JobStore,
    local_job_id: &LocalJobId,
    state: JobState,
) -> Result<(), CliError> {
    if state == JobState::Cancelled {
        let latest = store.latest(local_job_id)?;
        if latest.terminal_outcome == Some(StoredBuildOutcome::Cancelled)
            && latest.cancellation_status == StoredCancellationStatus::Confirmed
        {
            return Ok(());
        }
        return Err(remote_error(
            "cancellation_checkpoint_missing",
            "the provider reported cancellation without an exact durable terminal checkpoint",
            "Preserve the local job ID and inspect its latest immutable provider checkpoint.",
        ));
    }
    let latest = store.latest(local_job_id)?;
    let expected_outcome = match state {
        JobState::Succeeded => StoredBuildOutcome::Succeeded,
        JobState::Failed => StoredBuildOutcome::Failed,
        _ => {
            return Err(remote_error(
                "cancellation_terminal_checkpoint_missing",
                "the provider acknowledgement is not an exact supported terminal build outcome",
                "Preserve the local job ID and inspect its immutable provider checkpoint.",
            ));
        }
    };
    if latest.terminal_outcome != Some(expected_outcome) {
        return Err(remote_error(
            "cancellation_terminal_checkpoint_missing",
            "the provider acknowledgement lacks a matching durable terminal build outcome",
            "Preserve the local job ID and inspect its immutable provider checkpoint.",
        ));
    }
    if latest.cancellation_status == StoredCancellationStatus::Failed {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |_previous, next| {
        next.cancellation_status = StoredCancellationStatus::Failed;
        Ok(())
    })
}

fn persist_non_cancel_terminal_race(
    store: &JobStore,
    local_job_id: &LocalJobId,
) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.cancellation_status == StoredCancellationStatus::Failed {
        return Ok(());
    }
    if latest.terminal_outcome.is_none() && latest.failure.is_none() {
        return Err(remote_error(
            "cancellation_terminal_checkpoint_missing",
            "a non-cancel terminal race lacks exact durable outcome evidence",
            "Preserve the local job ID and inspect its immutable provider checkpoint.",
        ));
    }
    update_stored_job(store, local_job_id, |_previous, next| {
        next.cancellation_status = StoredCancellationStatus::Failed;
        Ok(())
    })
}

fn interrupted_cleanup_progress(
    outcome: Option<StoredBuildOutcome>,
    cancellation_confirmed: bool,
    cleanup_confirmed: bool,
) -> &'static str {
    match (outcome, cancellation_confirmed, cleanup_confirmed) {
        (Some(StoredBuildOutcome::Cancelled), true, true) => {
            "Remote cancellation and cleanup confirmed"
        }
        (Some(StoredBuildOutcome::Cancelled), true, false) => {
            "Remote cancellation was confirmed, but cleanup remains unconfirmed"
        }
        (Some(StoredBuildOutcome::Succeeded), _, true) => {
            "Remote build succeeded before cancellation; cleanup confirmed"
        }
        (Some(StoredBuildOutcome::Succeeded), _, false) => {
            "Remote build succeeded before cancellation; cleanup remains unconfirmed"
        }
        (Some(StoredBuildOutcome::Failed), _, true) => {
            "Remote build failed before cancellation; cleanup confirmed"
        }
        (Some(StoredBuildOutcome::Failed), _, false) => {
            "Remote build failed before cancellation; cleanup remains unconfirmed"
        }
        (Some(StoredBuildOutcome::Expired), _, true) => {
            "Remote build expired before cancellation; cleanup confirmed"
        }
        (Some(StoredBuildOutcome::Expired), _, false) => {
            "Remote build expired before cancellation; cleanup remains unconfirmed"
        }
        (Some(StoredBuildOutcome::Cancelled), false, true) => {
            "Remote cleanup confirmed, but cancellation lacks durable confirmation"
        }
        (Some(StoredBuildOutcome::Cancelled), false, false) | (None, _, false) => {
            "Remote cancellation and cleanup remain unconfirmed; inspect the exact job"
        }
        (None, _, true) => "Remote cleanup confirmed, but the terminal job outcome is uncertain",
    }
}

fn interrupted_cleanup_progress_for_job(
    job: Option<&StoredJobV1>,
    provider_job_id: &str,
) -> &'static str {
    interrupted_cleanup_progress(
        job.and_then(|job| job.terminal_outcome),
        job.is_some_and(|job| job.cancellation_status == StoredCancellationStatus::Confirmed),
        job.is_some_and(|job| durable_cleanup_is_confirmed(job, provider_job_id)),
    )
}

fn poll_job(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    job_id: &str,
    deadline: Instant,
    cancellation: &CancellationToken,
    reporter: &Reporter,
) -> Result<JobTerminal, CliError> {
    let mut sequence = None;
    let mut diagnostics = Vec::new();
    loop {
        if cancellation.is_cancelled() || rustferry_core::process_control::interrupt_requested() {
            reporter
                .progress("Cancellation requested; waiting for exact-run termination and cleanup");
            let cancellation = cancel_and_wait(CancellationWaitContext {
                provider,
                store,
                local_job_id,
                job_id,
                reason: "client_interrupted",
                sequence: &mut sequence,
                diagnostics: &mut diagnostics,
                reporter,
            });
            reporter.progress(match cancellation.outcome {
                CancellationWaitOutcome::Cancelled => "Exact remote cancellation confirmed",
                CancellationWaitOutcome::OtherTerminal => {
                    "Remote job reached another terminal outcome before cancellation"
                }
                CancellationWaitOutcome::Uncertain => {
                    "Remote cancellation outcome remains uncertain"
                }
            });
            return Err(CliError::CommandInterrupted {
                tool: "GitHub Actions job".to_owned(),
                stage: "remote iPhone build",
            });
        }
        if Instant::now() >= deadline {
            reporter
                .progress("Build timeout reached; waiting for exact-run cancellation and cleanup");
            let mut details = vec![format!("job_id={job_id}")];
            let cancellation = cancel_and_wait(CancellationWaitContext {
                provider,
                store,
                local_job_id,
                job_id,
                reason: "client_timeout",
                sequence: &mut sequence,
                diagnostics: &mut diagnostics,
                reporter,
            });
            details.extend(cancellation.details);
            details.extend(diagnostics);
            return Err(remote_error_with_details(
                "remote_job_timed_out",
                "the GitHub iPhone build exceeded its bounded runtime and was not accepted as successful",
                "Inspect the exact GitHub Actions job and temporary ref before retrying.",
                details,
            ));
        }
        let page = match provider_call(
            provider.events(
                EventRequest {
                    job_id: job_id.to_owned(),
                    after_sequence: sequence,
                    limit: 128,
                },
                cancellation.clone(),
            ),
            "remote_events_failed",
            "GitHub build events could not be retrieved",
        ) {
            Ok(page) => page,
            Err(error) => {
                let mut details = vec![format!("job_id={job_id}"), error.to_string()];
                let cancellation = cancel_and_wait(CancellationWaitContext {
                    provider,
                    store,
                    local_job_id,
                    job_id,
                    reason: "client_tracking_failed",
                    sequence: &mut sequence,
                    diagnostics: &mut diagnostics,
                    reporter,
                });
                details.extend(cancellation.details);
                details.extend(diagnostics);
                return Err(remote_error_with_details(
                    "remote_job_tracking_failed",
                    "the GitHub job could not be tracked to a verified terminal state",
                    "Preserve the exact job ID and inspect the provider-created temporary ref before retrying.",
                    details,
                ));
            }
        };
        record_events(&page.events, reporter, &mut diagnostics);
        if page.next_sequence.is_some() {
            sequence = page.next_sequence;
        }
        if page.state.is_build_terminal() {
            return Ok(JobTerminal {
                state: page.state,
                diagnostics,
            });
        }
        sleep_interruptibly_with_cancellation(POLL_INTERVAL, cancellation);
    }
}

fn observe_job_until_terminal(
    provider: &GithubProvider,
    local_job_id: &LocalJobId,
    job_id: &str,
    deadline: Instant,
    cancellation: &CancellationToken,
    reporter: &Reporter,
) -> Result<JobTerminal, CliError> {
    let mut sequence = None;
    let mut diagnostics = Vec::new();
    loop {
        if cancellation.is_cancelled() || rustferry_core::process_control::interrupt_requested() {
            return Err(CliError::CommandInterrupted {
                tool: "GitHub Actions retry job".to_owned(),
                stage: "remote iPhone retry",
            });
        }
        if Instant::now() >= deadline {
            return Err(remote_error_with_details(
                "remote_retry_observation_timed_out",
                "the GitHub retry did not reach an exact terminal state within the bounded wait",
                "The child remains durable; rerun jobs retry to continue observation or cancel it separately.",
                vec![
                    format!("local_job_id={}", local_job_id.as_str()),
                    format!("job_id={job_id}"),
                ],
            ));
        }
        let page = provider_call(
            provider.events(
                EventRequest {
                    job_id: job_id.to_owned(),
                    after_sequence: sequence,
                    limit: 128,
                },
                cancellation.clone(),
            ),
            "remote_retry_events_failed",
            "GitHub retry events could not be retrieved",
        )?;
        record_events(&page.events, reporter, &mut diagnostics);
        if page.next_sequence.is_some() {
            sequence = page.next_sequence;
        }
        if page.state.is_build_terminal() {
            return Ok(JobTerminal {
                state: page.state,
                diagnostics,
            });
        }
        sleep_interruptibly_with_cancellation(POLL_INTERVAL, cancellation);
    }
}

enum ImmediateProviderResult<T> {
    Ready(rustferry_remote::RemoteBuildResult<T>),
    Pending,
}

fn list_artifacts_with_retry(
    provider: &GithubProvider,
    job_id: &str,
    deadline: Instant,
    reporter: &Reporter,
    project_binding: &ProjectFilesystemBinding,
) -> Result<Vec<rustferry_remote::ArtifactManifest>, CliError> {
    retry_artifact_listing(
        || project_binding.verify(),
        || {
            poll_provider_once(provider.list_artifacts(
                ArtifactListRequest {
                    job_id: job_id.to_owned(),
                },
                CancellationToken::new(),
            ))
        },
        deadline,
        reporter,
        ARTIFACT_LIST_ATTEMPTS,
        ARTIFACT_LIST_BACKOFF,
    )
}

fn retry_artifact_listing<B, F>(
    mut before_list: B,
    mut list: F,
    deadline: Instant,
    reporter: &Reporter,
    attempts: usize,
    backoff: Duration,
) -> Result<Vec<rustferry_remote::ArtifactManifest>, CliError>
where
    B: FnMut() -> Result<(), CliError>,
    F: FnMut() -> ImmediateProviderResult<Vec<rustferry_remote::ArtifactManifest>>,
{
    let mut last_failure = "the verified artifact manifest is not indexed yet".to_owned();
    for attempt in 1..=attempts {
        check_artifact_listing_deadline(deadline)?;
        before_list()?;
        match list() {
            ImmediateProviderResult::Ready(Ok(manifests)) if !manifests.is_empty() => {
                check_artifact_listing_deadline(deadline)?;
                return Ok(manifests);
            }
            ImmediateProviderResult::Ready(Ok(_)) => {}
            ImmediateProviderResult::Ready(Err(error)) if error.retryable() => {
                last_failure = safe_public_text(&error.to_string());
            }
            ImmediateProviderResult::Ready(Err(error)) => {
                return Err(provider_failure(
                    &error,
                    "artifact_list_failed",
                    "the verified artifact manifest could not be listed",
                ));
            }
            ImmediateProviderResult::Pending => return Err(provider_runtime_required()),
        }
        if attempt < attempts {
            reporter.progress(format!(
                "Verified artifact manifest not ready; retrying ({}/{attempts})",
                attempt + 1
            ));
            let remaining = deadline.saturating_duration_since(Instant::now());
            sleep_interruptibly(backoff.min(remaining));
        }
    }
    check_artifact_listing_deadline(deadline)?;
    Err(remote_error_with_details(
        "artifact_list_timed_out",
        "the successful GitHub run did not expose its verified artifact manifest within the bounded retry window",
        "Preserve the exact job ID, inspect the uploaded artifact set, and retry the build.",
        vec![format!("attempts={attempts}"), last_failure],
    ))
}

fn check_artifact_listing_deadline(deadline: Instant) -> Result<(), CliError> {
    if rustferry_core::process_control::interrupt_requested() {
        return Err(CliError::CommandInterrupted {
            tool: "GitHub artifact listing".to_owned(),
            stage: "remote iPhone build",
        });
    }
    if Instant::now() >= deadline {
        return Err(remote_error(
            "remote_job_timed_out",
            "the GitHub iPhone build exceeded its bounded runtime before verified artifacts were available",
            "Preserve the exact job ID and inspect the GitHub Actions run before retrying.",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationWaitOutcome {
    Cancelled,
    OtherTerminal,
    Uncertain,
}

#[derive(Debug)]
struct CancellationWaitResult {
    outcome: CancellationWaitOutcome,
    details: Vec<String>,
}

struct CancellationWaitContext<'a> {
    provider: &'a GithubProvider,
    store: &'a JobStore,
    local_job_id: &'a LocalJobId,
    job_id: &'a str,
    reason: &'a str,
    sequence: &'a mut Option<u64>,
    diagnostics: &'a mut Vec<String>,
    reporter: &'a Reporter,
}

fn cancellation_outcome_from_job(job: &StoredJobV1) -> CancellationWaitOutcome {
    if job.terminal_outcome == Some(StoredBuildOutcome::Cancelled)
        && job.cancellation_status == StoredCancellationStatus::Confirmed
    {
        CancellationWaitOutcome::Cancelled
    } else if job.terminal_outcome.is_some() || job.failure.is_some() {
        CancellationWaitOutcome::OtherTerminal
    } else {
        CancellationWaitOutcome::Uncertain
    }
}

fn begin_cancellation(
    context: &CancellationWaitContext<'_>,
    details: &mut Vec<String>,
) -> Option<CancellationWaitOutcome> {
    let should_cancel = match persist_cancellation_requested(context.store, context.local_job_id) {
        Ok(should_cancel) => should_cancel,
        Err(error) => {
            details.push(format!("cancel_intent_persistence={error}"));
            return Some(CancellationWaitOutcome::Uncertain);
        }
    };
    if !should_cancel {
        details.push("cancel_skipped_terminal=true".to_owned());
        let outcome = context
            .store
            .latest(context.local_job_id)
            .map_or(CancellationWaitOutcome::Uncertain, |latest| {
                cancellation_outcome_from_job(&latest)
            });
        return Some(outcome);
    }
    match provider_call(
        context.provider.cancel(
            CancellationRequest {
                job_id: context.job_id.to_owned(),
                reason: context.reason.to_owned(),
            },
            CancellationToken::new(),
        ),
        "remote_cancel_failed",
        "the exact GitHub job could not be cancelled",
    ) {
        Ok(acknowledgement) => {
            details.push(format!("cancel_accepted={}", acknowledgement.accepted));
            details.push(format!(
                "cancel_state={}",
                state_name(acknowledgement.state)
            ));
            if acknowledgement.state.is_build_terminal() {
                let outcome = match persist_terminal_cancellation_result(
                    context.store,
                    context.local_job_id,
                    acknowledgement.state,
                ) {
                    Ok(()) if acknowledgement.state == JobState::Cancelled => {
                        CancellationWaitOutcome::Cancelled
                    }
                    Ok(()) => CancellationWaitOutcome::OtherTerminal,
                    Err(error) => {
                        details.push(format!("terminal_checkpoint={error}"));
                        CancellationWaitOutcome::Uncertain
                    }
                };
                details.push("terminal_after_cancel=true".to_owned());
                return Some(outcome);
            }
        }
        Err(error) => details.push(format!("cancel_error={error}")),
    }
    None
}

fn cancel_and_wait(context: CancellationWaitContext<'_>) -> CancellationWaitResult {
    let mut details = Vec::new();
    if let Some(outcome) = begin_cancellation(&context, &mut details) {
        return CancellationWaitResult { outcome, details };
    }
    let CancellationWaitContext {
        provider,
        store,
        local_job_id,
        job_id,
        reason: _,
        sequence,
        diagnostics,
        reporter,
    } = context;
    let deadline = Instant::now() + CANCELLATION_TIMEOUT;
    while Instant::now() < deadline {
        match provider_call(
            provider.events(
                EventRequest {
                    job_id: job_id.to_owned(),
                    after_sequence: *sequence,
                    limit: 128,
                },
                CancellationToken::new(),
            ),
            "remote_events_failed",
            "GitHub cancellation status could not be retrieved",
        ) {
            Ok(page) => {
                record_events(&page.events, reporter, diagnostics);
                if page.next_sequence.is_some() {
                    *sequence = page.next_sequence;
                }
                if page.state.is_build_terminal() {
                    let outcome =
                        match persist_terminal_cancellation_result(store, local_job_id, page.state)
                        {
                            Ok(()) if page.state == JobState::Cancelled => {
                                CancellationWaitOutcome::Cancelled
                            }
                            Ok(()) => CancellationWaitOutcome::OtherTerminal,
                            Err(error) => {
                                details.push(format!("terminal_checkpoint={error}"));
                                CancellationWaitOutcome::Uncertain
                            }
                        };
                    details.push(format!("terminal_state={}", state_name(page.state)));
                    return CancellationWaitResult { outcome, details };
                }
            }
            Err(error) => {
                if !details
                    .iter()
                    .any(|detail| detail.starts_with("wait_error="))
                {
                    details.push(format!("wait_error={error}"));
                }
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    let outcome = store
        .latest(local_job_id)
        .map_or(CancellationWaitOutcome::Uncertain, |latest| {
            cancellation_outcome_from_job(&latest)
        });
    if outcome == CancellationWaitOutcome::Uncertain {
        if let Err(error) = persist_cancellation_uncertain(store, local_job_id) {
            details.push(format!("cancel_uncertain_persistence={error}"));
        }
        details.push("terminal_after_cancel=false".to_owned());
    } else {
        if outcome == CancellationWaitOutcome::OtherTerminal
            && let Err(error) = persist_non_cancel_terminal_race(store, local_job_id)
        {
            details.push(format!("terminal_race_persistence={error}"));
        }
        details.push("terminal_race_observed_durably=true".to_owned());
    }
    CancellationWaitResult { outcome, details }
}

fn record_events(events: &[RemoteBuildEvent], reporter: &Reporter, diagnostics: &mut Vec<String>) {
    for event in events {
        let detail = event_detail(event);
        reporter.progress(format!("[{}] {}", safe_public_text(&event.phase), detail));
        if diagnostics.len() < 32
            && matches!(
                &event.kind,
                RemoteBuildEventKind::Warning { .. } | RemoteBuildEventKind::Diagnostic { .. }
            )
        {
            diagnostics.push(format!("{}: {detail}", event.phase));
        }
    }
}

pub(super) fn event_detail(event: &RemoteBuildEvent) -> String {
    let detail = match &event.kind {
        RemoteBuildEventKind::Progress { message, .. }
        | RemoteBuildEventKind::Warning { message, .. }
        | RemoteBuildEventKind::PhaseStarted {
            message: Some(message),
        } => message.clone(),
        RemoteBuildEventKind::Diagnostic { diagnostic }
            if diagnostic.severity == DiagnosticSeverity::Error =>
        {
            diagnostic.message.clone()
        }
        _ => event.kind.event_name().replace('_', " "),
    };
    safe_public_text(&detail)
}

fn sleep_interruptibly(duration: Duration) {
    let started = Instant::now();
    while started.elapsed() < duration && !rustferry_core::process_control::interrupt_requested() {
        thread::sleep(Duration::from_millis(100));
    }
}

fn sleep_interruptibly_with_cancellation(duration: Duration, cancellation: &CancellationToken) {
    let started = Instant::now();
    while started.elapsed() < duration
        && !cancellation.is_cancelled()
        && !rustferry_core::process_control::interrupt_requested()
    {
        thread::sleep(Duration::from_millis(100));
    }
}

fn cleanup_job(provider: &GithubProvider, job_id: &str) -> Result<CleanupConfirmation, CliError> {
    let confirmation = provider_call(
        provider.cleanup(
            CleanupRequest {
                job_id: job_id.to_owned(),
                remove_artifacts: false,
            },
            CancellationToken::new(),
        ),
        "remote_cleanup_failed",
        "exact temporary-ref cleanup failed",
    )?;
    if !confirmation.workspace_removed || !confirmation.signing_material_removed {
        return Err(remote_error_with_details(
            "remote_cleanup_unconfirmed",
            "remote workspace or signing-material cleanup was not confirmed",
            "Preserve the exact job ID and inspect the provider-owned temporary ref before retrying.",
            vec![
                format!("job_id={job_id}"),
                format!("workspace_removed={}", confirmation.workspace_removed),
                format!(
                    "signing_material_removed={}",
                    confirmation.signing_material_removed
                ),
            ],
        ));
    }
    Ok(confirmation)
}

fn persist_cleanup_pending(store: &JobStore, local_job_id: &LocalJobId) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.state == StoredJobState::CleanupPending
        && latest.cleanup_status == StoredCleanupStatus::Pending
    {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |previous, next| {
        next.state = StoredJobState::CleanupPending;
        next.last_confirmed_state = Some(effective_local_phase(previous));
        next.cleanup_status = StoredCleanupStatus::Pending;
        Ok(())
    })
}

fn persist_cleanup_uncertain(store: &JobStore, local_job_id: &LocalJobId) -> Result<(), CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.state == StoredJobState::CleanupFailed {
        return Ok(());
    }
    update_stored_job(store, local_job_id, |previous, next| {
        next.cleanup_status = StoredCleanupStatus::Uncertain;
        match previous.terminal_outcome {
            Some(StoredBuildOutcome::Succeeded) => {
                next.state = StoredJobState::Failed;
                if next.failure.is_none() {
                    next.failure = Some(StoredFailureV1 {
                        code: "controller.cleanup_unconfirmed".to_owned(),
                        retryable: true,
                    });
                }
            }
            Some(StoredBuildOutcome::Failed) => {
                next.state = StoredJobState::Failed;
            }
            Some(StoredBuildOutcome::Cancelled | StoredBuildOutcome::Expired) | None => {
                next.state = StoredJobState::Unknown;
                next.last_confirmed_state = Some(effective_local_phase(previous));
            }
        }
        Ok(())
    })
}

fn effective_local_phase(job: &StoredJobV1) -> StoredJobState {
    let overlay = matches!(
        job.state,
        StoredJobState::Unknown | StoredJobState::CleanupPending | StoredJobState::CleanupFailed
    ) || recoverable_cleanup_failure(job);
    if overlay
        && let Some(confirmed) = job.last_confirmed_state
        && !matches!(
            confirmed,
            StoredJobState::Unknown
                | StoredJobState::CleanupPending
                | StoredJobState::CleanupFailed
        )
    {
        return confirmed;
    }
    job.state
}

fn recoverable_cleanup_failure(job: &StoredJobV1) -> bool {
    let Some(failure) = &job.failure else {
        return false;
    };
    if failure.code == "github.cleanup_failed" {
        return matches!(
            job.cleanup_status,
            StoredCleanupStatus::Failed
                | StoredCleanupStatus::Pending
                | StoredCleanupStatus::Uncertain
        ) && matches!(
            job.state,
            StoredJobState::CleanupFailed
                | StoredJobState::CleanupPending
                | StoredJobState::Failed
                | StoredJobState::Unknown
        ) && matches!(
            job.provider_resume.as_ref(),
            Some(resume) if resume.state == JobState::CleanupFailed
        );
    }
    failure.code == "controller.cleanup_unconfirmed"
        && failure.retryable
        && matches!(
            job.cleanup_status,
            StoredCleanupStatus::Pending | StoredCleanupStatus::Uncertain
        )
        && matches!(
            job.state,
            StoredJobState::Failed | StoredJobState::CleanupPending | StoredJobState::Unknown
        )
}

fn cleanup_job_durably(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    provider_job_id: &str,
    project_binding: &ProjectFilesystemBinding,
) -> Result<(), CliError> {
    cleanup_job_durably_with(
        store,
        local_job_id,
        provider_job_id,
        project_binding,
        || cleanup_job(provider, provider_job_id),
    )
}

fn cleanup_job_durably_with(
    store: &JobStore,
    local_job_id: &LocalJobId,
    provider_job_id: &str,
    project_binding: &ProjectFilesystemBinding,
    cleanup: impl FnOnce() -> Result<CleanupConfirmation, CliError>,
) -> Result<(), CliError> {
    let before = store.latest(local_job_id)?;
    if durable_cleanup_is_confirmed(&before, provider_job_id) {
        project_binding.verify()?;
        return Ok(());
    }
    if let Err(error) = project_binding.verify() {
        persist_cleanup_uncertain(store, local_job_id)?;
        return Err(error);
    }
    persist_cleanup_pending(store, local_job_id)?;
    if let Err(error) = project_binding.verify() {
        persist_cleanup_uncertain(store, local_job_id)?;
        return Err(error);
    }
    let cleanup = cleanup();
    let latest = store.latest(local_job_id)?;
    if durable_cleanup_is_confirmed(&latest, provider_job_id) {
        if let Err(error) = project_binding.verify() {
            persist_controller_failure(
                store,
                local_job_id,
                "controller.project_identity_changed",
                false,
            )?;
            return Err(error);
        }
        return Ok(());
    }
    persist_cleanup_uncertain(store, local_job_id)?;
    match cleanup {
        Err(error) => Err(error),
        Ok(_confirmation) => Err(remote_error(
            "cleanup_checkpoint_missing",
            "the provider returned cleanup success without a durable exact-cleanup checkpoint",
            "Preserve the local job ID and inspect its immutable provider checkpoint before retrying.",
        )),
    }
}

fn durable_cleanup_is_confirmed(job: &StoredJobV1, provider_job_id: &str) -> bool {
    job.provider_job_id.as_deref() == Some(provider_job_id)
        && job.cleanup_status == StoredCleanupStatus::Confirmed
        && job.provider_resume.as_ref().is_some_and(|resume| {
            resume.job_id == provider_job_id
                && resume.state == JobState::Cleaned
                && resume.cleanup_requested
                && (resume.temporary_ref_deleted || resume.publication_not_attempted)
        })
}

fn is_exact_success_promotion(before: &StoredJobV1, after: &StoredJobV1) -> bool {
    let Some(expected_revision) = before.revision.checked_add(1) else {
        return false;
    };
    if after.revision != expected_revision || after.updated_at_ms < before.updated_at_ms {
        return false;
    }
    let mut expected = before.clone();
    expected.revision = after.revision;
    expected.updated_at_ms = after.updated_at_ms;
    expected.state = StoredJobState::Succeeded;
    expected.last_confirmed_state = Some(StoredJobState::Succeeded);
    for artifact in &mut expected.artifacts {
        artifact.locally_validated = true;
    }
    expected == *after
}

fn validate_durable_artifact_for_promotion(
    artifact: &StoredArtifactV1,
    binding: &DownloadDestinationBinding,
    project_binding: &ProjectFilesystemBinding,
) -> Result<RetainedArtifactValidation, CliError> {
    binding.verify(project_binding)?;
    let (Some(path), Some(identity)) = (
        artifact.local_path.as_deref(),
        artifact.local_file_identity.as_deref(),
    ) else {
        return Err(remote_error(
            "durable_job_incomplete",
            "a successful durable artifact lacks its local path or filesystem identity",
            "Do not use the artifact; preserve the local job ID and inspect its immutable revision.",
        ));
    };
    let path = Utf8Path::new(path);
    if artifact.download_destination.as_deref() != Some(binding.path.as_str())
        || path != Utf8Path::new(&binding.path)
    {
        return Err(remote_error(
            "durable_artifact_destination_changed",
            "a durable artifact no longer matches its retained destination binding",
            "Do not use the artifact; preserve the local job ID and reconcile its immutable destination.",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        remote_error(
            "artifact_destination_invalid",
            "a durable artifact path has no destination parent",
            "Do not use the artifact; preserve the local job and inspect its immutable intent.",
        )
    })?;
    let parent_identity = artifact
        .download_parent_identity
        .as_deref()
        .ok_or_else(|| {
            remote_error(
                "durable_job_incomplete",
                "a durable artifact lacks its destination parent identity",
                "Do not use the artifact; preserve the local job and inspect its immutable revision.",
            )
        })?
        .parse::<DirectoryFilesystemIdentity>()
        .map_err(|error| {
            remote_error_with_details(
                "artifact_parent_identity_invalid",
                "a durable artifact destination parent has an invalid filesystem identity",
                "Do not use the artifact; preserve the local job and inspect its immutable revision.",
                vec![error.to_string()],
            )
        })?;
    if parent_identity != binding.parent_identity {
        return Err(remote_error(
            "artifact_parent_identity_changed",
            "a durable artifact parent differs from its retained live filesystem binding",
            "Do not use the artifact; preserve the local job and reconcile its exact intended destination.",
        ));
    }
    verify_directory_identity(parent.as_std_path(), &parent_identity).map_err(|error| {
        remote_error_with_details(
            "artifact_parent_identity_changed",
            "a durable artifact destination parent changed before final validation",
            "Do not use the artifact; preserve the local job and reconcile its intended destination.",
            vec![error.to_string()],
        )
    })?;
    let identity = identity
        .parse::<RegularFileFilesystemIdentity>()
        .map_err(|error| {
            remote_error_with_details(
                "durable_artifact_identity_invalid",
                "a durable artifact has an invalid persistent filesystem identity",
                "Do not use the artifact; preserve the local job ID and inspect its immutable revision.",
                vec![
                    format!("artifact_id={}", artifact.record.artifact_id),
                    error.to_string(),
                ],
            )
        })?;
    let current_identity = independently_validate_artifact_file(artifact, path)?;
    if current_identity != identity {
        return Err(remote_error_with_details(
            "durable_artifact_identity_changed",
            "a durable artifact path no longer names its validated filesystem object",
            "Do not use the artifact; preserve the local job ID and inspect the path replacement.",
            vec![format!("artifact_id={}", artifact.record.artifact_id)],
        ));
    }
    let retained = RetainedArtifactValidation::capture(path, &identity, &artifact.record)?;
    verify_directory_identity(parent.as_std_path(), &parent_identity).map_err(|error| {
        remote_error_with_details(
            "artifact_parent_identity_changed",
            "a durable artifact destination parent changed during final validation",
            "Do not use the artifact; preserve the local job and reconcile its intended destination.",
            vec![error.to_string()],
        )
    })?;
    binding.verify(project_binding)?;
    retained.verify()?;
    Ok(retained)
}

fn validate_and_promote_durable_success(
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
) -> Result<Vec<RetainedArtifactValidation>, CliError> {
    validate_and_promote_durable_success_with_hook(
        store,
        local_job_id,
        project_binding,
        destinations,
        |_| {},
    )
}

fn retain_exact_durable_success(
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
) -> Result<Vec<RetainedArtifactValidation>, CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.state != StoredJobState::Succeeded
        || latest.terminal_outcome != Some(StoredBuildOutcome::Succeeded)
        || latest.cleanup_status != StoredCleanupStatus::Confirmed
        || latest.artifacts.is_empty()
        || latest.artifacts.len() != destinations.len()
        || latest.artifacts.iter().any(|artifact| {
            !artifact.locally_validated
                || artifact.local_path.is_none()
                || artifact.local_file_identity.is_none()
        })
    {
        return Err(remote_error(
            "durable_job_incomplete",
            "the retry child lacks complete durable success, artifact, or cleanup evidence",
            "Preserve the child and reconcile its exact artifact lifecycle before reporting success.",
        ));
    }
    let mut retained = Vec::with_capacity(latest.artifacts.len());
    for artifact in &latest.artifacts {
        let binding = destinations
            .get(&artifact.record.artifact_id)
            .ok_or_else(|| {
                remote_error(
                    "durable_artifact_binding_missing",
                    "a durable artifact lacks its exact live destination binding",
                    "Preserve the child and reconcile every intended artifact destination.",
                )
            })?;
        retained.push(validate_durable_artifact_for_promotion(
            artifact,
            binding,
            project_binding,
        )?);
    }
    for guard in &retained {
        guard.verify()?;
    }
    project_binding.verify()?;
    Ok(retained)
}

fn retain_completed_artifact_downloads(
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    expected_downloads: &[ExpectedDownload],
    artifact_path: &Utf8Path,
) -> Result<CompletedArtifactDownloads, CliError> {
    let latest = store.latest(local_job_id)?;
    let provider_job_id = latest.provider_job_id.as_deref().ok_or_else(|| {
        remote_error(
            "provider_job_identity_missing",
            "the completed retry child lacks its exact provider job identifier",
            "Preserve the child and inspect its immutable success checkpoint.",
        )
    })?;
    if !durable_cleanup_is_confirmed(&latest, provider_job_id) {
        return Err(remote_error(
            "durable_cleanup_evidence_missing",
            "the completed retry child lacks exact provider cleanup evidence",
            "Preserve the child and reconcile its immutable provider cleanup checkpoint.",
        ));
    }
    let mut destinations = BTreeMap::new();
    let mut primary_sha256 = None;
    for expected in expected_downloads {
        let mut matches = latest
            .artifacts
            .iter()
            .filter(|artifact| artifact.record.kind == expected.kind);
        let artifact = matches.next().ok_or_else(|| {
            remote_error(
                "durable_artifact_binding_missing",
                "the completed retry child lacks an expected durable artifact",
                "Preserve the child and inspect its exact artifact records.",
            )
        })?;
        if matches.next().is_some()
            || artifact.download_destination.as_deref() != Some(expected.path.as_str())
        {
            return Err(remote_error(
                "durable_artifact_binding_mismatch",
                "the completed retry child has ambiguous or redirected artifact evidence",
                "Preserve the child and do not report or overwrite its local artifacts.",
            ));
        }
        let binding = DownloadDestinationBinding::capture(&expected.path, project_binding)?;
        if destinations
            .insert(artifact.record.artifact_id.clone(), binding)
            .is_some()
        {
            return Err(remote_error(
                "durable_artifact_binding_mismatch",
                "the completed retry child reused an artifact identifier",
                "Preserve the child and inspect its immutable artifact records.",
            ));
        }
        if expected.path == artifact_path {
            primary_sha256 = Some(artifact.record.sha256.clone());
        }
    }
    let validation_guards =
        retain_exact_durable_success(store, local_job_id, project_binding, &destinations)?;
    Ok(CompletedArtifactDownloads {
        primary_sha256: primary_sha256.ok_or_else(|| {
            remote_error(
                "artifact_missing",
                "the completed retry child lacks its primary local artifact",
                "Preserve the child and inspect its immutable artifact records.",
            )
        })?,
        destinations,
        validation_guards,
    })
}

fn finish_completed_downloads(
    provider: &GithubProvider,
    store: &JobStore,
    local_job_id: &LocalJobId,
    job_id: &str,
    project_binding: &ProjectFilesystemBinding,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
) -> Result<Vec<RetainedArtifactValidation>, CliError> {
    match store.latest(local_job_id)?.state {
        StoredJobState::Downloaded => persist_validating(store, local_job_id)?,
        StoredJobState::Validating
        | StoredJobState::CleanupPending
        | StoredJobState::CleanupFailed
        | StoredJobState::Succeeded => {}
        _ => {
            return Err(remote_error(
                "artifact_validation_phase_mismatch",
                "the durable job cannot resume final artifact validation from its current state",
                "Preserve the job and reconcile its exact download and cleanup checkpoints.",
            ));
        }
    }
    if store.latest(local_job_id)?.state == StoredJobState::Validating {
        persist_validation_ready_for_cleanup(store, local_job_id)?;
    }
    let latest = store.latest(local_job_id)?;
    if latest.state == StoredJobState::Succeeded {
        return retain_exact_durable_success(store, local_job_id, project_binding, destinations);
    }
    cleanup_job_durably(provider, store, local_job_id, job_id, project_binding)?;
    let latest = store.latest(local_job_id)?;
    if latest.state == StoredJobState::Succeeded {
        return retain_exact_durable_success(store, local_job_id, project_binding, destinations);
    }
    validate_and_promote_durable_success(store, local_job_id, project_binding, destinations)
}

fn validate_and_promote_durable_success_with_hook(
    store: &JobStore,
    local_job_id: &LocalJobId,
    project_binding: &ProjectFilesystemBinding,
    destinations: &BTreeMap<String, DownloadDestinationBinding>,
    mut after_artifact_validation: impl FnMut(usize),
) -> Result<Vec<RetainedArtifactValidation>, CliError> {
    let latest = store.latest(local_job_id)?;
    if latest.state != StoredJobState::CleanupPending
        || latest.terminal_outcome != Some(StoredBuildOutcome::Succeeded)
        || latest.cleanup_status != StoredCleanupStatus::Confirmed
        || latest.artifacts.is_empty()
        || latest.artifacts.len() != destinations.len()
        || latest.artifacts.iter().any(|artifact| {
            artifact.local_path.is_none()
                || artifact.download_parent_identity.is_none()
                || artifact.local_file_identity.is_none()
                || artifact.locally_validated
        })
    {
        return Err(remote_error(
            "durable_job_incomplete",
            "the remote build cleanup completed without an exact pending local-validation record",
            "Preserve the local job ID and inspect its latest immutable revision before using the artifacts.",
        ));
    }
    project_binding.verify()?;
    let mut retained_artifacts = Vec::with_capacity(latest.artifacts.len());
    for (index, artifact) in latest.artifacts.iter().enumerate() {
        let binding = destinations
            .get(&artifact.record.artifact_id)
            .ok_or_else(|| {
                remote_error(
                    "durable_artifact_binding_missing",
                    "a durable artifact lacks its retained live destination binding",
                    "Do not use the artifacts; preserve the local job and reconcile every intended destination.",
                )
            })?;
        retained_artifacts.push(validate_durable_artifact_for_promotion(
            artifact,
            binding,
            project_binding,
        )?);
        after_artifact_validation(index);
    }
    for binding in destinations.values() {
        binding.verify(project_binding)?;
    }
    for retained in &retained_artifacts {
        retained.verify()?;
    }
    project_binding.verify()?;
    let promoted = update_stored_job(store, local_job_id, |previous, next| {
        if previous.revision != latest.revision
            || previous.state != StoredJobState::CleanupPending
            || previous.terminal_outcome != Some(StoredBuildOutcome::Succeeded)
            || previous.cleanup_status != StoredCleanupStatus::Confirmed
            || previous.artifacts != latest.artifacts
        {
            return Err(JobStoreError::InvalidRecord {
                reason: "local success promotion raced a different durable revision",
            });
        }
        for artifact in &mut next.artifacts {
            artifact.locally_validated = true;
        }
        next.state = StoredJobState::Succeeded;
        next.last_confirmed_state = Some(StoredJobState::Succeeded);
        Ok(())
    });
    if let Err(error) = promoted {
        let reconciled = store
            .latest(local_job_id)
            .is_ok_and(|job| is_exact_success_promotion(&latest, &job));
        if !reconciled {
            return Err(error);
        }
    }
    for retained in &retained_artifacts {
        retained.verify()?;
    }
    for binding in destinations.values() {
        binding.verify(project_binding)?;
    }
    project_binding.verify()?;
    Ok(retained_artifacts)
}

fn provider_call<T>(
    future: ProviderFuture<'_, T>,
    code: &'static str,
    message: &'static str,
) -> Result<T, CliError> {
    match poll_provider_once(future) {
        ImmediateProviderResult::Ready(result) => {
            result.map_err(|error| provider_failure(&error, code, message))
        }
        ImmediateProviderResult::Pending => Err(provider_runtime_required()),
    }
}

fn poll_provider_once<T>(mut future: ProviderFuture<'_, T>) -> ImmediateProviderResult<T> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => ImmediateProviderResult::Ready(result),
        Poll::Pending => ImmediateProviderResult::Pending,
    }
}

fn provider_failure(
    error: &rustferry_remote::RemoteBuildError,
    code: &'static str,
    message: &'static str,
) -> CliError {
    remote_error_with_details(
        code,
        message,
        "Check provider authentication, repository state, and the exact job before retrying.",
        vec![error.to_string()],
    )
}

fn provider_runtime_required() -> CliError {
    remote_error(
        "provider_runtime_required",
        "the provider returned a pending future without a configured async runtime",
        "Use the synchronous GitHub provider adapter supplied with this cargo-ferry version.",
    )
}

fn workflow_from_stored(stored: &StoredGithubConfig) -> Result<WorkflowConfig, CliError> {
    let filename = WorkflowFileName::new(stored.workflow_file.clone());
    let environment = ProtectedEnvironment::new(stored.protected_environment.clone());
    let worker = WorkerDistribution::from_source(
        stored.worker_repository.clone(),
        stored.worker_revision.clone(),
        stored.worker_version.clone(),
    );
    let public_source = PublicSourceRepository::new(stored.source_repository.clone());
    let trusted = TrustedSourceRef::new(stored.trusted_source_ref.clone());
    let namespace = TemporaryBranchNamespace::new(stored.temporary_namespace.clone());
    let (Ok(filename), Ok(environment), Ok(worker), Ok(public_source), Ok(trusted), Ok(namespace)) = (
        filename,
        environment,
        worker,
        public_source,
        trusted,
        namespace,
    ) else {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub workflow configuration is invalid",
            "Remove the generated provider config and rerun GitHub setup with exact safe values.",
        ));
    };
    let secret_names = if stored.signing_targets.is_empty() {
        SigningSecretNames::goal3_defaults()
    } else {
        SigningSecretNames::for_targets(&stored.signing_targets).map_err(|error| {
            remote_error_with_details(
                "invalid_provider_config",
                "the stored target graph cannot form a static signing-secret map",
                "Rerun GitHub setup from the current validated target graph.",
                vec![error.to_string()],
            )
        })?
    };
    WorkflowConfig::new_with_run_trigger(
        filename,
        environment,
        secret_names,
        worker,
        public_source,
        trusted,
        namespace,
        stored.run_trigger.into(),
    )
    .map_err(|error| {
        remote_error_with_details(
            "invalid_provider_config",
            "the stored GitHub workflow policy is invalid",
            "Remove the generated provider config and rerun GitHub setup.",
            vec![error.to_string()],
        )
    })
}

fn validate_stored_config(stored: &StoredGithubConfig) -> Result<(), CliError> {
    if (1..CONFIG_SCHEMA_VERSION).contains(&stored.schema_version) {
        return Err(configuration_upgrade_required());
    }
    if stored.schema_version != CONFIG_SCHEMA_VERSION
        || stored.workflow_file != WORKFLOW_FILE
        || stored.protected_environment != PROTECTED_ENVIRONMENT
        || stored.temporary_namespace != TEMPORARY_NAMESPACE
    {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub provider config has an unsupported schema or fixed policy",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
    if stored.signing_targets.is_empty() {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub provider target-map schema is inconsistent",
            "Rerun GitHub setup from the current validated target graph.",
        ));
    }
    let source_endpoints =
        stored_remote_snapshot(&stored.source_fetch_endpoint, &stored.source_push_endpoint)?;
    let execution_endpoints = stored_remote_snapshot(
        &stored.execution_fetch_endpoint,
        &stored.execution_push_endpoint,
    )?;
    validate_execution_endpoint_transports(
        execution_endpoints.fetch(),
        execution_endpoints.push(),
    )?;
    let (_, execution_slug, execution_repository) = parse_repository_spec(&stored.repository)?;
    let (_, source_slug, source) = parse_repository_spec(&stored.source_repository)?;
    let (_, _, worker_repository) = parse_repository_spec(&stored.worker_repository)?;
    if execution_slug != stored.repository
        || source != stored.source_repository
        || worker_repository != stored.worker_repository
        || (worker_repository == execution_repository && execution_slug != source_slug)
        || source_endpoints.fetch().repository_slug() != source_slug
        || execution_endpoints.fetch().repository_slug() != execution_slug
    {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub repository identity is inconsistent",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
    if stored.signing.is_some() && execution_slug == source_slug {
        return Err(remote_error(
            "invalid_provider_config",
            "signed builds require distinct public-source and private-execution repositories",
            "Configure a separate private GitHub execution remote and rerun setup.",
        ));
    }
    workflow_from_stored(stored)?;
    if let Some(signing) = &stored.signing {
        validate_github_signing_plan(signing)?;
        if !stored.signing_targets.is_empty() && signing.targets != stored.signing_targets {
            return Err(remote_error(
                "signing_target_graph_mismatch",
                "the stored signing plan differs from the workflow's static target-secret map",
                "Rerun GitHub setup and signing setup from one unchanged target graph.",
            ));
        }
    }
    Ok(())
}

fn provider_config_lock_for_signing(
    root: &Utf8Path,
    path: &Utf8Path,
    mutating: bool,
) -> Result<Option<ProviderConfigLock>, CliError> {
    if mutating {
        acquire_provider_config_lock(root, path).map(Some)
    } else {
        Ok(None)
    }
}

fn acquire_provider_config_lock(
    root: &Utf8Path,
    path: &Utf8Path,
) -> Result<ProviderConfigLock, CliError> {
    acquire_provider_config_lock_with_interlock(root, path, || {})
}

#[cfg(unix)]
fn open_provider_config_lock_file(path: &Utf8Path) -> Result<File, CliError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|source| CliError::Io {
        action: "open provider-config lock",
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect open provider-config lock",
        path: path.to_owned(),
        source,
    })?;
    require_single_link(&metadata, "provider-config lock")?;
    require_private_mode(path, &metadata)?;
    Ok(file)
}

#[cfg(windows)]
fn open_provider_config_lock_file(path: &Utf8Path) -> Result<File, CliError> {
    use std::os::windows::io::AsHandle as _;

    let file = match fs::symlink_metadata(path) {
        Ok(_) => rustferry_core::windows_private_directory::open_private_file(path.as_std_path())
            .map_err(|error| {
            if error.os_code() == Some(32) {
                remote_error(
                    "provider_config_busy",
                    "another RustFerry command is updating the GitHub provider config",
                    "Wait for that command to finish, then rerun signing setup.",
                )
            } else {
                map_windows_private_provider_error(&error)
            }
        })?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            rustferry_core::windows_private_directory::create_private_file(path.as_std_path())
                .map_err(|error| map_windows_private_provider_error(&error))?
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect provider-config lock",
                path: path.to_owned(),
                source,
            });
        }
    };
    rustferry_core::windows_private_directory::verify_private_file_handle(file.as_handle())
        .map_err(|error| map_windows_private_provider_error(&error))?;
    Ok(file)
}

fn acquire_provider_config_lock_with_interlock(
    root: &Utf8Path,
    path: &Utf8Path,
    after_recovery_preflight: impl FnOnce(),
) -> Result<ProviderConfigLock, CliError> {
    if path != root.join(CONFIG_LOCK_RELATIVE_PATH) {
        return Err(remote_error(
            "unsafe_provider_config_lock",
            "the provider-config lock path is not the fixed project-local path",
            "Use the standard generated GitHub provider directory.",
        ));
    }
    reject_linked_components(root, Utf8Path::new("target/ferry/github"), false)?;
    let parent = path.parent().ok_or_else(|| {
        remote_error(
            "unsafe_provider_config_lock",
            "the provider-config lock has no parent directory",
            "Use the standard generated GitHub provider directory.",
        )
    })?;
    #[cfg(unix)]
    require_private_directory(parent, "GitHub provider config lock")?;
    #[cfg(windows)]
    let parent_guard =
        rustferry_core::windows_private_directory::open_private_directory(parent.as_std_path())
            .map_err(|error| {
                if error.os_code() == Some(32) {
                    remote_error(
                        "provider_config_busy",
                        "another RustFerry command is updating the GitHub provider config",
                        "Wait for that command to finish, then rerun signing setup.",
                    )
                } else {
                    map_windows_private_provider_error(&error)
                }
            })?;
    reject_config_recovery_entries(parent)?;
    after_recovery_preflight();
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file() || metadata.file_type().is_symlink())
    {
        return Err(remote_error(
            "unsafe_provider_config_lock",
            "the provider-config lock path is linked or not a regular file",
            "Remove the unsafe generated lock entry and retry.",
        ));
    }

    let file = open_provider_config_lock_file(path)?;
    let opened = ArtifactFileIdentity::from_file(&file).map_err(|source| CliError::Io {
        action: "identify open provider-config lock",
        path: path.to_owned(),
        source,
    })?;
    let linked = ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
        action: "identify provider-config lock path",
        path: path.to_owned(),
        source,
    })?;
    if opened != linked {
        return Err(remote_error(
            "unsafe_provider_config_lock",
            "the provider-config lock path changed while it was opened",
            "Stop concurrent filesystem changes and retry.",
        ));
    }
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| {
        remote_error(
            "provider_config_busy",
            "another RustFerry command is updating the GitHub provider config",
            "Wait for that command to finish, then rerun signing setup.",
        )
    })?;
    let locked = ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
        action: "reidentify locked provider-config path",
        path: path.to_owned(),
        source,
    })?;
    if locked != opened {
        return Err(remote_error(
            "unsafe_provider_config_lock",
            "the provider-config lock path changed during acquisition",
            "Stop concurrent filesystem changes and retry.",
        ));
    }
    reject_config_recovery_entries(parent)?;
    Ok(ProviderConfigLock {
        _file: file,
        #[cfg(windows)]
        _parent: parent_guard,
    })
}

#[cfg(unix)]
fn require_single_link(metadata: &fs::Metadata, label: &'static str) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.nlink() != 1 {
        return Err(remote_error_with_details(
            "unsafe_generated_path",
            "private provider metadata has multiple hard links",
            "Replace the generated entry with one private regular file and retry.",
            vec![format!("role={label}")],
        ));
    }
    Ok(())
}

fn reject_config_recovery_entries(parent: &Utf8Path) -> Result<(), CliError> {
    let entries = fs::read_dir(parent).map_err(|source| CliError::Io {
        action: "inspect provider-config recovery entries",
        path: parent.to_owned(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| CliError::Io {
            action: "inspect provider-config recovery entry",
            path: parent.to_owned(),
            source,
        })?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(CONFIG_BACKUP_PREFIX) {
            return Err(remote_error_with_details(
                "provider_config_recovery_required",
                "a preserved provider-config transaction requires inspection",
                "Restore or remove the preserved transaction only after comparing it with the current provider config.",
                vec![format!("recovery={}", entry.path().display())],
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileState {
    length: u64,
    modified: Option<std::time::SystemTime>,
}

impl ConfigFileState {
    fn capture(metadata: &fs::Metadata) -> Result<Self, CliError> {
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(remote_error(
                "invalid_provider_config",
                "the GitHub provider config is not a bounded regular file",
                "Restore the original private provider config and rerun setup.",
            ));
        }
        #[cfg(unix)]
        require_single_link(metadata, "provider_config")?;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

fn identify_config_file(
    file: &File,
    path: &Utf8Path,
    action: &'static str,
) -> Result<ArtifactFileIdentity, CliError> {
    ArtifactFileIdentity::from_file(file).map_err(|source| CliError::Io {
        action,
        path: path.to_owned(),
        source,
    })
}

fn identify_config_path(
    path: &Utf8Path,
    action: &'static str,
) -> Result<ArtifactFileIdentity, CliError> {
    ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
        action,
        path: path.to_owned(),
        source,
    })
}

fn read_private_config_snapshot(
    root: &Utf8Path,
    path: &Utf8Path,
) -> Result<(ArtifactFileIdentity, Vec<u8>), CliError> {
    if path != root.join(CONFIG_RELATIVE_PATH) {
        return Err(remote_error(
            "unsafe_provider_config",
            "the GitHub provider config is not at its fixed project-local path",
            "Use the standard generated GitHub provider config.",
        ));
    }
    reject_linked_components(root, Utf8Path::new(CONFIG_RELATIVE_PATH), true)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(remote_error(
                "remote_not_configured",
                "the GitHub remote provider is not configured for this project",
                "Run `cargo ferry remote setup github --worker-revision <exact-commit>` first.",
            ));
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect GitHub provider config",
                path: path.to_owned(),
                source,
            });
        }
    }
    read_private_config_file(path)
}

fn read_private_config_file(path: &Utf8Path) -> Result<(ArtifactFileIdentity, Vec<u8>), CliError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let initial_metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect private provider file",
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    require_private_mode(path, &initial_metadata)?;
    let initial = ConfigFileState::capture(&initial_metadata)?;

    #[cfg(unix)]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options.open(path).map_err(|source| CliError::Io {
            action: "open GitHub provider config snapshot",
            path: path.to_owned(),
            source,
        })?
    };
    #[cfg(windows)]
    let file = rustferry_core::windows_private_directory::open_private_file_for_removal(
        path.as_std_path(),
    )
    .map_err(|error| map_windows_private_provider_error(&error))?;
    let opened_metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect open GitHub provider config",
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    require_private_mode(path, &opened_metadata)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;

        rustferry_core::windows_private_directory::verify_private_file_handle(file.as_handle())
            .map_err(|error| map_windows_private_provider_error(&error))?;
    }
    let opened = ConfigFileState::capture(&opened_metadata)?;
    let opened_identity =
        identify_config_file(&file, path, "identify open GitHub provider config")?;
    let linked_identity = identify_config_path(path, "identify GitHub provider config path")?;
    if opened != initial || linked_identity != opened_identity {
        return Err(provider_config_changed());
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(initial.length.min(MAX_CONFIG_BYTES)).unwrap_or(256 * 1024),
    );
    (&file)
        .take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read GitHub provider config snapshot",
            path: path.to_owned(),
            source,
        })?;
    let final_handle_state =
        ConfigFileState::capture(&file.metadata().map_err(|source| CliError::Io {
            action: "reinspect open GitHub provider config",
            path: path.to_owned(),
            source,
        })?)?;
    let final_handle_identity =
        identify_config_file(&file, path, "reidentify open GitHub provider config")?;
    let final_path_metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "reinspect GitHub provider config path",
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    require_private_mode(path, &final_path_metadata)?;
    let final_path_state = ConfigFileState::capture(&final_path_metadata)?;
    let final_path_identity = identify_config_path(path, "reidentify GitHub provider config path")?;
    if bytes.len() as u64 != initial.length
        || final_handle_state != initial
        || final_path_state != initial
        || final_handle_identity != opened_identity
        || final_path_identity != opened_identity
    {
        return Err(provider_config_changed());
    }
    Ok((opened_identity, bytes))
}

fn provider_config_changed() -> CliError {
    remote_error(
        "provider_config_changed",
        "the GitHub provider config changed during signing setup",
        "Inspect the concurrent change and rerun signing setup from a stable config.",
    )
}

fn load_config(root: &Utf8Path) -> Result<StoredGithubConfig, CliError> {
    let path = root.join(CONFIG_RELATIVE_PATH);
    let (_, bytes) = read_private_config_snapshot(root, &path)?;
    let stored = decode_stored_config(&bytes)?;
    validate_stored_config(&stored)?;
    Ok(stored)
}

fn decode_stored_config(bytes: &[u8]) -> Result<StoredGithubConfig, CliError> {
    #[derive(Deserialize)]
    struct SchemaProbe {
        schema_version: u32,
    }

    serde_json::from_slice::<StoredGithubConfig>(bytes).map_err(|_| {
        if serde_json::from_slice::<SchemaProbe>(bytes)
            .is_ok_and(|probe| (1..CONFIG_SCHEMA_VERSION).contains(&probe.schema_version))
        {
            configuration_upgrade_required()
        } else {
            remote_error(
                "invalid_provider_config",
                "the GitHub provider config is malformed or contains unknown fields",
                "Remove the generated config and rerun GitHub setup.",
            )
        }
    })
}

fn configuration_upgrade_required() -> CliError {
    remote_error(
        "configuration_upgrade_required",
        "the GitHub provider config predates immutable Git endpoint binding",
        "After reviewing and moving the generated provider config aside, rerun GitHub setup to capture canonical fetch and push endpoints; remote names are never reconstructed at runtime.",
    )
}

fn load_config_for_build(
    root: &Utf8Path,
) -> Result<(StoredGithubConfig, ProviderConfigLock), CliError> {
    let _ = load_config(root)?;
    let lock_path = root.join(CONFIG_LOCK_RELATIVE_PATH);
    let lock = acquire_provider_config_lock(root, &lock_path)?;
    let stored = load_config(root)?;
    Ok((stored, lock))
}

fn encode_stored_config(stored: &StoredGithubConfig) -> Result<Vec<u8>, CliError> {
    let mut bytes = serde_json::to_vec_pretty(stored).map_err(|error| {
        remote_error_with_details(
            "provider_config_encoding_failed",
            "the GitHub provider config could not be encoded",
            "Validate the public provider and signing metadata.",
            vec![error.to_string()],
        )
    })?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(remote_error(
            "provider_config_too_large",
            "the encoded GitHub provider config exceeds its storage bound",
            "Reduce public signing metadata and retry setup.",
        ));
    }
    Ok(bytes)
}

fn replace_private_config(
    root: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    expected_original_identity: ArtifactFileIdentity,
    expected_original_bytes: &[u8],
    expected_installed: &StoredGithubConfig,
    _config_lock: &ProviderConfigLock,
) -> Result<(), ConfigCommitError> {
    replace_private_config_with(
        root,
        path,
        bytes,
        expected_original_identity,
        expected_original_bytes,
        expected_installed,
        |_| {},
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn replace_private_config_with(
    root: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    expected_original_identity: ArtifactFileIdentity,
    expected_original_bytes: &[u8],
    expected_installed: &StoredGithubConfig,
    before_quarantine: impl FnOnce(&std::path::Path),
    after_quarantine: impl FnOnce(&Utf8Path),
) -> Result<(), ConfigCommitError> {
    let StagedPrivateConfig { temporary, parent } = stage_private_config(
        root,
        path,
        bytes,
        &expected_original_identity,
        expected_original_bytes,
    )
    .map_err(|error| ConfigCommitError::NotCommitted(Box::new(error)))?;
    #[cfg(not(windows))]
    before_quarantine(temporary.path());
    #[cfg(windows)]
    before_quarantine(temporary.path.as_std_path());
    let quarantine = match ConfigQuarantine::capture(&parent, path) {
        Ok(quarantine) => quarantine,
        Err(error) => {
            return Err(ConfigCommitError::NotCommitted(Box::new(
                cleanup_staged_private_config(temporary, error),
            )));
        }
    };
    let quarantined_snapshot = quarantine.snapshot();
    let quarantine_matches = quarantined_snapshot
        .as_ref()
        .is_ok_and(|(identity, current)| {
            identity == &expected_original_identity && current == expected_original_bytes
        });
    if !quarantine_matches {
        let cause = quarantined_snapshot
            .err()
            .unwrap_or_else(provider_config_changed);
        let error = restore_config_or_preserve(quarantine, path, cause);
        return Err(cleanup_staged_private_config_commit(temporary, error));
    }
    drop(quarantined_snapshot);
    drop(expected_original_identity);
    #[cfg(unix)]
    {
        if let Err(error) = sync_private_config_directory(&parent) {
            return Err(restore_config_or_preserve(quarantine, path, error));
        }
    }
    after_quarantine(&quarantine.path);

    let installed = match temporary.persist_noclobber(path) {
        Ok(file) => file,
        Err(error) => {
            let recovery = quarantine.keep();
            return Err(ConfigCommitError::CommittedNeedsInspection(Box::new(
                remote_error_with_details(
                    "provider_config_commit_uncertain",
                    "the provider config could not be installed without overwriting a concurrent path",
                    "Inspect the current provider config and the preserved original before retrying.",
                    vec![format!("recovery={recovery}"), error.to_string()],
                ),
            )));
        }
    };
    drop(installed);
    if let Err(error) = finish_private_config_commit(root, &parent, expected_installed) {
        let recovery = quarantine.keep();
        return Err(ConfigCommitError::CommittedNeedsInspection(Box::new(
            remote_error_with_details(
                "provider_config_commit_uncertain",
                "the updated provider config could not be verified after installation",
                "Inspect the installed provider config and the preserved original before building.",
                vec![format!("recovery={recovery}"), error.to_string()],
            ),
        )));
    }
    quarantine.delete().map_err(|failure| {
        ConfigCommitError::CommittedNeedsInspection(Box::new(remote_error_with_details(
            "provider_config_cleanup_uncertain",
            "the verified provider-config backup could not be completely removed",
            "Inspect the reported provider paths before retrying.",
            failure.details(),
        )))
    })?;
    #[cfg(unix)]
    sync_private_config_directory(&parent)
        .map_err(|error| ConfigCommitError::CommittedNeedsInspection(Box::new(error)))?;
    Ok(())
}

struct StagedPrivateConfig {
    temporary: PrivateConfigStaging,
    parent: Utf8PathBuf,
}

#[cfg(not(windows))]
type PrivateConfigStaging = tempfile::NamedTempFile;

#[derive(Debug)]
struct ConfigRecoveryFailure {
    inspection_paths: Vec<Utf8PathBuf>,
    source: std::io::Error,
}

impl ConfigRecoveryFailure {
    fn new(
        inspection_paths: impl IntoIterator<Item = Utf8PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self {
            inspection_paths: inspection_paths.into_iter().collect(),
            source,
        }
    }

    fn details(&self) -> Vec<String> {
        let mut details = self
            .inspection_paths
            .iter()
            .map(|path| format!("inspect={path}"))
            .collect::<Vec<_>>();
        details.push(self.source.to_string());
        details
    }
}

#[cfg(windows)]
struct PrivateConfigStaging {
    file: Option<File>,
    path: Utf8PathBuf,
}

#[cfg(windows)]
impl PrivateConfigStaging {
    fn create(parent: &Utf8Path, target: &Utf8Path) -> Result<Self, CliError> {
        let filename = target.file_name().unwrap_or("provider.json");
        let path = parent.join(format!(".{filename}.{}.tmp", Uuid::new_v4().simple()));
        let file = rustferry_core::windows_private_directory::create_private_staging_file(
            path.as_std_path(),
        )
        .map_err(|error| map_windows_private_provider_error(&error))?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }

    fn as_file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("private staging file")
    }

    fn cleanup_with_cause(mut self, cause: CliError) -> CliError {
        let file = self.file.take().expect("private staging file");
        match rustferry_core::windows_private_directory::remove_private_file_handle(file) {
            Ok(()) => cause,
            Err(cleanup) => remote_error_with_details(
                "provider_config_cleanup_uncertain",
                "a private Windows provider staging file could not be removed after the transaction stopped",
                "Inspect the generated provider directory before retrying.",
                vec![
                    format!("staging={}", self.path),
                    cause.to_string(),
                    cleanup.to_string(),
                ],
            ),
        }
    }

    fn persist_noclobber(mut self, destination: &Utf8Path) -> Result<File, std::io::Error> {
        use rustferry_core::windows_private_directory::PrivateFileLinkState;
        use std::os::windows::io::AsHandle as _;

        let file = self.file.take().expect("private staging file");
        let identity = ArtifactFileIdentity::from_file(&file)?;
        if let Err(source) = fs::hard_link(&self.path, destination) {
            return match rustferry_core::windows_private_directory::remove_private_file_handle(file)
            {
                Ok(()) => Err(source),
                Err(cleanup) => Err(std::io::Error::other(format!(
                    "{source}; staging cleanup failed: {cleanup}"
                ))),
            };
        }
        rustferry_core::windows_private_directory::verify_private_file_handle_in_state(
            file.as_handle(),
            PrivateFileLinkState::PublicationPair,
        )
        .map_err(std::io::Error::other)?;
        if ArtifactFileIdentity::capture(destination)? != identity {
            return Err(std::io::Error::other(
                "published provider config changed identity",
            ));
        }
        drop(identity);
        rustferry_core::windows_private_directory::remove_private_file_handle_in_state(
            file,
            PrivateFileLinkState::PublicationPair,
        )
        .map_err(std::io::Error::other)?;
        rustferry_core::windows_private_directory::open_private_file(destination.as_std_path())
            .map_err(std::io::Error::other)
    }
}

#[cfg(windows)]
impl Drop for PrivateConfigStaging {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = rustferry_core::windows_private_directory::remove_private_file_handle(file);
        }
    }
}

#[cfg(not(windows))]
struct ConfigQuarantine {
    directory: tempfile::TempDir,
    path: Utf8PathBuf,
}

#[cfg(windows)]
struct ConfigQuarantine {
    directory: Option<File>,
    file: Option<File>,
    path: Utf8PathBuf,
}

#[cfg(not(windows))]
impl ConfigQuarantine {
    fn capture(parent: &Utf8Path, path: &Utf8Path) -> Result<Self, CliError> {
        let directory = tempfile::Builder::new()
            .prefix(CONFIG_BACKUP_PREFIX)
            .tempdir_in(parent)
            .map_err(|source| CliError::Io {
                action: "create provider-config backup directory",
                path: parent.to_owned(),
                source,
            })?;
        let root = Utf8PathBuf::from_path_buf(directory.path().to_path_buf())
            .map_err(CliError::NonUtf8Path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|source| {
                CliError::Io {
                    action: "secure provider-config backup directory",
                    path: root.clone(),
                    source,
                }
            })?;
        }
        require_private_directory(&root, "provider-config backup")?;
        let quarantined = root.join("provider.json");
        fs::rename(path, &quarantined).map_err(|source| CliError::Io {
            action: "quarantine original provider config",
            path: path.to_owned(),
            source,
        })?;
        Ok(Self {
            directory,
            path: quarantined,
        })
    }

    fn keep(self) -> Utf8PathBuf {
        let path = self.path.clone();
        let _ = self.directory.keep();
        path
    }

    fn snapshot(&self) -> Result<(ArtifactFileIdentity, Vec<u8>), CliError> {
        read_private_config_file(&self.path)
    }

    fn restore_noclobber(self, destination: &Utf8Path) -> Result<(), ConfigRecoveryFailure> {
        self.restore_noclobber_with(destination, || Ok(()))
    }

    fn restore_noclobber_with(
        self,
        destination: &Utf8Path,
        after_rename: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<(), ConfigRecoveryFailure> {
        let recovery = self.path.clone();
        let recovery_root = Utf8PathBuf::from_path_buf(self.directory.path().to_path_buf())
            .unwrap_or_else(|_| recovery.clone());
        let temporary = match tempfile::TempPath::try_from_path(self.path.to_path_buf()) {
            Ok(temporary) => temporary,
            Err(source) => {
                let _ = self.directory.keep();
                return Err(ConfigRecoveryFailure::new([recovery], source));
            }
        };
        match temporary.persist_noclobber(destination) {
            Ok(()) => {
                if let Err(source) = after_rename() {
                    let _ = self.directory.keep();
                    return Err(ConfigRecoveryFailure::new(
                        [destination.to_owned(), recovery_root],
                        source,
                    ));
                }
                self.directory.close().map_err(|source| {
                    ConfigRecoveryFailure::new([destination.to_owned(), recovery_root], source)
                })
            }
            Err(mut error) => {
                error.path.disable_cleanup(true);
                let source = error.error;
                drop(error.path);
                let _ = self.directory.keep();
                Err(ConfigRecoveryFailure::new([recovery], source))
            }
        }
    }

    fn delete(self) -> Result<(), ConfigRecoveryFailure> {
        self.delete_with_interlock(|_| Ok(()))
    }

    fn delete_with_interlock(
        self,
        after_file_delete: impl FnOnce(&Utf8Path) -> std::io::Result<()>,
    ) -> Result<(), ConfigRecoveryFailure> {
        let recovery = self.path.clone();
        let recovery_root = Utf8PathBuf::from_path_buf(self.directory.path().to_path_buf())
            .unwrap_or_else(|_| recovery.clone());
        if let Err(source) = fs::remove_file(&self.path) {
            let _ = self.directory.keep();
            return Err(ConfigRecoveryFailure::new([recovery], source));
        }
        if let Err(source) = after_file_delete(&recovery_root) {
            let _ = self.directory.keep();
            return Err(ConfigRecoveryFailure::new([recovery_root], source));
        }
        match self.directory.close() {
            Ok(()) => Ok(()),
            Err(source) => Err(ConfigRecoveryFailure::new([recovery_root], source)),
        }
    }
}

#[cfg(windows)]
impl ConfigQuarantine {
    fn capture(parent: &Utf8Path, path: &Utf8Path) -> Result<Self, CliError> {
        Self::capture_with_interlock(parent, path, |_| {})
    }

    fn capture_with_interlock(
        parent: &Utf8Path,
        path: &Utf8Path,
        after_directory_create: impl FnOnce(&Utf8Path),
    ) -> Result<Self, CliError> {
        let root = parent.join(format!("{CONFIG_BACKUP_PREFIX}{}", Uuid::new_v4().simple()));
        let directory =
            rustferry_core::windows_private_directory::create_private_directory(root.as_std_path())
                .map_err(|error| map_windows_private_provider_error(&error))?;
        after_directory_create(&root);
        let file = match rustferry_core::windows_private_directory::open_private_file_for_removal(
            path.as_std_path(),
        ) {
            Ok(file) => file,
            Err(error) => {
                let primary = map_windows_private_provider_error(&error);
                return match rustferry_core::windows_private_directory::remove_private_directory_handle(
                    directory,
                ) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(remote_error_with_details(
                        "provider_config_recovery_required",
                        "the provider config could not be quarantined and its private backup directory could not be removed",
                        "Inspect the generated provider directory before retrying.",
                        vec![
                            format!("recovery={root}"),
                            primary.to_string(),
                            cleanup.to_string(),
                        ],
                    )),
                };
            }
        };
        let quarantined = root.join("provider.json");
        if let Err(source) = fs::rename(path, &quarantined) {
            let cleanup =
                rustferry_core::windows_private_directory::remove_private_directory_handle(
                    directory,
                );
            return Err(match cleanup {
                Ok(()) => CliError::Io {
                    action: "quarantine original provider config",
                    path: path.to_owned(),
                    source,
                },
                Err(cleanup) => remote_error_with_details(
                    "provider_config_recovery_required",
                    "the provider config could not be quarantined and cleanup is uncertain",
                    "Inspect the generated provider directory before retrying.",
                    vec![source.to_string(), cleanup.to_string()],
                ),
            });
        }
        Ok(Self {
            directory: Some(directory),
            file: Some(file),
            path: quarantined,
        })
    }

    fn snapshot(&self) -> Result<(ArtifactFileIdentity, Vec<u8>), CliError> {
        let file = self.file.as_ref().expect("quarantined provider config");
        let identity = ArtifactFileIdentity::from_file(file).map_err(|source| CliError::Io {
            action: "identify quarantined provider config",
            path: self.path.clone(),
            source,
        })?;
        if ArtifactFileIdentity::capture(&self.path).map_err(|source| CliError::Io {
            action: "identify quarantined provider config path",
            path: self.path.clone(),
            source,
        })? != identity
        {
            return Err(provider_config_changed());
        }
        let metadata = file.metadata().map_err(|source| CliError::Io {
            action: "inspect quarantined provider config",
            path: self.path.clone(),
            source,
        })?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(provider_config_changed());
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len().min(MAX_CONFIG_BYTES)).unwrap_or(256 * 1024),
        );
        file.take(MAX_CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| CliError::Io {
                action: "read quarantined provider config",
                path: self.path.clone(),
                source,
            })?;
        if bytes.len() as u64 != metadata.len() {
            return Err(provider_config_changed());
        }
        Ok((identity, bytes))
    }

    fn keep(mut self) -> Utf8PathBuf {
        let path = self.path.clone();
        drop(self.file.take());
        drop(self.directory.take());
        path
    }

    fn restore_noclobber(self, destination: &Utf8Path) -> Result<(), ConfigRecoveryFailure> {
        self.restore_noclobber_with(destination, || Ok(()))
    }

    fn restore_noclobber_with(
        mut self,
        destination: &Utf8Path,
        after_rename: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<(), ConfigRecoveryFailure> {
        let recovery = self.path.clone();
        let recovery_root = self
            .path
            .parent()
            .map_or_else(|| recovery.clone(), Utf8Path::to_owned);
        let identity = match self.file.as_ref().map(ArtifactFileIdentity::from_file) {
            Some(Ok(identity)) => identity,
            Some(Err(source)) => {
                return Err(ConfigRecoveryFailure::new(
                    [recovery, recovery_root],
                    source,
                ));
            }
            None => {
                return Err(ConfigRecoveryFailure::new(
                    [recovery, recovery_root],
                    std::io::Error::other("missing recovery handle"),
                ));
            }
        };
        if let Err(source) = fs::rename(&self.path, destination) {
            drop(self.file.take());
            drop(self.directory.take());
            return Err(ConfigRecoveryFailure::new(
                [recovery, recovery_root],
                source,
            ));
        }
        if let Err(source) = after_rename() {
            drop(self.file.take());
            drop(self.directory.take());
            return Err(ConfigRecoveryFailure::new(
                [destination.to_owned(), recovery_root],
                source,
            ));
        }
        let restored = match ArtifactFileIdentity::capture(destination) {
            Ok(restored) => restored,
            Err(source) => {
                return Err(ConfigRecoveryFailure::new(
                    [destination.to_owned(), recovery_root],
                    source,
                ));
            }
        };
        if restored != identity {
            return Err(ConfigRecoveryFailure::new(
                [destination.to_owned(), recovery_root],
                std::io::Error::other("restored provider config changed identity"),
            ));
        }
        drop(self.file.take());
        let directory = self.directory.take().expect("provider backup directory");
        rustferry_core::windows_private_directory::remove_private_directory_handle(directory)
            .map_err(|error| {
                ConfigRecoveryFailure::new(
                    [destination.to_owned(), recovery_root],
                    std::io::Error::other(error),
                )
            })
    }

    fn delete(self) -> Result<(), ConfigRecoveryFailure> {
        self.delete_with_interlock(|_| Ok(()))
    }

    fn delete_with_interlock(
        mut self,
        after_file_delete: impl FnOnce(&Utf8Path) -> std::io::Result<()>,
    ) -> Result<(), ConfigRecoveryFailure> {
        let recovery = self.path.clone();
        let recovery_root = self
            .path
            .parent()
            .map_or_else(|| recovery.clone(), Utf8Path::to_owned);
        let file = self.file.take().ok_or_else(|| {
            ConfigRecoveryFailure::new(
                [recovery.clone(), recovery_root.clone()],
                std::io::Error::other("missing recovery handle"),
            )
        })?;
        rustferry_core::windows_private_directory::remove_private_file_handle(file).map_err(
            |error| {
                ConfigRecoveryFailure::new(
                    [recovery, recovery_root.clone()],
                    std::io::Error::other(error),
                )
            },
        )?;
        after_file_delete(&recovery_root)
            .map_err(|source| ConfigRecoveryFailure::new([recovery_root.clone()], source))?;
        let directory = self.directory.take().ok_or_else(|| {
            ConfigRecoveryFailure::new(
                [recovery_root.clone()],
                std::io::Error::other("missing recovery directory handle"),
            )
        })?;
        rustferry_core::windows_private_directory::remove_private_directory_handle(directory)
            .map_err(|error| {
                ConfigRecoveryFailure::new([recovery_root], std::io::Error::other(error))
            })
    }
}

fn restore_config_or_preserve(
    quarantine: ConfigQuarantine,
    destination: &Utf8Path,
    cause: CliError,
) -> ConfigCommitError {
    match quarantine.restore_noclobber(destination) {
        Ok(()) => ConfigCommitError::NotCommitted(Box::new(cause)),
        Err(failure) => {
            let mut details = failure.details();
            details.push(cause.to_string());
            ConfigCommitError::CommittedNeedsInspection(Box::new(remote_error_with_details(
                "provider_config_recovery_required",
                "the changed provider config could not be restored without overwriting another path",
                "Inspect the reported provider paths before retrying.",
                details,
            )))
        }
    }
}

fn stage_private_config(
    root: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    expected_original_identity: &ArtifactFileIdentity,
    expected_original_bytes: &[u8],
) -> Result<StagedPrivateConfig, CliError> {
    stage_private_config_with(
        root,
        path,
        bytes,
        expected_original_identity,
        expected_original_bytes,
        |_| {},
    )
}

fn stage_private_config_with(
    root: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    expected_original_identity: &ArtifactFileIdentity,
    expected_original_bytes: &[u8],
    after_staging_write: impl FnOnce(&std::path::Path),
) -> Result<StagedPrivateConfig, CliError> {
    reject_linked_components(root, Utf8Path::new(CONFIG_RELATIVE_PATH), true)?;
    ensure_config_snapshot_unchanged(
        root,
        path,
        expected_original_identity,
        expected_original_bytes,
    )?;
    let parent = path.parent().ok_or_else(|| {
        remote_error(
            "unsafe_provider_config",
            "the GitHub provider config path has no parent directory",
            "Use the standard project-local provider config path.",
        )
    })?;
    #[cfg(not(windows))]
    let mut temporary = tempfile::Builder::new()
        .prefix(".provider.json.")
        .tempfile_in(parent)
        .map_err(|source| CliError::Io {
            action: "create private temporary provider config",
            path: parent.to_owned(),
            source,
        })?;
    #[cfg(windows)]
    let mut temporary = PrivateConfigStaging::create(parent, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| CliError::Io {
                action: "secure temporary provider config",
                path: path.to_owned(),
                source,
            })?;
    }
    if let Err(source) = temporary
        .as_file_mut()
        .write_all(bytes)
        .and_then(|()| temporary.as_file_mut().sync_all())
    {
        let cause = CliError::Io {
            action: "write temporary provider config",
            path: path.to_owned(),
            source,
        };
        return Err(cleanup_staged_private_config(temporary, cause));
    }
    #[cfg(not(windows))]
    after_staging_write(temporary.path());
    #[cfg(windows)]
    after_staging_write(temporary.path.as_std_path());
    if let Err(cause) = ensure_config_snapshot_unchanged(
        root,
        path,
        expected_original_identity,
        expected_original_bytes,
    ) {
        return Err(cleanup_staged_private_config(temporary, cause));
    }
    Ok(StagedPrivateConfig {
        temporary,
        parent: parent.to_owned(),
    })
}

fn cleanup_staged_private_config(temporary: PrivateConfigStaging, cause: CliError) -> CliError {
    #[cfg(windows)]
    {
        temporary.cleanup_with_cause(cause)
    }
    #[cfg(not(windows))]
    {
        drop(temporary);
        cause
    }
}

fn cleanup_staged_private_config_commit(
    temporary: PrivateConfigStaging,
    error: ConfigCommitError,
) -> ConfigCommitError {
    match error {
        ConfigCommitError::NotCommitted(cause) => ConfigCommitError::NotCommitted(Box::new(
            cleanup_staged_private_config(temporary, *cause),
        )),
        ConfigCommitError::CommittedNeedsInspection(cause) => {
            ConfigCommitError::CommittedNeedsInspection(Box::new(cleanup_staged_private_config(
                temporary, *cause,
            )))
        }
    }
}

fn finish_private_config_commit(
    root: &Utf8Path,
    parent: &Utf8Path,
    expected_installed: &StoredGithubConfig,
) -> Result<(), CliError> {
    #[cfg(unix)]
    sync_private_config_directory(parent)?;
    #[cfg(not(unix))]
    let _ = parent;
    let installed = load_config(root)?;
    if &installed != expected_installed {
        return Err(remote_error(
            "provider_config_update_failed",
            "the updated GitHub provider config does not exactly match the validated signing plan",
            "Stop before building and inspect the private provider config.",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_private_config_directory(parent: &Utf8Path) -> Result<(), CliError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CliError::Io {
            action: "synchronize GitHub provider config directory",
            path: parent.to_owned(),
            source,
        })?;
    Ok(())
}

fn ensure_config_snapshot_unchanged(
    root: &Utf8Path,
    path: &Utf8Path,
    expected_identity: &ArtifactFileIdentity,
    expected_bytes: &[u8],
) -> Result<(), CliError> {
    let (identity, current_bytes) = read_private_config_snapshot(root, path)?;
    if &identity != expected_identity || current_bytes != expected_bytes {
        return Err(provider_config_changed());
    }
    Ok(())
}

fn make_gh_runner(root: &Utf8Path) -> Result<GhProcessRunner, CliError> {
    let gh = executable("gh")?;
    let authentication = if let Some((variable, _)) = selected_environment_token() {
        GhAuthentication::environment_token(variable)
    } else {
        let config = gh_config_directory()?;
        GhAuthentication::config_directory(config).map_err(|error| {
            remote_error_with_details(
                "github_authentication_invalid",
                "GitHub CLI authentication configuration is not usable",
                "Authenticate GitHub API access with `gh auth login` or GH_TOKEN. Temporary-ref publication also needs separately configured SSH or credential-manager Git authentication.",
                vec![error.to_string()],
            )
        })?
    };
    GhProcessRunner::new(&gh, root, authentication).map_err(|error| {
        remote_error_with_details(
            "github_cli_invalid",
            "the GitHub CLI adapter could not be configured",
            "Install a canonical `gh` executable and authenticate it.",
            vec![error.to_string()],
        )
    })
}

fn selected_environment_token() -> Option<(TokenEnvironmentVariable, &'static str)> {
    if std::env::var_os("GH_TOKEN").is_some_and(|value| !value.is_empty()) {
        Some((TokenEnvironmentVariable::GhToken, "GH_TOKEN"))
    } else if std::env::var_os("GITHUB_TOKEN").is_some_and(|value| !value.is_empty()) {
        Some((TokenEnvironmentVariable::GithubToken, "GITHUB_TOKEN"))
    } else {
        None
    }
}

fn gh_config_directory() -> Result<Utf8PathBuf, CliError> {
    let candidate = if let Some(path) = utf8_environment_path("GH_CONFIG_DIR")? {
        Some(path)
    } else if let Some(path) = utf8_environment_path("XDG_CONFIG_HOME")? {
        Some(path.join("gh"))
    } else {
        #[cfg(windows)]
        {
            utf8_environment_path("APPDATA")?.map(|path| path.join("GitHub CLI"))
        }
        #[cfg(not(windows))]
        {
            utf8_environment_path("HOME")?.map(|path| path.join(".config/gh"))
        }
    }
    .ok_or_else(|| {
        remote_error(
            "github_authentication_required",
            "no GitHub CLI authentication directory is configured",
            "Run `gh auth login`, or provide GH_TOKEN through the process environment.",
        )
    })?;
    if !candidate.is_dir() {
        return Err(remote_error_with_details(
            "github_authentication_required",
            "the selected GitHub CLI authentication directory does not exist",
            "Run `gh auth login`, correct the selected configuration environment variable, or provide GH_TOKEN.",
            vec![format!("path={candidate}")],
        ));
    }
    candidate
        .canonicalize_utf8()
        .map_err(|source| CliError::Io {
            action: "resolve GitHub CLI config directory",
            path: candidate,
            source,
        })
}

fn utf8_environment_path(name: &'static str) -> Result<Option<Utf8PathBuf>, CliError> {
    std::env::var_os(name)
        .map(|value| {
            Utf8PathBuf::from_os_string(value).map_err(|value| CliError::NonUtf8Path(value.into()))
        })
        .transpose()
}

fn executable(name: &'static str) -> Result<Utf8PathBuf, CliError> {
    let found = find_in_path(name).ok_or_else(|| CliError::ToolMissing {
        tool: name.to_owned(),
        searched: vec!["PATH".to_owned()],
        help: format!("Install `{name}` and make it available in PATH."),
    })?;
    executable_entrypoint(&found, name)
}

fn executable_entrypoint(found: &Utf8Path, name: &'static str) -> Result<Utf8PathBuf, CliError> {
    let parent = found.parent().unwrap_or(Utf8Path::new("."));
    let directory = parent.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve external tool directory",
        path: parent.to_owned(),
        source,
    })?;
    let filename = found.file_name().ok_or_else(|| CliError::ToolMissing {
        tool: name.to_owned(),
        searched: vec!["PATH".to_owned()],
        help: format!("Install `{name}` and make it available in PATH."),
    })?;
    let entrypoint = directory.join(filename);
    if !entrypoint.is_file() {
        return Err(CliError::ToolMissing {
            tool: name.to_owned(),
            searched: vec!["PATH".to_owned()],
            help: format!("Install `{name}` and make it available in PATH."),
        });
    }
    Ok(entrypoint)
}

fn checked_output(
    program: &Utf8Path,
    arguments: &[OsString],
    directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
) -> Result<Vec<u8>, CliError> {
    let output = run_captured_bounded(
        program,
        arguments,
        directory,
        stage,
        reporter,
        MAX_TOOL_OUTPUT_BYTES,
    )?;
    if !output.status.success() {
        return Err(CliError::CommandFailed {
            tool: program.file_name().unwrap_or(program.as_str()).to_owned(),
            stage,
            status: output.status.code(),
            stderr: String::new(),
            log: None,
            help: "Correct the repository or tool configuration, then rerun with --verbose."
                .to_owned(),
        });
    }
    if output.stdout.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(remote_error(
            "external_output_too_large",
            "an external metadata command exceeded the client output bound",
            "Reduce the project metadata size and retry.",
        ));
    }
    Ok(output.stdout)
}

fn checked_caller_git_output(
    output: Result<CallerGitOutput, GitExecutionError>,
    stage: &'static str,
) -> Result<Vec<u8>, CliError> {
    let output = output.map_err(|_| caller_git_command_error(stage, None))?;
    if !output.success() {
        return Err(caller_git_command_error(stage, output.exit_code()));
    }
    Ok(output.stdout().to_vec())
}

fn caller_git_command_error(stage: &'static str, status: Option<i32>) -> CliError {
    CliError::CommandFailed {
        tool: "git".to_owned(),
        stage,
        status,
        stderr: String::new(),
        log: None,
        help: "Correct the repository state, then rerun with --verbose.".to_owned(),
    }
}

fn caller_git_policy_error(error: GitPublisherConfigError) -> CliError {
    let (code, message, help) = match error {
        GitPublisherConfigError::UnsafeCallerRepositoryConfig => (
            "unsafe_local_git_config",
            "the caller repository has executable or redirecting local Git policy",
            "Remove local include, worktree-redirection, filter, and external-diff commands before retrying.",
        ),
        GitPublisherConfigError::UnsupportedSecurePlatform => (
            "secure_git_platform_unsupported",
            "the platform has no sealed caller-repository Git reader",
            "Run this operation on supported Windows or Unix with the standard trusted Git installation.",
        ),
        _ => (
            "sealed_git_reader_unavailable",
            "the caller repository could not be bound to the sealed Git reader",
            "Install the standard trusted Git toolchain and restore a canonical local repository before retrying.",
        ),
    };
    remote_error_with_details(code, message, help, vec![error.to_string()])
}

fn utf8_line(bytes: &[u8], label: &'static str) -> Result<String, CliError> {
    let value = std::str::from_utf8(bytes).map_err(|_| {
        remote_error(
            "invalid_external_output",
            "an external tool returned non-UTF-8 metadata",
            "Use UTF-8 Git repository and target names.",
        )
    })?;
    let value = value.trim();
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(remote_error_with_details(
            "invalid_external_output",
            "an external tool returned malformed single-line metadata",
            "Inspect the selected Git repository and remote configuration.",
            vec![label.to_owned()],
        ));
    }
    Ok(value.to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingFile {
    Missing,
    Identical,
}

fn preflight_file(
    path: &Utf8Path,
    expected: &[u8],
    private: bool,
) -> Result<ExistingFile, CliError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(ExistingFile::Missing),
        Err(source) => Err(CliError::Io {
            action: "inspect setup target",
            path: path.to_owned(),
            source,
        }),
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(remote_error(
                    "setup_target_unsafe",
                    "GitHub setup refuses a non-regular or linked target file",
                    "Move the unsafe target aside, inspect it, and rerun setup.",
                ));
            }
            if private {
                require_private_mode(path, &metadata)?;
            }
            if metadata.len() > MAX_CONFIG_BYTES.max(expected.len() as u64) {
                return Err(remote_error(
                    "setup_target_conflict",
                    "GitHub setup found an oversized existing target file",
                    "Inspect the existing file manually; setup never overwrites it.",
                ));
            }
            let maximum = MAX_CONFIG_BYTES.max(expected.len() as u64);
            #[cfg(windows)]
            let actual = if private {
                read_bounded_private_file_windows(path, maximum)?
            } else {
                read_bounded_file(path, maximum)?
            };
            #[cfg(not(windows))]
            let actual = read_bounded_file(path, maximum)?;
            if actual == expected {
                Ok(ExistingFile::Identical)
            } else {
                Err(remote_error_with_details(
                    "setup_target_conflict",
                    "GitHub setup found different existing workflow or provider configuration",
                    "Inspect the existing file and reconcile it manually; setup never overwrites it.",
                    vec![format!("path={path}")],
                ))
            }
        }
    }
}

#[cfg(windows)]
fn read_bounded_private_file_windows(path: &Utf8Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let file = rustferry_core::windows_private_directory::open_private_file(path.as_std_path())
        .map_err(|error| map_windows_private_provider_error(&error))?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect private Windows provider file",
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > maximum {
        return Err(remote_error(
            "setup_target_conflict",
            "GitHub setup found an oversized existing private target file",
            "Inspect the existing file manually; setup never overwrites it.",
        ));
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len().min(maximum)).unwrap_or(256 * 1024));
    (&file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read private Windows provider file",
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(remote_error(
            "setup_target_conflict",
            "GitHub setup found an oversized existing private target file",
            "Inspect the existing file manually; setup never overwrites it.",
        ));
    }
    Ok(bytes)
}

fn existing_file_matches(path: &Utf8Path, expected: &[u8]) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CliError::Io {
            action: "inspect generated workflow",
            path: path.to_owned(),
            source,
        }),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if metadata.len() > MAX_CONFIG_BYTES.max(expected.len() as u64) {
                return Ok(false);
            }
            Ok(read_bounded_file(path, MAX_CONFIG_BYTES.max(expected.len() as u64))? == expected)
        }
        Ok(_) => Ok(false),
    }
}

fn write_create_only(path: &Utf8Path, bytes: &[u8], private: bool) -> Result<(), CliError> {
    if preflight_file(path, bytes, private)? == ExistingFile::Identical {
        return Ok(());
    }
    #[cfg(windows)]
    if private {
        return write_private_create_only_windows(path, bytes);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path).map_err(|source| CliError::Io {
        action: "create setup target without overwriting",
        path: path.to_owned(),
        source,
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| CliError::Io {
            action: "write setup target",
            path: path.to_owned(),
            source,
        })
}

#[cfg(windows)]
struct PreparedPrivateProviderStaging {
    file: File,
    path: Utf8PathBuf,
    identity: ArtifactFileIdentity,
}

#[cfg(windows)]
fn prepare_private_provider_staging(
    path: &Utf8Path,
    bytes: &[u8],
) -> Result<PreparedPrivateProviderStaging, CliError> {
    use std::os::windows::io::AsHandle as _;

    let parent = path.parent().ok_or_else(|| {
        remote_error(
            "setup_target_unsafe",
            "the private provider target has no parent directory",
            "Use the standard project-local generated provider path.",
        )
    })?;
    let filename = path.file_name().ok_or_else(|| {
        remote_error(
            "setup_target_unsafe",
            "the private provider target has no file name",
            "Use the standard project-local generated provider path.",
        )
    })?;
    let staging_path = parent.join(format!(".{filename}.{}.tmp", Uuid::new_v4().simple()));
    let mut staging = rustferry_core::windows_private_directory::create_private_staging_file(
        staging_path.as_std_path(),
    )
    .map_err(|error| map_windows_private_provider_error(&error))?;
    if let Err(source) = staging.write_all(bytes).and_then(|()| staging.sync_all()) {
        let original = CliError::Io {
            action: "write private Windows provider staging file",
            path: path.to_owned(),
            source,
        };
        return Err(cleanup_failed_private_provider_staging(
            staging, path, original,
        ));
    }
    if let Err(error) =
        rustferry_core::windows_private_directory::verify_private_file_handle(staging.as_handle())
            .map_err(|error| map_windows_private_provider_error(&error))
    {
        return Err(cleanup_failed_private_provider_staging(
            staging, path, error,
        ));
    }
    let staging_identity = match ArtifactFileIdentity::from_file(&staging) {
        Ok(identity) => identity,
        Err(source) => {
            let original = CliError::Io {
                action: "identify private Windows provider staging file",
                path: path.to_owned(),
                source,
            };
            return Err(cleanup_failed_private_provider_staging(
                staging, path, original,
            ));
        }
    };
    Ok(PreparedPrivateProviderStaging {
        file: staging,
        path: staging_path,
        identity: staging_identity,
    })
}

#[cfg(windows)]
fn write_private_create_only_windows(path: &Utf8Path, bytes: &[u8]) -> Result<(), CliError> {
    use rustferry_core::windows_private_directory::PrivateFileLinkState;
    use std::os::windows::io::AsHandle as _;

    let PreparedPrivateProviderStaging {
        file: staging,
        path: staging_path,
        identity: staging_identity,
    } = prepare_private_provider_staging(path, bytes)?;
    if let Err(source) = fs::hard_link(&staging_path, path) {
        let original = CliError::Io {
            action: "publish private Windows provider file without overwriting",
            path: path.to_owned(),
            source,
        };
        return Err(cleanup_failed_private_provider_staging(
            staging, path, original,
        ));
    }
    let publication = (|| {
        rustferry_core::windows_private_directory::verify_private_file_handle_in_state(
            staging.as_handle(),
            PrivateFileLinkState::PublicationPair,
        )
        .map_err(|error| map_windows_private_provider_error(&error))?;
        let final_identity =
            ArtifactFileIdentity::capture(path).map_err(|source| CliError::Io {
                action: "identify published private Windows provider file",
                path: path.to_owned(),
                source,
            })?;
        if final_identity != staging_identity {
            return Err(remote_error(
                "provider_config_commit_uncertain",
                "the published Windows provider file changed identity",
                "Inspect the generated provider directory before retrying.",
            ));
        }
        Ok(())
    })();
    if let Err(original) = publication {
        drop(staging);
        return Err(remote_error_with_details(
            "provider_config_commit_uncertain",
            "the private Windows provider file was linked but could not be verified",
            "Inspect the generated provider directory before retrying.",
            vec![original.to_string()],
        ));
    }
    drop(staging_identity);
    rustferry_core::windows_private_directory::remove_private_file_handle_in_state(
        staging,
        PrivateFileLinkState::PublicationPair,
    )
    .map_err(|error| {
        remote_error_with_details(
            "provider_config_publication_incomplete",
            "the private Windows provider file was published but its staging link remains",
            "Inspect the generated provider directory before retrying.",
            vec![error.to_string()],
        )
    })?;
    let final_file =
        rustferry_core::windows_private_directory::open_private_file(path.as_std_path())
            .map_err(|error| map_windows_private_provider_error(&error))?;
    let final_metadata = final_file.metadata().map_err(|source| CliError::Io {
        action: "inspect published private Windows provider file",
        path: path.to_owned(),
        source,
    })?;
    if final_metadata.len() != bytes.len() as u64 {
        return Err(remote_error(
            "provider_config_commit_uncertain",
            "the published Windows provider file has an unexpected length",
            "Inspect the generated provider directory before retrying.",
        ));
    }
    let mut actual = Vec::with_capacity(bytes.len());
    (&final_file)
        .take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|source| CliError::Io {
            action: "verify published private Windows provider file",
            path: path.to_owned(),
            source,
        })?;
    if actual != bytes {
        return Err(remote_error(
            "provider_config_commit_uncertain",
            "the published Windows provider file does not match the requested bytes",
            "Inspect the generated provider directory before retrying.",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn cleanup_failed_private_provider_staging(
    staging: File,
    path: &Utf8Path,
    original: CliError,
) -> CliError {
    match rustferry_core::windows_private_directory::remove_private_file_handle(staging) {
        Ok(()) => original,
        Err(cleanup) => remote_error_with_details(
            "provider_config_cleanup_uncertain",
            "a private Windows provider staging file failed and cleanup could not be confirmed",
            "Inspect the generated provider directory before retrying.",
            vec![
                format!("path={path}"),
                original.to_string(),
                cleanup.to_string(),
            ],
        ),
    }
}

fn ensure_workflow_directory(root: &Utf8Path) -> Result<(), CliError> {
    ensure_directory_chain(root, Utf8Path::new(".github/workflows"), false)?;
    Ok(())
}

fn ensure_provider_directories(root: &Utf8Path, paths: &GithubPaths) -> Result<(), CliError> {
    ensure_directory_chain(root, Utf8Path::new("target/ferry"), false)?;
    ensure_directory_chain(root, Utf8Path::new("target/ferry/github"), true)?;
    ensure_directory_chain(root, Utf8Path::new(CACHE_RELATIVE_PATH), true)?;
    ensure_directory_chain(root, Utf8Path::new(GIT_ISOLATION_RELATIVE_PATH), true)?;
    require_private_directory(&paths.cache, "GitHub artifact cache")?;
    require_private_directory(&paths.git_isolation, "Git publisher isolation")?;
    Ok(())
}

pub(super) fn ensure_directory_chain(
    root: &Utf8Path,
    relative: &Utf8Path,
    private_final: bool,
) -> Result<Utf8PathBuf, CliError> {
    let mut current = root.to_owned();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let name = component.as_str();
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(remote_error(
                "unsafe_generated_path",
                "a generated directory path is unsafe",
                "Use the standard project-local generated paths.",
            ));
        }
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(remote_error_with_details(
                    "unsafe_generated_path",
                    "a generated directory component is not a real directory",
                    "Move the linked or non-directory component aside and rerun setup.",
                    vec![format!("path={current}")],
                ));
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let is_private = private_final && index + 1 == component_count;
                #[cfg(windows)]
                if is_private {
                    rustferry_core::windows_private_directory::create_private_directory(
                        current.as_std_path(),
                    )
                    .map(drop)
                    .map_err(|error| map_windows_private_provider_error(&error))?;
                } else {
                    fs::create_dir(&current).map_err(|source| CliError::Io {
                        action: "create generated directory",
                        path: current.clone(),
                        source,
                    })?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(if is_private { 0o700 } else { 0o755 });
                    builder.create(&current).map_err(|source| CliError::Io {
                        action: "create generated directory",
                        path: current.clone(),
                        source,
                    })?;
                }
            }
            Err(source) => {
                return Err(CliError::Io {
                    action: "inspect generated directory",
                    path: current.clone(),
                    source,
                });
            }
        }
    }
    if private_final {
        require_private_directory(&current, "private generated directory")?;
    }
    Ok(current)
}

pub(super) fn prepare_artifact_destination(
    root: &Utf8Path,
    artifact: &Utf8Path,
) -> Result<(), CliError> {
    let parent = artifact.parent().ok_or_else(|| {
        remote_error(
            "artifact_destination_invalid",
            "the artifact destination has no parent directory",
            "Use the standard project-local target directory.",
        )
    })?;
    let relative = parent.strip_prefix(root).map_err(|_| {
        remote_error(
            "artifact_destination_invalid",
            "the artifact destination escapes the project",
            "Use the standard project-local target directory.",
        )
    })?;
    ensure_directory_chain(root, relative, false)?;
    match fs::symlink_metadata(artifact) {
        Ok(_) => {
            return Err(remote_error_with_details(
                "artifact_destination_exists",
                "the final iPhone artifact path already exists or is linked",
                "Move the existing entry aside or choose a clean build profile; cargo-ferry never overwrites it.",
                vec![format!("path={artifact}")],
            ));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect artifact destination",
                path: artifact.to_owned(),
                source,
            });
        }
    }
    Ok(())
}

fn require_private_directory(path: &Utf8Path, label: &'static str) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect private generated directory",
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(remote_error_with_details(
            "private_directory_invalid",
            "a private generated directory is linked or not a directory",
            "Remove the generated provider directory and rerun setup.",
            vec![label.to_owned()],
        ));
    }
    require_private_mode(path, &metadata)
}

fn require_private_mode(path: &Utf8Path, metadata: &fs::Metadata) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(remote_error_with_details(
                "private_permissions_required",
                "GitHub provider metadata must not be group- or world-accessible",
                "Restrict the generated provider file or directory to the current user, then retry.",
                vec![format!("path={path}")],
            ));
        }
    }
    #[cfg(windows)]
    if metadata.is_dir() {
        rustferry_core::windows_private_directory::open_private_directory(path.as_std_path())
            .map(drop)
            .map_err(|error| map_windows_private_provider_error(&error))?;
    } else if metadata.is_file() {
        rustferry_core::windows_private_directory::open_private_file(path.as_std_path())
            .map(drop)
            .map_err(|error| map_windows_private_provider_error(&error))?;
    } else {
        return Err(remote_error_with_details(
            "private_permissions_required",
            "GitHub provider metadata is not a private regular file or directory",
            "Replace the generated provider entry with one created by RustFerry, then retry.",
            vec![format!("path={path}")],
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn map_windows_private_provider_error(
    error: &rustferry_core::windows_private_directory::PrivateDirectoryError,
) -> CliError {
    use rustferry_core::windows_private_directory::PrivateDirectoryCleanupStatus;

    let cleanup_uncertain = error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain;
    remote_error_with_details(
        if cleanup_uncertain {
            "private_permissions_cleanup_uncertain"
        } else {
            "private_permissions_required"
        },
        if cleanup_uncertain {
            "Windows provider metadata failed private access-control validation and cleanup could not be confirmed"
        } else {
            "Windows provider metadata does not satisfy the private access-control policy"
        },
        "Use an NTFS project filesystem and RustFerry-created current-user-owned provider metadata, then retry.",
        vec![error.to_string()],
    )
}

fn read_bounded_file(path: &Utf8Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|source| CliError::Io {
        action: "open bounded file",
        path: path.to_owned(),
        source,
    })?;
    let capacity = usize::try_from(maximum.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read bounded file",
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(remote_error(
            "file_too_large",
            "a provider input exceeded its configured size bound",
            "Inspect and reduce the generated provider metadata.",
        ));
    }
    Ok(bytes)
}

fn reject_linked_components(
    root: &Utf8Path,
    relative: &Utf8Path,
    allow_missing: bool,
) -> Result<(), CliError> {
    let mut current = root.to_owned();
    for component in relative.components() {
        let name = component.as_str();
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(remote_error(
                "unsafe_generated_path",
                "a generated path contains an unsafe component",
                "Use the standard project-local generated paths.",
            ));
        }
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(remote_error_with_details(
                    "unsafe_generated_path",
                    "a generated path contains a symbolic-link component",
                    "Move the linked component aside and rerun the command.",
                    vec![format!("path={current}")],
                ));
            }
            Ok(_) => {}
            Err(source) if allow_missing && source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(source) => {
                return Err(CliError::Io {
                    action: "inspect generated path component",
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn expected_artifact_downloads(
    root: &Utf8Path,
    product_name: &str,
    release: bool,
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> Result<Vec<ExpectedDownload>, CliError> {
    validate_artifact_product_name(product_name)?;
    let directory = root
        .join("target/ferry/ios/device")
        .join(profile_name(release));
    let mut downloads = if signing_mode == SigningMode::UnsignedCompileOnly {
        vec![ExpectedDownload {
            kind: ArtifactKind::Xcarchive,
            path: directory.join(format!("{product_name}-unsigned.xcarchive.zip")),
        }]
    } else {
        let mut signed = vec![ExpectedDownload {
            kind: ArtifactKind::Ipa,
            path: directory.join(format!("{product_name}-development.ipa")),
        }];
        if requested_artifacts.contains(&IosArtifactType::AppBundle) {
            signed.push(ExpectedDownload {
                kind: ArtifactKind::App,
                path: directory.join(format!("{product_name}.app.zip")),
            });
        }
        if requested_artifacts.contains(&IosArtifactType::Xcarchive) {
            signed.push(ExpectedDownload {
                kind: ArtifactKind::Xcarchive,
                path: directory.join(format!("{product_name}.xcarchive.zip")),
            });
        }
        if requested_artifacts.contains(&IosArtifactType::Dsym) {
            signed.push(ExpectedDownload {
                kind: ArtifactKind::Dsym,
                path: directory.join(format!("{product_name}.dSYM.zip")),
            });
        }
        signed.extend([
            ExpectedDownload {
                kind: ArtifactKind::Manifest,
                path: directory.join("artifact-manifest.json"),
            },
            ExpectedDownload {
                kind: ArtifactKind::SigningReport,
                path: directory.join("signing-report.json"),
            },
            ExpectedDownload {
                kind: ArtifactKind::ValidationReport,
                path: directory.join("validation-report.json"),
            },
        ]);
        signed
    };
    downloads.push(ExpectedDownload {
        kind: ArtifactKind::SanitizedLog,
        path: directory.join("sanitized-build-log.txt"),
    });
    Ok(downloads)
}

pub(super) fn validate_artifact_product_name(product_name: &str) -> Result<(), CliError> {
    let filename = format!("{product_name}-development.ipa");
    let basename = product_name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || basename
            .strip_prefix("COM")
            .or_else(|| basename.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if product_name.is_empty()
        || filename.len() > 255
        || product_name.chars().any(char::is_control)
        || product_name.contains(['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'])
        || product_name.ends_with(['.', ' '])
        || matches!(product_name, "." | "..")
        || reserved
    {
        return Err(remote_error(
            "invalid_artifact_product_name",
            "the application product name is not a portable artifact filename stem",
            "Use a ferry.toml application name that is safe on Windows, Linux, and macOS.",
        ));
    }
    Ok(())
}

fn require_one_artifact(
    manifest: &rustferry_remote::ArtifactManifest,
    kind: ArtifactKind,
) -> Result<&rustferry_remote::ArtifactRecord, CliError> {
    let matching = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == kind)
        .collect::<Vec<_>>();
    let [artifact] = matching.as_slice() else {
        return Err(remote_error_with_details(
            "artifact_missing",
            "the verified manifest does not contain exactly one required artifact kind",
            "Inspect the worker artifact manifest and retry after correcting the remote build.",
            vec![format!("kind={kind:?}")],
        ));
    };
    Ok(artifact)
}

fn downloaded_manifest(
    manifest: &rustferry_remote::ArtifactManifest,
) -> rustferry_remote::ArtifactManifest {
    let mut downloaded = manifest.clone();
    downloaded
        .validation_levels
        .insert(ValidationLevel::DownloadedToClient);
    downloaded
}

fn doctor_not_ready(checks: &[rustferry_remote::ProviderCheck]) -> CliError {
    let details = checks
        .iter()
        .filter(|check| check.status == rustferry_remote::ProviderCheckStatus::Error)
        .map(|check| format!("{}: {}", check.code, check.message))
        .collect();
    remote_error_with_details(
        "remote_not_ready",
        "the GitHub remote provider is not ready",
        "Apply the reported authentication, repository, workflow, or artifact-store fixes, then rerun `cargo ferry remote doctor github`.",
        details,
    )
}

fn ensure_doctor_ready(
    report: &rustferry_remote::ProviderDoctorReport,
    require_signing: bool,
) -> Result<(), CliError> {
    if !report.ready {
        return Err(doctor_not_ready(&report.checks));
    }
    if require_signing {
        let reviewers_proven = report.checks.iter().any(|check| {
            check.code == "github.signing_environment.reviewers"
                && check.status == rustferry_remote::ProviderCheckStatus::Ready
        });
        if !reviewers_proven {
            return Err(remote_error(
                "protected_environment_reviewers_required",
                "signed GitHub builds require a protected environment with required reviewers",
                "Configure required reviewers for the signing environment and rerun `cargo ferry remote doctor github`. A warning or configured secret name is not proof of this server-side gate.",
            ));
        }
    }
    Ok(())
}

fn ensure_configured_repositories(
    stored: &StoredGithubConfig,
    git: &GitContext,
    execution: &GitRemoteContext,
) -> Result<(), CliError> {
    let (_, source_slug, source_repository) = parse_repository_spec(&stored.source_repository)?;
    if git.source_repository == source_repository
        && git.repository_slug == source_slug
        && execution.repository_slug == stored.repository
    {
        Ok(())
    } else {
        Err(remote_error(
            "remote_repository_changed",
            "a configured GitHub source or execution repository no longer matches its selected Git remote",
            "Run `cargo ferry remote status github`, then remove the generated provider config and rerun setup if the repository intentionally changed.",
        ))
    }
}

fn configured_signing_mode(config: &StoredGithubConfig) -> &'static str {
    config
        .signing
        .as_ref()
        .map_or("unsigned-smoke-only", |plan| signing_mode_name(plan.mode))
}

const fn signing_mode_name(mode: SigningMode) -> &'static str {
    match mode {
        SigningMode::UnsignedCompileOnly => "unsigned-compile-only",
        SigningMode::ManualDevelopment => "manual-development",
        SigningMode::Development => "development",
        SigningMode::PersonalTeam => "personal-team",
        SigningMode::AdHoc => "ad-hoc",
        SigningMode::AppStore => "app-store",
    }
}

const fn profile_name(release: bool) -> &'static str {
    if release { "release" } else { "debug" }
}

fn state_name(state: JobState) -> &'static str {
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

fn unsigned_warning(mode: SigningMode) -> Vec<String> {
    if mode == SigningMode::UnsignedCompileOnly {
        vec![
            "This artifact is not installable on a stock iPhone. Apple code signing and provisioning are required."
                .to_owned(),
        ]
    } else {
        Vec::new()
    }
}

fn operation_id() -> String {
    format!("ferry-{}", Uuid::new_v4().simple())
}

fn remote_error(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
) -> CliError {
    remote_error_with_details(code, message, help, Vec::new())
}

fn remote_error_with_details(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    details: Vec<String>,
) -> CliError {
    CliError::Remote {
        code,
        message: safe_public_text(&message.into()),
        help: safe_public_text(&help.into()),
        details: details
            .into_iter()
            .take(64)
            .map(|detail| safe_public_text(&detail))
            .collect(),
    }
}

fn safe_public_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_PUBLIC_TEXT_BYTES));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len().saturating_add(character.len_utf8()) > MAX_PUBLIC_TEXT_BYTES {
            truncated = true;
            break;
        }
        output.push(character);
    }
    if truncated {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::CONFIG_BACKUP_PREFIX;
    #[cfg(any(test, not(unix)))]
    use super::parse_git_index_executable_paths;
    use super::{
        ArtifactDownloadRollback, ArtifactPathReconciliation, CONFIG_SCHEMA_VERSION,
        CancellationWaitOutcome, CanonicalBase64SigningBlob, ConfigCommitError,
        DownloadDestinationBinding, ExistingFile, GithubPaths, ImmediateProviderResult,
        MAX_ENVIRONMENT_SECRET_BYTES, ManualGithubSecretValues, ManualGithubSigningAssets,
        ManualGithubSigningSession, ManualSigningRemote, PROTECTED_ENVIRONMENT,
        ProjectFilesystemBinding, RawSigningPassword, SigningSecretUpload,
        SnapshotSubmissionAuthority, StoredGithubConfig, StoredGithubWorkflowTrigger,
        SubmitPublicationEvidence, TEMPORARY_NAMESPACE, ValidatedLocalArtifact, WORKFLOW_FILE,
        acquire_provider_config_lock, cancellation_outcome_from_job, cleanup_job_durably_with,
        decode_stored_config, downloaded_manifest, encode_stored_config,
        ensure_config_snapshot_unchanged, ensure_doctor_ready, ensure_provider_directories,
        ensure_workflow_directory, existing_snapshot_submission_authority,
        expected_artifact_downloads, find_resumable_snapshot_job, generate_workflow,
        independently_validate_download, interrupted_cleanup_progress,
        interrupted_cleanup_progress_for_job, is_exact_success_promotion, load_config,
        load_signing_project_state, local_signing_readiness_checks, map_ide_signing_readiness,
        parse_repository_spec, persist_artifact_publication_uncertain,
        persist_cancellation_requested, persist_cancellation_uncertain, persist_cleanup_pending,
        persist_cleanup_uncertain, persist_controller_failure, persist_downloaded_artifact,
        persist_downloading, persist_downloads_complete, persist_validating,
        persist_validation_ready_for_cleanup, preflight_file, prepare_artifact_destination,
        provider_config_lock_for_signing, provider_resume_is_bound, read_private_config_snapshot,
        reconcile_artifact_path_publication, remote_error, replace_private_config,
        required_build_features_for_source, required_signing_secret_names, retry_artifact_listing,
        safe_ide_readiness_code, select_requested_artifacts, sha256_bytes,
        signing_config_commit_uncertain, signing_readiness_from_report,
        signing_workflow_phase_policy, snapshot_initial_job, snapshot_request_template,
        source_manifest_digest, submit_publication_evidence, unsigned_signing_plan,
        update_stored_job, validate_and_promote_durable_success,
        validate_and_promote_durable_success_with_hook, validate_existing_snapshot_owner,
        validate_git_remote_name, validate_manual_assets_match_plan, validate_stored_config,
        workflow_from_stored, write_create_only,
    };
    use super::{current_snapshot_manifest_diff, current_snapshot_retry_request_template};
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::executable_entrypoint;
    use crate::cli::BuildArtifactSelection;
    use crate::error::CliError;
    use crate::output::Reporter;
    use cargo_ferry::job_store::{
        JOB_STORE_SCHEMA_VERSION, JobOperationKind, JobStore, LocalJobId,
        SnapshotOperationVacancyV1, StoredArtifactV1, StoredBuildOutcome, StoredCancellationStatus,
        StoredCleanupStatus, StoredJobState, StoredJobV1, StoredProjectIdentityV1,
        StoredProviderIdentityV1, StoredRetryLineageV1, StoredSourceIdentityV1,
    };
    use rustferry_github::git_endpoint::GithubGitEndpoint;
    use rustferry_github::provider::{
        GITHUB_PROVIDER_ID, GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS, GithubGitSnapshotPhaseV1,
        GithubGitSnapshotRecoveryCandidateV1, GithubGitSnapshotResumeV1, GithubJobResumeV1,
        GithubPrincipalIdentityV1, GithubRunConclusionV1, GithubRunEventV1, GithubRunIdentityV1,
        GithubRunStatusV1, GithubWorkflowDispatchReceiptV1, GithubWorkflowDispatchResumeV1,
    };
    use rustferry_github::snapshot::{
        GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION, GitSha1ObjectId, GitSnapshotObjectGraphV1,
    };
    use rustferry_github::transport::{
        EnvironmentSecretWriteRequest, GhExecutionError, Repository, TransportError,
    };
    use rustferry_github::workflow::WorkflowRunTrigger;
    use rustferry_github::{ProtectedEnvironment, SigningSecretNames};
    use rustferry_remote::{
        ArtifactKind, ArtifactManifest, ArtifactRecord, BuildProfile, BundleIdentifier,
        COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CURRENT_PROTOCOL_VERSION, CancellationToken,
        CleanupConfirmation, CompilePhaseEvidence, CompileToolchainEvidence, DevelopmentTeam,
        DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet, GitSnapshotDescriptor,
        IOS_DEVICE_RUST_TARGET, IosArtifactType, IosDeviceBuildRequest, IosDeviceBuildResult,
        IosDeviceProductExpectation, JobState, ProviderCapabilities, ProviderCheck,
        ProviderCheckStatus, ProviderDoctorReport, ProviderFeature, ProvisioningPlan,
        ProvisioningPlatform, ProvisioningProfile, ProvisioningProfileType, RemoteBuildError,
        RemoteBuildEvent, RemoteBuildEventKind, SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
        SealedUnsignedArchive, SecretBytes, SecretReference, SecretReferenceKind,
        SigningCertificate, SigningIdentity, SigningMode, SigningPlan, SigningPrivateKeyReference,
        SigningReference, SigningTarget, SigningTargetKind, SourceArchive, SourceBundleDescriptor,
        SourceBundleRequest, SourceManifest, SourceManifestEntry, SourceMode,
        UnsignedAppInspection, UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection,
        canonical_request_sha256, canonical_retry_template_sha256_v1, plan_source_bundle,
    };

    fn unsigned_stored_config() -> StoredGithubConfig {
        StoredGithubConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            repository: "example/private-builds".to_owned(),
            source_repository: "https://github.com/example/public-app".to_owned(),
            source_fetch_endpoint: GithubGitEndpoint::parse(
                "https://github.com/example/public-app",
            )
            .expect("source fetch endpoint"),
            source_push_endpoint: GithubGitEndpoint::parse("https://github.com/example/public-app")
                .expect("source push endpoint"),
            execution_fetch_endpoint: GithubGitEndpoint::parse(
                "git@github.com:example/private-builds",
            )
            .expect("execution fetch endpoint"),
            execution_push_endpoint: GithubGitEndpoint::parse(
                "git@github.com:example/private-builds",
            )
            .expect("execution push endpoint"),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_file: WORKFLOW_FILE.to_owned(),
            protected_environment: PROTECTED_ENVIRONMENT.to_owned(),
            temporary_namespace: TEMPORARY_NAMESPACE.to_owned(),
            worker_repository: "https://github.com/example/rustferry".to_owned(),
            worker_revision: "a".repeat(40),
            worker_version: "0.1.0".to_owned(),
            run_trigger: StoredGithubWorkflowTrigger::Push,
            signing_targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle ID"),
                kind: SigningTargetKind::Application,
            }],
            signing: None,
        }
    }

    #[test]
    fn current_snapshot_retry_diff_is_deterministic_and_globally_bounded() {
        let previous_entries = vec![
            SourceManifestEntry {
                path: "a.txt".to_owned(),
                size: 1,
                sha256: "1".repeat(64),
                executable: false,
            },
            SourceManifestEntry {
                path: "b.txt".to_owned(),
                size: 1,
                sha256: "2".repeat(64),
                executable: false,
            },
            SourceManifestEntry {
                path: "removed.txt".to_owned(),
                size: 1,
                sha256: "3".repeat(64),
                executable: false,
            },
        ];
        let mut current_entries = vec![
            previous_entries[0].clone(),
            SourceManifestEntry {
                path: "b.txt".to_owned(),
                size: 2,
                sha256: "4".repeat(64),
                executable: false,
            },
        ];
        current_entries.extend((0..140).map(|index| SourceManifestEntry {
            path: format!("added-{index:03}.txt"),
            size: 1,
            sha256: format!("{index:064x}"),
            executable: false,
        }));
        current_entries.sort_by(|left, right| left.path.cmp(&right.path));
        let previous = SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            total_size: previous_entries.iter().map(|entry| entry.size).sum(),
            sha256: source_manifest_digest(".", &previous_entries, 3),
            entries: previous_entries,
        };
        let total_size = current_entries.iter().map(|entry| entry.size).sum();
        let current = SourceManifest {
            schema_version: 1,
            project_path: "member".to_owned(),
            sha256: source_manifest_digest("member", &current_entries, total_size),
            entries: current_entries,
            total_size,
        };

        let diff = current_snapshot_manifest_diff(&previous, &current).expect("snapshot diff");

        assert_eq!(diff.added_count, 140);
        assert_eq!(diff.modified_count, 1);
        assert_eq!(diff.removed_count, 1);
        assert_eq!(diff.unchanged, 1);
        assert!(diff.project_path_changed);
        assert!(diff.paths_truncated);
        assert_eq!(diff.added_paths.len(), 128);
        assert!(diff.modified_paths.is_empty());
        assert!(diff.removed_paths.is_empty());
        let retained = diff
            .added_paths
            .iter()
            .chain(&diff.modified_paths)
            .chain(&diff.removed_paths)
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(retained.len(), 128);
    }

    #[test]
    fn current_snapshot_retry_template_changes_only_operation_and_source() {
        let temporary = tempfile::tempdir().expect("controller fixture");
        let parent = durable_controller_record(&temporary, None);
        let mut current_source = parent.request.source.clone();
        current_source.entries[0].sha256 = "f".repeat(64);
        current_source.sha256 = source_manifest_digest(
            &current_source.project_path,
            &current_source.entries,
            current_source.total_size,
        );

        let template = current_snapshot_retry_request_template(
            &parent,
            "retry-current-source-1",
            "https://github.com/example/public-app",
            current_source.clone(),
        )
        .expect("current-source request template");

        let mut expected = parent.request;
        expected.operation_id = "retry-current-source-1".to_owned();
        expected.source_mode = SourceMode::GitSnapshot;
        expected.source_repository = Some("https://github.com/example/public-app".to_owned());
        expected.source_revision = None;
        expected.source = current_source;
        assert_eq!(template, expected);
    }

    fn current_snapshot_retry_parent() -> (
        tempfile::TempDir,
        camino::Utf8PathBuf,
        GithubPaths,
        StoredJobV1,
    ) {
        let (temporary, root, paths, config) = provider_config_fixture();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("source file");
        std::fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"App\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo lockfile");
        let root = canonical_utf8(root.as_std_path());
        let project = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let source = plan_source_bundle(&SourceBundleRequest::new(&root, &root))
            .expect("parent source plan");
        let ferry_config = rustferry_core::FerryConfig::starter("App", "com.example.app");
        let mut request = snapshot_request_template(
            &ferry_config,
            "App",
            false,
            "current-source-parent",
            &config.source_repository,
            source.manifest().clone(),
            unsigned_signing_plan(&ferry_config, "App").expect("unsigned signing plan"),
            BTreeSet::from([IosArtifactType::Xcarchive]),
        )
        .expect("parent request template");
        request.source_revision = Some("a".repeat(40));
        request.validate().expect("parent request");
        let provider = StoredProviderIdentityV1 {
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: "b".repeat(64),
            principal: GithubPrincipalIdentityV1::User {
                id: 7,
                login: "retry-user".to_owned(),
            },
            execution_repository: "https://github.com/example/private-builds".to_owned(),
            execution_repository_id: 42,
        };
        let parent = snapshot_initial_job(
            &project,
            provider,
            LocalJobId::new("current-source-parent-job").expect("parent job ID"),
            request,
            1_700_000_000_000,
            1_700_000_000_001,
        )
        .expect("parent job");
        (temporary, root, paths, parent)
    }

    fn test_filesystem_snapshot(root: &std::path::Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn visit(
            root: &std::path::Path,
            current: &std::path::Path,
            output: &mut Vec<(String, Option<Vec<u8>>)>,
        ) {
            let mut entries = std::fs::read_dir(current)
                .expect("read fixture directory")
                .collect::<Result<Vec<_>, _>>()
                .expect("read fixture entries");
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("fixture-relative path")
                    .to_string_lossy()
                    .replace('\\', "/");
                if entry.file_type().expect("fixture file type").is_dir() {
                    output.push((format!("{relative}/"), None));
                    visit(root, &path, output);
                } else {
                    output.push((
                        relative,
                        Some(std::fs::read(path).expect("fixture file bytes")),
                    ));
                }
            }
        }

        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    #[test]
    fn current_snapshot_retry_preview_is_zero_write_and_archive_free() {
        let (temporary, _root, _paths, parent) = current_snapshot_retry_parent();
        let before = test_filesystem_snapshot(temporary.path());

        let prepared = super::prepare_current_snapshot_retry(
            &parent,
            "current-source-child".to_owned(),
            1_700_000_000_100,
        )
        .expect("zero-write current-source preview");

        assert_eq!(test_filesystem_snapshot(temporary.path()), before);
        assert_eq!(prepared.preview().archive_status, "computed_after_consent");
        assert_eq!(prepared.preview().archive_size, None);
        assert_eq!(prepared.preview().archive_sha256, None);
        assert_eq!(prepared.preview().source_repository_visibility, "public");
        assert!(!prepared.preview().ref_deletion_erases_objects);
    }

    #[test]
    fn current_snapshot_retry_stale_consent_creates_no_stage_or_lineage() {
        let (_temporary, root, paths, parent) = current_snapshot_retry_parent();
        let store_directory = tempfile::tempdir().expect("job store directory");
        let store = JobStore::open_at(store_directory.path().join("job-store")).expect("job store");
        store.create(&parent).expect("durable parent");
        let prepared = super::prepare_current_snapshot_retry(
            &parent,
            "current-source-child".to_owned(),
            1_700_000_000_100,
        )
        .expect("current-source preview");
        let confirmed = prepared
            .confirm(true, &Reporter::new(false, true, false))
            .expect("explicit current-source consent");
        std::fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"changed\"); }\n",
        )
        .expect("change source after consent");
        let parent_lease = store
            .try_acquire_operation_lease(&parent.local_job_id, JobOperationKind::Retry)
            .expect("parent Retry lease");
        let vacancy = match store
            .try_acquire_vacant_snapshot_operation_lease("current-source-child")
            .expect("child operation reservation")
        {
            SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
            SnapshotOperationVacancyV1::Owned(_) => panic!("unexpected child owner"),
        };

        let error = confirmed
            .stage(
                &parent_lease,
                super::CurrentSnapshotRetryOperationGuard::Vacant(&vacancy),
                &CancellationToken::new(),
            )
            .expect_err("stale consent must fail before staging");

        assert_eq!(error.code(), "snapshot_plan_changed");
        assert!(
            !paths
                .git_isolation
                .join("snapshots/current-source-child")
                .exists()
        );
        assert!(parent.retry_lineage.child_job_ids.is_empty());
        assert_eq!(store.latest(&parent.local_job_id).unwrap(), parent);
    }

    pub(super) fn provider_config_fixture() -> (
        tempfile::TempDir,
        camino::Utf8PathBuf,
        GithubPaths,
        StoredGithubConfig,
    ) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8PathBuf::from_path_buf(temporary.path().to_owned())
            .expect("UTF-8 temp path");
        let project_config = rustferry_core::FerryConfig::starter("App", "com.example.app");
        std::fs::write(
            root.join("ferry.toml"),
            project_config
                .to_pretty_toml()
                .expect("project config TOML"),
        )
        .expect("project config");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"App\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("Cargo manifest");
        let paths = GithubPaths::new(&root, &root);
        ensure_provider_directories(&root, &paths).expect("private provider directories");
        let config = unsigned_stored_config();
        let bytes = encode_stored_config(&config).expect("config bytes");
        write_create_only(&paths.config, &bytes, true).expect("provider config");
        (temporary, root, paths, config)
    }

    struct SnapshotRecoveryFixture {
        temporary: tempfile::TempDir,
        stage_path: std::path::PathBuf,
        project_binding: ProjectFilesystemBinding,
        provider: StoredProviderIdentityV1,
        candidate: GithubGitSnapshotRecoveryCandidateV1,
        initial_job: StoredJobV1,
    }

    fn snapshot_test_object(character: char) -> GitSha1ObjectId {
        GitSha1ObjectId::new(character.to_string().repeat(40)).expect("snapshot object")
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the crash fixture binds the complete stage, request, project, provider, and initial job"
    )]
    fn snapshot_recovery_fixture() -> SnapshotRecoveryFixture {
        let temporary = tempfile::tempdir().expect("snapshot recovery fixture");
        let project_path = temporary.path().join("project");
        std::fs::create_dir_all(project_path.join("src")).expect("project source directory");
        let root = canonical_utf8(&project_path);
        let ferry_config = rustferry_core::FerryConfig::starter("App", "com.example.app");
        std::fs::write(
            root.join("ferry.toml"),
            ferry_config.to_pretty_toml().expect("ferry config TOML"),
        )
        .expect("ferry config");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n",
        )
        .expect("Cargo manifest");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("Rust source");
        let source = plan_source_bundle(&SourceBundleRequest::new(&root, &root))
            .expect("snapshot source plan");
        let operation_id = "snapshot-crash-recovery-1";
        let signing = unsigned_signing_plan(&ferry_config, "app").expect("unsigned signing plan");
        let request_template = snapshot_request_template(
            &ferry_config,
            "app",
            false,
            operation_id,
            "https://github.com/example/public-app",
            source.manifest().clone(),
            signing,
            BTreeSet::from([IosArtifactType::Xcarchive]),
        )
        .expect("snapshot request template");
        let isolation = camino::Utf8PathBuf::from_path_buf(temporary.path().join("isolation"))
            .expect("UTF-8 isolation path");
        #[cfg(windows)]
        drop(
            rustferry_core::windows_private_directory::create_private_directory(
                isolation.as_std_path(),
            )
            .expect("private snapshot isolation root"),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = std::fs::DirBuilder::new();
            builder
                .mode(0o700)
                .create(isolation.as_std_path())
                .expect("private snapshot isolation root");
        }
        let staged = crate::commands::github_snapshot::stage_same_invocation_snapshot(
            &isolation,
            &source,
            request_template.clone(),
            1_700_000_000_000,
            &"9".repeat(64),
            |_inputs, _operation_id, _created_at_ms| {
                Ok(GitSnapshotObjectGraphV1 {
                    schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
                    archive_blob: snapshot_test_object('1'),
                    descriptor_blob: snapshot_test_object('2'),
                    goal3_tree: snapshot_test_object('3'),
                    rustferry_tree: snapshot_test_object('4'),
                    root_tree: snapshot_test_object('5'),
                    commit: snapshot_test_object('6'),
                })
            },
        )
        .expect("complete snapshot stage");
        let descriptor = GitSnapshotDescriptor::from_request(
            &request_template,
            SourceBundleDescriptor::new(
                staged.stage.archive.clone(),
                request_template.source.clone(),
            ),
        )
        .expect("snapshot descriptor");
        let candidate = GithubGitSnapshotRecoveryCandidateV1 {
            stage_locator: staged.locator,
            stage: staged.stage,
            descriptor,
            final_request: staged.request,
        };
        let stage_path = isolation
            .join("snapshots")
            .join(operation_id)
            .into_std_path_buf();
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let provider = StoredProviderIdentityV1 {
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: "a".repeat(64),
            principal: GithubPrincipalIdentityV1::User {
                id: 7,
                login: "snapshot-user".to_owned(),
            },
            execution_repository: "https://github.com/example/private-builds".to_owned(),
            execution_repository_id: 42,
        };
        let initial_job = snapshot_initial_job(
            &project_binding,
            provider.clone(),
            LocalJobId::new("snapshot-crash-job").expect("local job ID"),
            candidate.final_request.clone(),
            candidate.stage.source_created_at_ms,
            candidate.stage.source_created_at_ms.saturating_add(1),
        )
        .expect("initial snapshot job");
        SnapshotRecoveryFixture {
            temporary,
            stage_path,
            project_binding,
            provider,
            candidate,
            initial_job,
        }
    }

    fn snapshot_resume_at_phase(
        record: &StoredJobV1,
        candidate: &GithubGitSnapshotRecoveryCandidateV1,
        phase: GithubGitSnapshotPhaseV1,
    ) -> GithubJobResumeV1 {
        let source_exact = phase == GithubGitSnapshotPhaseV1::SourceExact;
        let source_phase = source_exact;
        let source_publication_started_at_ms = if source_exact {
            record.created_at_ms
        } else {
            0
        };
        GithubJobResumeV1 {
            schema_version: 1,
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: record.provider.provider_config_sha256.clone(),
            principal: record.provider.principal.clone(),
            execution_repository: record.provider.execution_repository.clone(),
            execution_repository_id: record.provider.execution_repository_id,
            source_repository: record
                .request
                .source_repository
                .clone()
                .expect("snapshot source repository"),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_path: ".github/workflows/rustferry-goal3-iphone.yml".to_owned(),
            workflow_sha256: "b".repeat(64),
            temporary_ref: format!("refs/heads/rustferry/goal3/builds/{}", record.operation_id),
            operation_id: record.operation_id.clone(),
            job_id: record.operation_id.clone(),
            request: record.request.clone(),
            request_sha256: record.request_sha256.clone(),
            source_revision: record.source.revision.clone().expect("snapshot revision"),
            git_snapshot: Some(GithubGitSnapshotResumeV1 {
                schema_version: 1,
                stage_locator: candidate.stage_locator.clone(),
                stage: candidate.stage.clone(),
                phase,
                source_publication_attempts: u8::from(source_phase),
                source_publication_started_at_ms,
                source_publication_quiescence_deadline_ms: if source_exact {
                    source_publication_started_at_ms
                        .saturating_add(GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS)
                } else {
                    0
                },
                source_publication_process_fenced: source_phase,
                source_publication_lease_scope_sha256: source_phase.then(|| "c".repeat(64)),
                source_publication_absence_observations: 0,
                source_publication_absence_first_observed_at_ms: 0,
                source_publication_absence_last_observed_at_ms: 0,
                keepalive_release_authorization_sha256: None,
            }),
            prepared_dispatch_commit: None,
            dispatch_commit: None,
            workflow_dispatch: None,
            run: None,
            created_at_ms: record.created_at_ms,
            publication_started_at_ms: 0,
            publication_quiescence_deadline_ms: u64::MAX,
            state: JobState::Created,
            publication_intent: false,
            publication_uncertain: false,
            publication_absent: false,
            publication_not_attempted: false,
            publication_process_fenced: false,
            publication_lease_scope_sha256: None,
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
            run_discovery_deadline_ms: record.created_at_ms.saturating_add(60_000),
            manifests: Vec::new(),
            compile_evidence: None,
            signed_cleanup_evidence: None,
            events: Vec::new(),
        }
    }

    fn current_snapshot_template(
        candidate: &GithubGitSnapshotRecoveryCandidateV1,
    ) -> IosDeviceBuildRequest {
        let mut template = candidate.final_request.clone();
        template.source_revision = None;
        template
    }

    #[test]
    fn snapshot_crash_after_initial_owner_reuses_exact_job_for_fresh_reconsent() {
        let fixture = snapshot_recovery_fixture();
        let store = JobStore::open_at(fixture.temporary.path().join("job-store"))
            .expect("snapshot job store");
        let vacancy = match store
            .try_acquire_vacant_snapshot_operation_lease(&fixture.initial_job.operation_id)
            .expect("operation vacancy")
        {
            SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
            SnapshotOperationVacancyV1::Owned(_) => panic!("fixture operation must be vacant"),
        };
        let created = store
            .create_with_operation_lease(vacancy, &fixture.initial_job)
            .expect("atomic snapshot owner creation");
        drop(created.operation_lease);

        let owner = store
            .snapshot_operation_owner(&fixture.initial_job.operation_id)
            .expect("snapshot owner scan")
            .expect("durable snapshot owner");
        assert_eq!(owner.local_job_id, fixture.initial_job.local_job_id);
        assert_eq!(owner.record.revision, 1);
        assert!(owner.record.provider_resume.is_none());
        validate_existing_snapshot_owner(
            &owner,
            &fixture.project_binding,
            &fixture.provider,
            &fixture.candidate,
        )
        .expect("exact revision-one owner");
        assert!(matches!(
            existing_snapshot_submission_authority(&owner.record),
            SnapshotSubmissionAuthority::FreshReconsent
        ));
        let occupied = store
            .try_acquire_vacant_snapshot_operation_lease(&fixture.initial_job.operation_id)
            .expect("owned operation result");
        assert!(matches!(
            occupied,
            SnapshotOperationVacancyV1::Owned(ref existing)
                if existing.local_job_id == fixture.initial_job.local_job_id
                    && existing.record.revision == 1
        ));

        let mut mismatched = owner;
        mismatched.record.request.source.sha256 = "f".repeat(64);
        assert!(
            validate_existing_snapshot_owner(
                &mismatched,
                &fixture.project_binding,
                &fixture.provider,
                &fixture.candidate,
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_crash_after_prepared_checkpoint_is_restore_only() {
        let fixture = snapshot_recovery_fixture();
        let store = JobStore::open_at(fixture.temporary.path().join("job-store"))
            .expect("snapshot job store");
        let vacancy = match store
            .try_acquire_vacant_snapshot_operation_lease(&fixture.initial_job.operation_id)
            .expect("operation vacancy")
        {
            SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
            SnapshotOperationVacancyV1::Owned(_) => panic!("fixture operation must be vacant"),
        };
        let created = store
            .create_with_operation_lease(vacancy, &fixture.initial_job)
            .expect("atomic snapshot owner creation");
        let resume = snapshot_resume_at_phase(
            &fixture.initial_job,
            &fixture.candidate,
            GithubGitSnapshotPhaseV1::Prepared,
        );
        store
            .checkpoint_github_resume(&fixture.initial_job.local_job_id, &resume)
            .expect("Prepared provider checkpoint");
        drop(created.operation_lease);

        let owner = store
            .snapshot_operation_owner(&fixture.initial_job.operation_id)
            .expect("snapshot owner scan")
            .expect("checkpointed snapshot owner");
        assert!(owner.record.revision > 1);
        assert!(owner.record.provider_resume.is_some());
        validate_existing_snapshot_owner(
            &owner,
            &fixture.project_binding,
            &fixture.provider,
            &fixture.candidate,
        )
        .expect("exact Prepared owner");
        assert!(matches!(
            existing_snapshot_submission_authority(&owner.record),
            SnapshotSubmissionAuthority::RestoreExisting
        ));
        assert!(matches!(
            store
                .try_acquire_vacant_snapshot_operation_lease(&fixture.initial_job.operation_id)
                .expect("owned operation result"),
            SnapshotOperationVacancyV1::Owned(ref existing)
                if existing.local_job_id == fixture.initial_job.local_job_id
                    && existing.record.revision == owner.record.revision
        ));
    }

    #[test]
    fn snapshot_resume_scan_recovers_after_stage_deletion_and_exact_source_publication() {
        for phase in [
            GithubGitSnapshotPhaseV1::StageDeleted,
            GithubGitSnapshotPhaseV1::SourceExact,
        ] {
            let fixture = snapshot_recovery_fixture();
            let store = JobStore::open_at(fixture.temporary.path().join("job-store"))
                .expect("snapshot job store");
            let vacancy = match store
                .try_acquire_vacant_snapshot_operation_lease(&fixture.initial_job.operation_id)
                .expect("operation vacancy")
            {
                SnapshotOperationVacancyV1::Vacant(vacancy) => vacancy,
                SnapshotOperationVacancyV1::Owned(_) => panic!("fixture operation must be vacant"),
            };
            let created = store
                .create_with_operation_lease(vacancy, &fixture.initial_job)
                .expect("atomic snapshot owner creation");
            let resume = snapshot_resume_at_phase(&fixture.initial_job, &fixture.candidate, phase);
            store
                .checkpoint_github_resume(&fixture.initial_job.local_job_id, &resume)
                .expect("advanced snapshot checkpoint");
            drop(created.operation_lease);
            std::fs::remove_dir_all(&fixture.stage_path).expect("simulate durable stage deletion");

            let found = find_resumable_snapshot_job(
                &store,
                &fixture.project_binding,
                &fixture.provider,
                &current_snapshot_template(&fixture.candidate),
            )
            .expect("resumable snapshot scan")
            .expect("exact unfinished snapshot job");
            assert_eq!(found.local_job_id, fixture.initial_job.local_job_id);
            assert_eq!(
                found
                    .provider_resume
                    .as_ref()
                    .and_then(|resume| resume.git_snapshot.as_ref())
                    .map(|snapshot| snapshot.phase),
                Some(phase)
            );
            assert!(matches!(
                existing_snapshot_submission_authority(&found),
                SnapshotSubmissionAuthority::RestoreExisting
            ));
            assert!(!fixture.stage_path.exists());
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the durable controller fixture keeps one complete cross-layer record auditable"
    )]
    pub(super) fn durable_controller_record(
        temporary: &tempfile::TempDir,
        artifact_bytes: Option<&[u8]>,
    ) -> StoredJobV1 {
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
        let source = SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries: entries.clone(),
            total_size: 0,
            sha256: source_manifest_digest(".", &entries, 0),
        };
        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle ID"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        };
        let request = IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-controller-test".to_owned(),
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
            source_mode: SourceMode::Git,
            source_repository: Some("https://github.com/example/app".to_owned()),
            source_revision: Some("a".repeat(40)),
            source,
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        request.validate().expect("valid durable request");
        let artifacts = artifact_bytes
            .map(|bytes| {
                vec![StoredArtifactV1 {
                    record: ArtifactRecord {
                        artifact_id: "artifact-1".to_owned(),
                        kind: ArtifactKind::Xcarchive,
                        file_name: "App-unsigned.xcarchive.zip".to_owned(),
                        size: u64::try_from(bytes.len()).expect("artifact size"),
                        sha256: super::sha256_bytes(bytes),
                        media_type: Some("application/zip".to_owned()),
                    },
                    download_destination: None,
                    download_parent_identity: None,
                    local_path: None,
                    local_file_identity: None,
                    locally_validated: false,
                }]
            })
            .unwrap_or_default();
        let state = if artifacts.is_empty() {
            StoredJobState::SourceReady
        } else {
            StoredJobState::ArtifactReady
        };
        let outcome = (!artifacts.is_empty()).then_some(StoredBuildOutcome::Succeeded);
        let record = StoredJobV1 {
            schema_version: JOB_STORE_SCHEMA_VERSION,
            local_job_id: LocalJobId::new("job-controller-test").expect("local job ID"),
            revision: 1,
            project: StoredProjectIdentityV1 {
                canonical_root: canonical_utf8(temporary.path()).to_string(),
                filesystem_identity: rustferry_core::DirectoryFilesystemIdentity::capture(
                    temporary.path(),
                )
                .expect("project identity")
                .to_string(),
                application_identifier: request.bundle_identifier.clone(),
            },
            provider: StoredProviderIdentityV1 {
                provider: GITHUB_PROVIDER_ID.to_owned(),
                provider_config_sha256: "b".repeat(64),
                principal: GithubPrincipalIdentityV1::User {
                    id: 7,
                    login: "example-user".to_owned(),
                },
                execution_repository: "https://github.com/example/builds".to_owned(),
                execution_repository_id: 42,
            },
            provider_job_id: None,
            provider_run_id: None,
            operation_id: request.operation_id.clone(),
            request_sha256: canonical_request_sha256(&request).expect("request hash"),
            semantic_retry_sha256: canonical_retry_template_sha256_v1(&request)
                .expect("retry hash"),
            source: StoredSourceIdentityV1 {
                revision: request.source_revision.clone(),
                manifest_sha256: request.source.sha256.clone(),
            },
            target: "iphone".to_owned(),
            profile: request.profile,
            signing_mode: request.signing.mode,
            request,
            created_at_ms: 1,
            submitted_at_ms: outcome.map(|_| 1),
            updated_at_ms: 1,
            state,
            last_confirmed_state: Some(state),
            terminal_outcome: outcome,
            compile_evidence: None,
            signed_cleanup_evidence: None,
            artifacts,
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
        };
        record.validate().expect("valid durable record");
        record
    }

    fn canonical_utf8(path: &std::path::Path) -> camino::Utf8PathBuf {
        camino::Utf8PathBuf::from_path_buf(path.canonicalize().expect("canonical test path"))
            .expect("UTF-8 test path")
    }

    fn test_download_destination(path: &camino::Utf8Path) -> DownloadDestinationBinding {
        let parent = path.parent().expect("artifact parent").to_owned();
        let managed_root_retained =
            rustferry_core::RetainedDirectoryIdentity::open(parent.as_std_path())
                .expect("retained managed root identity");
        let parent_retained = rustferry_core::RetainedDirectoryIdentity::open(parent.as_std_path())
            .expect("retained parent identity");
        DownloadDestinationBinding {
            path: path.to_string(),
            managed_root: parent.clone(),
            managed_root_identity: managed_root_retained.identity().clone(),
            managed_root_retained,
            parent_identity: parent_retained.identity().clone(),
            parent_retained,
            parent,
        }
    }

    fn push_durable_github_event(
        resume: &mut GithubJobResumeV1,
        timestamp_ms: u64,
        phase: &str,
        kind: RemoteBuildEventKind,
    ) {
        let sequence = u64::try_from(resume.events.len()).expect("event count") + 1;
        let event = RemoteBuildEvent::new(
            resume.operation_id.clone(),
            resume.job_id.clone(),
            timestamp_ms,
            GITHUB_PROVIDER_ID,
            phase,
            sequence,
            kind,
        )
        .expect("valid durable GitHub event");
        resume.events.push(event);
    }

    fn github_compile_evidence(record: &StoredJobV1) -> CompilePhaseEvidence {
        let product = &record.request.product;
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
                expectation: UnsignedXcarchiveExpectation {
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
                },
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

    #[expect(
        clippy::too_many_lines,
        reason = "the cleanup fixture spells out the complete durable provider evidence boundary"
    )]
    fn successful_cleanup_resume(record: &StoredJobV1) -> GithubJobResumeV1 {
        let mut manifest = ArtifactManifest::new(&record.operation_id, &record.operation_id);
        manifest.provider = GITHUB_PROVIDER_ID.to_owned();
        manifest.source_repository = record.request.source_repository.clone();
        manifest.source_revision = record.source.revision.clone();
        manifest.source_sha256 = record.source.manifest_sha256.clone();
        manifest.artifacts = record
            .artifacts
            .iter()
            .map(|artifact| artifact.record.clone())
            .collect();
        let dispatch_commit = "e".repeat(40);
        let workflow_path = ".github/workflows/rustferry-goal3-iphone.yml".to_owned();
        let branch = format!("rustferry/builds/{}", record.operation_id);
        let mut resume = GithubJobResumeV1 {
            schema_version: 1,
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: record.provider.provider_config_sha256.clone(),
            principal: record.provider.principal.clone(),
            execution_repository: record.provider.execution_repository.clone(),
            execution_repository_id: record.provider.execution_repository_id,
            source_repository: record
                .request
                .source_repository
                .clone()
                .expect("Git source repository"),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_path: workflow_path.clone(),
            workflow_sha256: "d".repeat(64),
            temporary_ref: format!("refs/heads/{branch}"),
            operation_id: record.operation_id.clone(),
            job_id: record.operation_id.clone(),
            request: record.request.clone(),
            request_sha256: record.request_sha256.clone(),
            source_revision: record.source.revision.clone().expect("source revision"),
            git_snapshot: None,
            prepared_dispatch_commit: Some(dispatch_commit.clone()),
            dispatch_commit: Some(dispatch_commit.clone()),
            workflow_dispatch: None,
            run: Some(GithubRunIdentityV1 {
                run_id: 7,
                workflow_id: 8,
                workflow_path,
                head_sha: dispatch_commit,
                branch,
                event: GithubRunEventV1::Push,
                run_number: 9,
                run_attempt: 1,
                status: GithubRunStatusV1::Completed,
                conclusion: Some(GithubRunConclusionV1::Success),
            }),
            created_at_ms: record.created_at_ms,
            publication_started_at_ms: record.created_at_ms,
            publication_quiescence_deadline_ms: record
                .created_at_ms
                .saturating_add(GITHUB_PUBLICATION_QUIESCENCE_WINDOW_MS),
            publication_absence_first_observed_at_ms: 0,
            state: JobState::Succeeded,
            publication_intent: true,
            publication_uncertain: false,
            publication_absent: false,
            publication_not_attempted: false,
            publication_process_fenced: true,
            publication_lease_scope_sha256: Some("a".repeat(64)),
            publication_absence_observations: 0,
            cancellation_requested: false,
            cancellation_dispatched: false,
            cleanup_requested: true,
            remove_artifacts_requested: false,
            artifacts_removed: false,
            temporary_ref_deleted: false,
            verification_pending_event: false,
            run_discovery_attempts: 0,
            run_discovery_deadline_ms: record.created_at_ms,
            manifests: vec![manifest.clone()],
            compile_evidence: Some(github_compile_evidence(record)),
            signed_cleanup_evidence: None,
            events: Vec::new(),
        };
        push_durable_github_event(
            &mut resume,
            record.created_at_ms.saturating_add(1),
            "artifacts",
            RemoteBuildEventKind::ArtifactValidated {
                artifact: manifest.clone(),
            },
        );
        let result = IosDeviceBuildResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: record.operation_id.clone(),
            job_id: record.operation_id.clone(),
            state: JobState::Succeeded,
            artifacts: vec![manifest],
            cleanup: None,
        };
        push_durable_github_event(
            &mut resume,
            record.created_at_ms.saturating_add(2),
            "finished",
            RemoteBuildEventKind::OperationFinished {
                success: true,
                duration_ms: 2,
                result: Some(result),
                error: None,
            },
        );
        resume
    }

    fn create_provider_artifact_ready_job(store: &JobStore, evidence: &StoredJobV1) -> StoredJobV1 {
        let mut initial = evidence.clone();
        initial.submitted_at_ms = None;
        initial.state = StoredJobState::SourceReady;
        initial.last_confirmed_state = Some(StoredJobState::SourceReady);
        initial.terminal_outcome = None;
        initial.compile_evidence = None;
        initial.signed_cleanup_evidence = None;
        initial.artifacts.clear();
        initial.cleanup_status = StoredCleanupStatus::NotStarted;
        initial.cancellation_status = StoredCancellationStatus::NotRequested;
        initial.failure = None;
        initial.provider_resume = None;
        initial.validate().expect("source-ready initial revision");
        store.create(&initial).expect("initial revision");
        for state in [StoredJobState::Submitting, StoredJobState::Running] {
            update_stored_job(store, &initial.local_job_id, |_previous, next| {
                next.state = state;
                next.last_confirmed_state = Some(state);
                Ok(())
            })
            .expect("advance local phase");
        }
        let mut resume = successful_cleanup_resume(evidence);
        resume.cleanup_requested = false;
        store
            .checkpoint_github_resume(&initial.local_job_id, &resume)
            .expect("successful provider checkpoint");
        let ready = store
            .latest(&initial.local_job_id)
            .expect("artifact-ready revision");
        assert_eq!(ready.state, StoredJobState::ArtifactReady);
        assert_eq!(ready.terminal_outcome, Some(StoredBuildOutcome::Succeeded));
        ready
    }

    fn checkpoint_cleaned_job(store: &JobStore, record: &StoredJobV1, checkpoint_cleaning: bool) {
        let mut resume = successful_cleanup_resume(record);
        store
            .checkpoint_github_resume(&record.local_job_id, &resume)
            .expect("pre-cleaning provider checkpoint");
        let started_at_ms = record.created_at_ms.saturating_add(3);
        push_durable_github_event(
            &mut resume,
            started_at_ms,
            "cleanup",
            RemoteBuildEventKind::CleanupStarted,
        );
        if checkpoint_cleaning {
            resume.state = JobState::Cleaning;
            store
                .checkpoint_github_resume(&record.local_job_id, &resume)
                .expect("cleaning checkpoint");
        }
        resume.state = JobState::Cleaned;
        resume.temporary_ref_deleted = true;
        let job_id = resume.job_id.clone();
        push_durable_github_event(
            &mut resume,
            started_at_ms.saturating_add(1),
            "cleanup",
            RemoteBuildEventKind::CleanupFinished {
                confirmation: CleanupConfirmation {
                    job_id,
                    completed_at_ms: started_at_ms.saturating_add(1),
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                },
            },
        );
        store
            .checkpoint_github_resume(&record.local_job_id, &resume)
            .expect("cleaned checkpoint");
    }

    fn complete_cleanup_with_cadence(
        temporary: &tempfile::TempDir,
        checkpoint_cleaning: bool,
    ) -> StoredJobV1 {
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let bytes = b"verified artifact bytes";
        let evidence = durable_controller_record(temporary, Some(bytes));
        let record = create_provider_artifact_ready_job(&store, &evidence);
        let artifact_parent = temporary.path().join("target").join("ferry");
        std::fs::create_dir_all(&artifact_parent).expect("artifact parent");
        let artifact_path = canonical_utf8(&artifact_parent).join("App-unsigned.xcarchive.zip");
        let destinations = BTreeMap::from([(
            "artifact-1".to_owned(),
            test_download_destination(&artifact_path),
        )]);
        persist_downloading(&store, &record.local_job_id, &destinations)
            .expect("downloading revision");
        std::fs::write(&artifact_path, bytes).expect("artifact bytes");
        let validated = independently_validate_download(
            &store,
            &record.local_job_id,
            "artifact-1",
            &artifact_path,
        )
        .expect("independent local validation");
        persist_downloaded_artifact(&store, &record.local_job_id, "artifact-1", &validated)
            .expect("artifact path checkpoint");
        persist_downloads_complete(&store, &record.local_job_id).expect("download completion");
        persist_validating(&store, &record.local_job_id).expect("validating revision");
        persist_validation_ready_for_cleanup(&store, &record.local_job_id)
            .expect("cleanup overlay");
        let pending = store.latest(&record.local_job_id).expect("pending cleanup");
        assert_eq!(pending.state, StoredJobState::CleanupPending);
        assert_eq!(
            pending.last_confirmed_state,
            Some(StoredJobState::Validating)
        );

        checkpoint_cleaned_job(&store, &record, checkpoint_cleaning);
        let cleaned = store
            .latest(&record.local_job_id)
            .expect("cleaned revision");
        assert_eq!(cleaned.state, StoredJobState::CleanupPending);
        assert_eq!(
            cleaned.last_confirmed_state,
            Some(StoredJobState::Validating)
        );
        assert_eq!(cleaned.cleanup_status, StoredCleanupStatus::Confirmed);

        let root = canonical_utf8(temporary.path());
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        validate_and_promote_durable_success(
            &store,
            &record.local_job_id,
            &project_binding,
            &destinations,
        )
        .expect("durable success promotion");
        store.latest(&record.local_job_id).expect("promoted job")
    }

    #[test]
    fn cancellation_timeout_is_persisted_as_uncertain_without_claiming_terminal() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("initial revision");

        assert!(
            persist_cancellation_requested(&store, &record.local_job_id)
                .expect("persist cancellation intent")
        );
        persist_cancellation_uncertain(&store, &record.local_job_id)
            .expect("persist uncertain cancellation");

        let latest = store.latest(&record.local_job_id).expect("latest revision");
        assert_eq!(latest.state, StoredJobState::Unknown);
        assert_eq!(
            latest.last_confirmed_state,
            Some(StoredJobState::CancellationRequested)
        );
        assert_eq!(
            latest.cancellation_status,
            StoredCancellationStatus::Uncertain
        );
        assert!(latest.terminal_outcome.is_none());
    }

    #[test]
    fn cancelled_cleanup_uncertainty_preserves_cancelled_underlying_phase() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("initial revision");
        assert!(
            persist_cancellation_requested(&store, &record.local_job_id)
                .expect("durable cancellation intent")
        );
        let mut resume = successful_cleanup_resume(&record);
        resume.state = JobState::Cancelled;
        resume.run.as_mut().expect("run identity").conclusion =
            Some(GithubRunConclusionV1::Cancelled);
        resume.cancellation_requested = true;
        resume.cancellation_dispatched = true;
        resume.cleanup_requested = false;
        resume.manifests.clear();
        resume.compile_evidence = None;
        resume.events.clear();
        push_durable_github_event(
            &mut resume,
            record.created_at_ms.saturating_add(1),
            "cancelled",
            RemoteBuildEventKind::OperationCancelled {
                reason: "test cancellation".to_owned(),
                duration_ms: 1,
            },
        );
        store
            .checkpoint_github_resume(&record.local_job_id, &resume)
            .expect("cancelled provider checkpoint");

        persist_cleanup_pending(&store, &record.local_job_id).expect("cleanup intent");
        persist_cleanup_uncertain(&store, &record.local_job_id).expect("cleanup uncertainty");

        let latest = store.latest(&record.local_job_id).expect("latest revision");
        assert_eq!(latest.state, StoredJobState::Unknown);
        assert_eq!(latest.last_confirmed_state, Some(StoredJobState::Cancelled));
        assert_eq!(latest.terminal_outcome, Some(StoredBuildOutcome::Cancelled));
        assert_eq!(
            latest.cancellation_status,
            StoredCancellationStatus::Confirmed
        );
        assert_eq!(latest.cleanup_status, StoredCleanupStatus::Uncertain);
    }

    #[test]
    fn expired_cleanup_uncertainty_preserves_expired_underlying_phase() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("initial revision");
        for state in [StoredJobState::Submitting, StoredJobState::Running] {
            update_stored_job(&store, &record.local_job_id, |_previous, next| {
                next.state = state;
                next.last_confirmed_state = Some(state);
                Ok(())
            })
            .expect("advance local phase");
        }
        let artifact_record = durable_controller_record(&temporary, Some(b"artifact bytes"));
        update_stored_job(&store, &record.local_job_id, |_previous, next| {
            next.state = StoredJobState::ArtifactReady;
            next.last_confirmed_state = Some(StoredJobState::ArtifactReady);
            next.artifacts.clone_from(&artifact_record.artifacts);
            Ok(())
        })
        .expect("artifact-ready revision");
        update_stored_job(&store, &record.local_job_id, |_previous, next| {
            next.state = StoredJobState::Expired;
            next.last_confirmed_state = Some(StoredJobState::Expired);
            next.terminal_outcome = Some(StoredBuildOutcome::Expired);
            Ok(())
        })
        .expect("expired revision");

        persist_cleanup_pending(&store, &record.local_job_id).expect("cleanup intent");
        persist_cleanup_uncertain(&store, &record.local_job_id).expect("cleanup uncertainty");

        let latest = store.latest(&record.local_job_id).expect("latest revision");
        assert_eq!(latest.state, StoredJobState::Unknown);
        assert_eq!(latest.last_confirmed_state, Some(StoredJobState::Expired));
        assert_eq!(latest.terminal_outcome, Some(StoredBuildOutcome::Expired));
        assert_eq!(latest.cleanup_status, StoredCleanupStatus::Uncertain);
    }

    #[test]
    fn succeeded_cleanup_uncertainty_remains_recoverable_for_cleanup_retry() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let record = durable_controller_record(&temporary, None);
        store.create(&record).expect("initial revision");
        for state in [StoredJobState::Submitting, StoredJobState::Running] {
            update_stored_job(&store, &record.local_job_id, |_previous, next| {
                next.state = state;
                next.last_confirmed_state = Some(state);
                Ok(())
            })
            .expect("advance local phase");
        }
        let artifact_record = durable_controller_record(&temporary, Some(b"artifact bytes"));
        let mut resume = successful_cleanup_resume(&artifact_record);
        resume.cleanup_requested = false;
        store
            .checkpoint_github_resume(&record.local_job_id, &resume)
            .expect("successful provider checkpoint");

        persist_cleanup_pending(&store, &record.local_job_id).expect("cleanup intent");
        persist_cleanup_uncertain(&store, &record.local_job_id).expect("cleanup uncertainty");

        let uncertain = store
            .latest(&record.local_job_id)
            .expect("uncertain cleanup revision");
        assert_eq!(uncertain.state, StoredJobState::Failed);
        assert_eq!(
            uncertain.last_confirmed_state,
            Some(StoredJobState::ArtifactReady)
        );
        assert_eq!(
            uncertain.terminal_outcome,
            Some(StoredBuildOutcome::Succeeded)
        );
        assert_eq!(uncertain.cleanup_status, StoredCleanupStatus::Uncertain);
        let failure = uncertain
            .failure
            .as_ref()
            .expect("sanitized cleanup failure");
        assert_eq!(failure.code, "controller.cleanup_unconfirmed");
        assert!(failure.retryable);

        persist_cleanup_pending(&store, &record.local_job_id).expect("cleanup retry intent");
        let retry = store
            .latest(&record.local_job_id)
            .expect("cleanup retry revision");
        assert_eq!(retry.state, StoredJobState::CleanupPending);
        assert_eq!(
            retry.last_confirmed_state,
            Some(StoredJobState::ArtifactReady)
        );
        assert_eq!(retry.cleanup_status, StoredCleanupStatus::Pending);
        assert_eq!(retry.failure, uncertain.failure);
    }

    #[test]
    fn cancellation_outcome_distinguishes_cancelled_terminal_races_and_uncertainty() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let uncertain = durable_controller_record(&temporary, None);
        assert_eq!(
            cancellation_outcome_from_job(&uncertain),
            CancellationWaitOutcome::Uncertain
        );

        let other_terminal = durable_controller_record(&temporary, Some(b"artifact"));
        assert_eq!(
            cancellation_outcome_from_job(&other_terminal),
            CancellationWaitOutcome::OtherTerminal
        );

        let mut cancelled = uncertain;
        cancelled.state = StoredJobState::Cancelled;
        cancelled.terminal_outcome = Some(StoredBuildOutcome::Cancelled);
        cancelled.cancellation_status = StoredCancellationStatus::Confirmed;
        assert_eq!(
            cancellation_outcome_from_job(&cancelled),
            CancellationWaitOutcome::Cancelled
        );
    }

    #[test]
    fn interrupted_cleanup_output_names_success_and_failure_terminal_races() {
        assert_eq!(
            interrupted_cleanup_progress(Some(StoredBuildOutcome::Succeeded), false, true),
            "Remote build succeeded before cancellation; cleanup confirmed"
        );
        assert_eq!(
            interrupted_cleanup_progress(Some(StoredBuildOutcome::Failed), false, false),
            "Remote build failed before cancellation; cleanup remains unconfirmed"
        );
        assert_eq!(
            interrupted_cleanup_progress(Some(StoredBuildOutcome::Cancelled), true, true),
            "Remote cancellation and cleanup confirmed"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn submit_publication_evidence_requires_exact_mapping_or_strong_absence() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let record = durable_controller_record(&temporary, None);
        let mut resume = successful_cleanup_resume(&record);
        let job_id = resume.job_id.clone();

        resume.publication_uncertain = true;
        assert_eq!(
            submit_publication_evidence(&resume, &job_id, WorkflowRunTrigger::Push),
            SubmitPublicationEvidence::Pending
        );

        resume.dispatch_commit = Some("a".repeat(40));
        resume.publication_uncertain = false;
        assert_eq!(
            submit_publication_evidence(&resume, &job_id, WorkflowRunTrigger::Push),
            SubmitPublicationEvidence::Mapped
        );
        let mut dispatch_pre_intent = resume.clone();
        dispatch_pre_intent.run = None;
        dispatch_pre_intent.workflow_dispatch = None;
        assert_eq!(
            submit_publication_evidence(
                &dispatch_pre_intent,
                &job_id,
                WorkflowRunTrigger::WorkflowDispatch,
            ),
            SubmitPublicationEvidence::Pending
        );
        assert!(!provider_resume_is_bound(
            &dispatch_pre_intent,
            &job_id,
            WorkflowRunTrigger::WorkflowDispatch,
        ));

        let mut dispatch_mapped = resume.clone();
        let dispatch_revision = dispatch_mapped
            .dispatch_commit
            .clone()
            .expect("dispatch commit");
        let run = dispatch_mapped.run.as_mut().expect("mapped Push run");
        run.event = GithubRunEventV1::WorkflowDispatch;
        run.head_sha.clone_from(&dispatch_revision);
        let branch = run.branch.clone();
        let workflow_id = run.workflow_id;
        let workflow_path = run.workflow_path.clone();
        let run_name = format!(
            "rustferry-v1|{}|{}|{}|{}",
            dispatch_mapped.operation_id,
            dispatch_mapped.request_sha256,
            dispatch_mapped.source_revision,
            dispatch_revision,
        );
        let body = format!(
            "{{\"ref\":\"{branch}\",\"inputs\":{{\"operation_id\":\"{}\",\"request_sha256\":\"{}\",\"source_revision\":\"{}\",\"dispatch_revision\":\"{}\"}}}}",
            dispatch_mapped.operation_id,
            dispatch_mapped.request_sha256,
            dispatch_mapped.source_revision,
            dispatch_revision,
        );
        let receipt = GithubWorkflowDispatchReceiptV1 {
            run_id: run.run_id,
            workflow_id,
            workflow_path: workflow_path.clone(),
            branch: branch.clone(),
            dispatch_revision: dispatch_revision.clone(),
            run_name: run_name.clone(),
        };
        dispatch_mapped.workflow_dispatch = Some(Box::new(GithubWorkflowDispatchResumeV1 {
            schema_version: 1,
            workflow_id,
            workflow_path,
            branch,
            operation_id: dispatch_mapped.operation_id.clone(),
            request_sha256: dispatch_mapped.request_sha256.clone(),
            source_revision: dispatch_mapped.source_revision.clone(),
            dispatch_revision,
            body_sha256: sha256_bytes(body.as_bytes()),
            run_name,
            uncertain: false,
            receipt: Some(receipt),
        }));
        dispatch_mapped
            .validate_trigger_binding()
            .expect("complete dispatch binding");
        assert_eq!(
            submit_publication_evidence(
                &dispatch_mapped,
                &job_id,
                WorkflowRunTrigger::WorkflowDispatch,
            ),
            SubmitPublicationEvidence::Mapped
        );
        assert!(provider_resume_is_bound(
            &dispatch_mapped,
            &job_id,
            WorkflowRunTrigger::WorkflowDispatch,
        ));

        let mut dispatch_intent = dispatch_mapped.clone();
        let intent = dispatch_intent
            .workflow_dispatch
            .as_mut()
            .expect("dispatch intent");
        intent.receipt = None;
        intent.uncertain = true;
        dispatch_intent.run = None;
        assert_eq!(
            submit_publication_evidence(
                &dispatch_intent,
                &job_id,
                WorkflowRunTrigger::WorkflowDispatch,
            ),
            SubmitPublicationEvidence::Pending
        );
        assert!(!provider_resume_is_bound(
            &dispatch_intent,
            &job_id,
            WorkflowRunTrigger::WorkflowDispatch,
        ));

        let mut dispatch_receipt_only = dispatch_mapped.clone();
        dispatch_receipt_only.run = None;
        assert_eq!(
            submit_publication_evidence(
                &dispatch_receipt_only,
                &job_id,
                WorkflowRunTrigger::WorkflowDispatch,
            ),
            SubmitPublicationEvidence::Pending
        );
        assert!(!provider_resume_is_bound(
            &dispatch_receipt_only,
            &job_id,
            WorkflowRunTrigger::WorkflowDispatch,
        ));

        let mut dispatch_as_push = dispatch_mapped.clone();
        dispatch_as_push.run.as_mut().expect("dispatch run").event = GithubRunEventV1::Push;
        assert!(!provider_resume_is_bound(
            &dispatch_as_push,
            &job_id,
            WorkflowRunTrigger::WorkflowDispatch,
        ));
        assert!(!provider_resume_is_bound(
            &dispatch_mapped,
            &job_id,
            WorkflowRunTrigger::Push,
        ));
        assert_eq!(
            submit_publication_evidence(&dispatch_mapped, &job_id, WorkflowRunTrigger::Push,),
            SubmitPublicationEvidence::Pending
        );

        resume.dispatch_commit = None;
        resume.publication_absent = true;
        resume.publication_absence_observations = 1;
        resume.temporary_ref_deleted = true;
        assert_eq!(
            submit_publication_evidence(&resume, &job_id, WorkflowRunTrigger::Push),
            SubmitPublicationEvidence::Pending
        );
        resume.publication_absence_observations = 2;
        assert_eq!(
            submit_publication_evidence(&resume, &job_id, WorkflowRunTrigger::Push),
            SubmitPublicationEvidence::Absent
        );

        resume.publication_absent = false;
        resume.publication_uncertain = true;
        resume.state = JobState::Failed;
        resume.publication_absence_first_observed_at_ms = 1;
        assert_eq!(
            submit_publication_evidence(&resume, &job_id, WorkflowRunTrigger::Push),
            SubmitPublicationEvidence::Conflict
        );

        assert_eq!(
            submit_publication_evidence(&resume, "different-job", WorkflowRunTrigger::Push,),
            SubmitPublicationEvidence::Pending
        );
    }

    #[test]
    fn project_binding_rejects_or_blocks_a_replaced_directory_before_later_writes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("project");
        let original = temporary.path().join("original-project");
        std::fs::create_dir(&project).expect("project directory");
        let root = canonical_utf8(&project);
        let binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        binding.verify().expect("original binding");

        if std::fs::rename(&project, &original).is_err() {
            binding
                .verify()
                .expect("retained project path remains bound");
            return;
        }
        std::fs::create_dir(&project).expect("replacement project");
        assert!(binding.verify().is_err());
    }

    #[test]
    fn project_binding_rejects_or_blocks_a_whole_root_alias_handoff() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("project");
        let moved = temporary.path().join("moved-project");
        std::fs::create_dir(&project).expect("project directory");
        let root = canonical_utf8(&project);
        let binding = ProjectFilesystemBinding::capture(&root).expect("project binding");

        if std::fs::rename(&project, &moved).is_err() {
            binding
                .verify()
                .expect("retained project path remains bound");
            return;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&moved, &project).expect("project alias");
        #[cfg(windows)]
        if std::os::windows::fs::symlink_dir(&moved, &project).is_err() {
            return;
        }

        assert!(binding.verify().is_err());
    }

    #[test]
    fn download_destination_rejects_a_linked_parent_below_target_ferry() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("project");
        let managed = project.join("target").join("ferry");
        let outside = temporary.path().join("outside");
        std::fs::create_dir_all(&managed).expect("managed root");
        std::fs::create_dir(&outside).expect("outside directory");
        let linked = managed.join("linked");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &linked).expect("linked destination parent");
        #[cfg(windows)]
        if std::os::windows::fs::symlink_dir(&outside, &linked).is_err() {
            return;
        }

        let root = canonical_utf8(&project);
        let binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let destination = camino::Utf8PathBuf::from_path_buf(linked.join("artifact.zip"))
            .expect("UTF-8 destination");
        assert!(DownloadDestinationBinding::capture(&destination, &binding).is_err());
    }

    #[test]
    fn download_destination_rejects_or_blocks_a_managed_root_alias_handoff() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("project");
        let managed = project.join("target").join("ferry");
        let parent = managed.join("ios").join("device").join("debug");
        let moved = project.join("target").join("moved-ferry");
        std::fs::create_dir_all(&parent).expect("artifact parent");
        let root = canonical_utf8(&project);
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let destination = canonical_utf8(&parent).join("artifact.zip");
        let binding = DownloadDestinationBinding::capture(&destination, &project_binding)
            .expect("destination binding");

        if std::fs::rename(&managed, &moved).is_err() {
            binding
                .verify(&project_binding)
                .expect("retained managed root remains bound");
            return;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&moved, &managed).expect("managed root alias");
        #[cfg(windows)]
        if std::os::windows::fs::symlink_dir(&moved, &managed).is_err() {
            return;
        }

        assert!(binding.verify(&project_binding).is_err());
    }

    #[test]
    fn success_promotion_reconciliation_allows_only_validation_false_to_true() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut before = durable_controller_record(&temporary, Some(b"artifact"));
        before.state = StoredJobState::CleanupPending;
        before.cleanup_status = StoredCleanupStatus::Confirmed;
        before.artifacts[0].download_destination = Some(
            temporary
                .path()
                .join("target")
                .join("ferry")
                .join("artifact.zip")
                .to_string_lossy()
                .into_owned(),
        );
        before.artifacts[0].download_parent_identity = Some("unix:1:2".to_owned());
        before.artifacts[0].local_path = before.artifacts[0].download_destination.clone();
        before.artifacts[0].local_file_identity = Some("unix:1:3".to_owned());

        let mut promoted = before.clone();
        promoted.revision += 1;
        promoted.updated_at_ms += 1;
        promoted.state = StoredJobState::Succeeded;
        promoted.last_confirmed_state = Some(StoredJobState::Succeeded);
        promoted.artifacts[0].locally_validated = true;
        assert!(is_exact_success_promotion(&before, &promoted));

        promoted.artifacts[0].local_file_identity = Some("unix:1:4".to_owned());
        assert!(!is_exact_success_promotion(&before, &promoted));
    }

    #[test]
    fn rejected_download_checkpoint_preserves_the_intended_file_for_reconciliation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let bytes = b"verified artifact bytes";
        let evidence = durable_controller_record(&temporary, Some(bytes));
        let record = create_provider_artifact_ready_job(&store, &evidence);
        let artifact_parent = temporary.path().join("target").join("ferry");
        std::fs::create_dir_all(&artifact_parent).expect("artifact parent");
        let artifact_path = canonical_utf8(&artifact_parent).join("App-unsigned.xcarchive.zip");
        let destinations = BTreeMap::from([(
            "artifact-1".to_owned(),
            test_download_destination(&artifact_path),
        )]);
        persist_downloading(&store, &record.local_job_id, &destinations)
            .expect("downloading revision");
        std::fs::write(&artifact_path, bytes).expect("artifact bytes");
        let validated = independently_validate_download(
            &store,
            &record.local_job_id,
            "artifact-1",
            &artifact_path,
        )
        .expect("independent validation");
        persist_downloaded_artifact(&store, &record.local_job_id, "missing-artifact", &validated)
            .expect_err("unknown artifact must not publish");

        let latest = store.latest(&record.local_job_id).expect("latest revision");
        assert_eq!(latest.state, StoredJobState::Downloading);
        assert_eq!(
            latest.artifacts[0].download_destination.as_deref(),
            Some(artifact_path.as_str())
        );
        assert!(latest.artifacts[0].local_path.is_none());
        assert_eq!(
            std::fs::read(&artifact_path).expect("preserved artifact"),
            bytes
        );
    }

    #[test]
    fn artifact_publication_uncertainty_preserves_downloading_and_downloaded_phases() {
        for downloaded in [false, true] {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
            let bytes = b"verified artifact bytes";
            let evidence = durable_controller_record(&temporary, Some(bytes));
            let record = create_provider_artifact_ready_job(&store, &evidence);
            let artifact_parent = temporary.path().join("target").join("ferry");
            std::fs::create_dir_all(&artifact_parent).expect("artifact parent");
            let artifact_path = canonical_utf8(&artifact_parent).join("artifact.zip");
            let destinations = BTreeMap::from([(
                "artifact-1".to_owned(),
                test_download_destination(&artifact_path),
            )]);
            persist_downloading(&store, &record.local_job_id, &destinations)
                .expect("downloading revision");
            if downloaded {
                std::fs::write(&artifact_path, bytes).expect("artifact bytes");
                let validated = independently_validate_download(
                    &store,
                    &record.local_job_id,
                    "artifact-1",
                    &artifact_path,
                )
                .expect("independent validation");
                persist_downloaded_artifact(&store, &record.local_job_id, "artifact-1", &validated)
                    .expect("artifact checkpoint");
                persist_downloads_complete(&store, &record.local_job_id)
                    .expect("downloaded revision");
            }
            let expected = if downloaded {
                StoredJobState::Downloaded
            } else {
                StoredJobState::Downloading
            };
            let before = store.latest(&record.local_job_id).expect("download phase");
            assert_eq!(before.state, expected);
            assert_eq!(
                before.last_confirmed_state,
                Some(StoredJobState::ArtifactReady)
            );

            persist_artifact_publication_uncertain(
                &store,
                &record.local_job_id,
                "controller.artifact_publication_uncertain",
            )
            .expect("durable publication uncertainty");

            let uncertain = store
                .latest(&record.local_job_id)
                .expect("uncertain publication revision");
            assert_eq!(uncertain.state, StoredJobState::Unknown);
            assert_eq!(uncertain.last_confirmed_state, Some(expected));
            let failure = uncertain.failure.as_ref().expect("sanitized failure");
            assert_eq!(failure.code, "controller.artifact_publication_uncertain");
            assert!(!failure.retryable);

            persist_cleanup_pending(&store, &record.local_job_id)
                .expect("cleanup intent after publication uncertainty");
            let pending = store
                .latest(&record.local_job_id)
                .expect("cleanup-pending revision");
            assert_eq!(pending.state, StoredJobState::CleanupPending);
            assert_eq!(pending.last_confirmed_state, Some(expected));
            assert_eq!(pending.cleanup_status, StoredCleanupStatus::Pending);
        }
    }

    #[test]
    fn artifact_failure_cleanup_uses_failed_phase_and_reaches_exact_confirmation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let evidence = durable_controller_record(&temporary, Some(b"artifact bytes"));
        let record = create_provider_artifact_ready_job(&store, &evidence);
        let artifact_parent = temporary.path().join("target").join("ferry");
        std::fs::create_dir_all(&artifact_parent).expect("artifact parent");
        let artifact_path = canonical_utf8(&artifact_parent).join("artifact.zip");
        let destinations = BTreeMap::from([(
            "artifact-1".to_owned(),
            test_download_destination(&artifact_path),
        )]);
        persist_downloading(&store, &record.local_job_id, &destinations)
            .expect("downloading revision");
        persist_controller_failure(
            &store,
            &record.local_job_id,
            "controller.artifact_processing_failed",
            false,
        )
        .expect("durable artifact failure");
        let failed = store.latest(&record.local_job_id).expect("failed revision");
        assert_eq!(failed.state, StoredJobState::Failed);
        assert_eq!(failed.last_confirmed_state, Some(StoredJobState::Failed));

        let root = canonical_utf8(temporary.path());
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let provider_job_id = record.provider_job_id.clone().expect("provider job ID");
        let cleanup_called = Cell::new(false);
        cleanup_job_durably_with(
            &store,
            &record.local_job_id,
            &provider_job_id,
            &project_binding,
            || {
                cleanup_called.set(true);
                let pending = store
                    .latest(&record.local_job_id)
                    .expect("cleanup-pending revision");
                assert_eq!(pending.state, StoredJobState::CleanupPending);
                assert_eq!(pending.last_confirmed_state, Some(StoredJobState::Failed));
                assert_eq!(pending.cleanup_status, StoredCleanupStatus::Pending);
                checkpoint_cleaned_job(&store, &record, false);
                Ok(CleanupConfirmation {
                    job_id: provider_job_id.clone(),
                    completed_at_ms: record.created_at_ms.saturating_add(4),
                    workspace_removed: true,
                    signing_material_removed: true,
                    artifacts_retained: true,
                })
            },
        )
        .expect("exact durable cleanup");

        assert!(cleanup_called.get());
        let cleaned = store
            .latest(&record.local_job_id)
            .expect("cleaned revision");
        assert_eq!(cleaned.state, StoredJobState::Failed);
        assert_eq!(cleaned.cleanup_status, StoredCleanupStatus::Confirmed);
        assert_eq!(
            cleaned
                .failure
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some("controller.artifact_processing_failed")
        );
        let resume = cleaned
            .provider_resume
            .as_ref()
            .expect("provider checkpoint");
        assert_eq!(resume.state, JobState::Cleaned);
        assert!(resume.temporary_ref_deleted);
    }

    #[test]
    fn unreadable_path_checkpoint_remains_reconciliation_uncertain() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let record = durable_controller_record(&temporary, Some(b"artifact"));
        let artifact_path = camino::Utf8PathBuf::from_path_buf(temporary.path().join("artifact"))
            .expect("UTF-8 artifact path");
        std::fs::write(&artifact_path, b"artifact").expect("artifact bytes");
        let validated = ValidatedLocalArtifact {
            path: artifact_path.to_string(),
            file_identity: rustferry_core::RegularFileFilesystemIdentity::capture(
                artifact_path.as_std_path(),
            )
            .expect("artifact identity"),
        };

        assert_eq!(
            reconcile_artifact_path_publication(record.revision, None, "artifact-1", &validated,),
            ArtifactPathReconciliation::Uncertain
        );
    }

    #[test]
    fn exact_downloads_are_rehashed_before_paths_and_validation_are_persisted() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let bytes = b"verified artifact bytes";
        let evidence = durable_controller_record(&temporary, Some(bytes));
        let record = create_provider_artifact_ready_job(&store, &evidence);
        let artifact_parent = temporary.path().join("target").join("ferry");
        std::fs::create_dir_all(&artifact_parent).expect("artifact parent");
        let artifact_path = canonical_utf8(&artifact_parent).join("App-unsigned.xcarchive.zip");
        let destinations = BTreeMap::from([(
            "artifact-1".to_owned(),
            test_download_destination(&artifact_path),
        )]);
        persist_downloading(&store, &record.local_job_id, &destinations)
            .expect("downloading revision");
        std::fs::write(&artifact_path, bytes).expect("artifact bytes");
        let validated = independently_validate_download(
            &store,
            &record.local_job_id,
            "artifact-1",
            &artifact_path,
        )
        .expect("independent local validation");
        persist_downloaded_artifact(&store, &record.local_job_id, "artifact-1", &validated)
            .expect("path checkpoint");
        persist_downloads_complete(&store, &record.local_job_id).expect("download completion");
        persist_validating(&store, &record.local_job_id).expect("validating revision");
        persist_validation_ready_for_cleanup(&store, &record.local_job_id)
            .expect("validated cleanup intent");

        let latest = store.latest(&record.local_job_id).expect("latest revision");
        assert_eq!(latest.state, StoredJobState::CleanupPending);
        assert_eq!(latest.cleanup_status, StoredCleanupStatus::Pending);
        assert_eq!(
            latest.artifacts[0].local_path.as_deref(),
            Some(artifact_path.as_str())
        );
        assert!(latest.artifacts[0].download_parent_identity.is_some());
        assert!(latest.artifacts[0].local_file_identity.is_some());
        assert!(!latest.artifacts[0].locally_validated);
        assert_eq!(std::fs::read(&artifact_path).expect("artifact"), bytes);
    }

    #[test]
    fn cleanup_checkpoint_cadence_preserves_validation_and_promotes_exact_success() {
        let direct_temporary = tempfile::tempdir().expect("direct cleanup directory");
        let direct = complete_cleanup_with_cadence(&direct_temporary, false);
        let cleaning_temporary = tempfile::tempdir().expect("cleaning checkpoint directory");
        let with_cleaning = complete_cleanup_with_cadence(&cleaning_temporary, true);

        for completed in [&direct, &with_cleaning] {
            assert_eq!(completed.state, StoredJobState::Succeeded);
            assert_eq!(
                completed.last_confirmed_state,
                Some(StoredJobState::Succeeded)
            );
            assert_eq!(
                completed.terminal_outcome,
                Some(StoredBuildOutcome::Succeeded)
            );
            assert_eq!(completed.cleanup_status, StoredCleanupStatus::Confirmed);
            assert!(
                completed
                    .artifacts
                    .iter()
                    .all(|artifact| artifact.locally_validated)
            );
        }
    }

    #[test]
    fn final_promotion_rejects_or_blocks_replacing_an_earlier_validated_artifact() {
        let temporary = tempfile::tempdir().expect("promotion guard directory");
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let first_bytes = b"first verified artifact";
        let second_bytes = b"second verified artifact";
        let mut evidence = durable_controller_record(&temporary, Some(first_bytes));
        evidence.artifacts.push(StoredArtifactV1 {
            record: ArtifactRecord {
                artifact_id: "artifact-2".to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: "sanitized-build-log.txt".to_owned(),
                size: u64::try_from(second_bytes.len()).expect("artifact size"),
                sha256: super::sha256_bytes(second_bytes),
                media_type: Some("text/plain".to_owned()),
            },
            download_destination: None,
            download_parent_identity: None,
            local_path: None,
            local_file_identity: None,
            locally_validated: false,
        });
        evidence.validate().expect("two-artifact durable record");
        let record = create_provider_artifact_ready_job(&store, &evidence);
        let parent = temporary.path().join("target").join("ferry");
        std::fs::create_dir_all(&parent).expect("artifact parent");
        let canonical_parent = canonical_utf8(&parent);
        let first = canonical_parent.join("first.zip");
        let second = canonical_parent.join("second.txt");
        let destinations = BTreeMap::from([
            ("artifact-1".to_owned(), test_download_destination(&first)),
            ("artifact-2".to_owned(), test_download_destination(&second)),
        ]);
        persist_downloading(&store, &record.local_job_id, &destinations).expect("download intents");
        for (artifact_id, path, bytes) in [
            ("artifact-1", first.as_path(), first_bytes.as_slice()),
            ("artifact-2", second.as_path(), second_bytes.as_slice()),
        ] {
            std::fs::write(path, bytes).expect("artifact bytes");
            let validated =
                independently_validate_download(&store, &record.local_job_id, artifact_id, path)
                    .expect("validated artifact");
            persist_downloaded_artifact(&store, &record.local_job_id, artifact_id, &validated)
                .expect("artifact checkpoint");
        }
        persist_downloads_complete(&store, &record.local_job_id).expect("download completion");
        persist_validating(&store, &record.local_job_id).expect("validating revision");
        persist_validation_ready_for_cleanup(&store, &record.local_job_id)
            .expect("cleanup overlay");
        checkpoint_cleaned_job(&store, &record, false);
        let root = canonical_utf8(temporary.path());
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let displaced = first.with_file_name("displaced-first.zip");
        let mutation_succeeded = Cell::new(false);

        let promotion = validate_and_promote_durable_success_with_hook(
            &store,
            &record.local_job_id,
            &project_binding,
            &destinations,
            |index| {
                if index == 0 {
                    let renamed = std::fs::rename(&first, &displaced).is_ok();
                    let overwritten = !renamed && std::fs::write(&first, b"replacement").is_ok();
                    mutation_succeeded.set(renamed || overwritten);
                    if renamed {
                        std::fs::write(&first, b"replacement").expect("replacement artifact");
                    }
                }
            },
        );
        let latest = store.latest(&record.local_job_id).expect("latest job");
        if mutation_succeeded.get() {
            assert!(promotion.is_err());
            assert_eq!(latest.state, StoredJobState::CleanupPending);
            assert!(
                latest
                    .artifacts
                    .iter()
                    .all(|artifact| !artifact.locally_validated)
            );
        } else {
            promotion.expect("replacement was blocked by retained artifact guard");
            assert_eq!(latest.state, StoredJobState::Succeeded);
        }
    }

    #[test]
    fn confirmed_cleanup_reentry_skips_provider_mutation_and_revision() {
        let temporary = tempfile::tempdir().expect("cleanup reentry directory");
        let completed = complete_cleanup_with_cadence(&temporary, false);
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let root = canonical_utf8(temporary.path());
        let project_binding = ProjectFilesystemBinding::capture(&root).expect("project binding");
        let provider_job_id = completed
            .provider_job_id
            .as_deref()
            .expect("provider job ID");

        cleanup_job_durably_with(
            &store,
            &completed.local_job_id,
            provider_job_id,
            &project_binding,
            || panic!("provider cleanup must not run after exact durable confirmation"),
        )
        .expect("idempotent cleanup reentry");

        let unchanged = store
            .latest(&completed.local_job_id)
            .expect("unchanged latest job");
        assert_eq!(unchanged.revision, completed.revision);
        assert_eq!(unchanged, completed);
    }

    #[test]
    fn confirmed_cleanup_reentry_keeps_confirmation_when_project_binding_changed() {
        let temporary = tempfile::tempdir().expect("cleanup reentry directory");
        let completed = complete_cleanup_with_cadence(&temporary, false);
        let store = JobStore::open_at(temporary.path().join("job-store")).expect("job store");
        let original = temporary.path().join("bound-project");
        let replacement = temporary.path().join("replacement-project");
        std::fs::create_dir(&original).expect("bound project");
        std::fs::create_dir(&replacement).expect("replacement project");
        let retained = rustferry_core::RetainedDirectoryIdentity::open(&original)
            .expect("retained original project");
        let project_binding = ProjectFilesystemBinding {
            root: camino::Utf8PathBuf::from_path_buf(
                replacement.canonicalize().expect("canonical replacement"),
            )
            .expect("UTF-8 replacement"),
            identity: retained.identity().clone(),
            retained,
        };
        let provider_job_id = completed
            .provider_job_id
            .as_deref()
            .expect("provider job ID");

        assert!(
            cleanup_job_durably_with(
                &store,
                &completed.local_job_id,
                provider_job_id,
                &project_binding,
                || panic!("provider cleanup must not run after exact durable confirmation"),
            )
            .is_err()
        );

        let latest = store.latest(&completed.local_job_id).expect("latest job");
        assert_eq!(latest, completed);
        assert_eq!(
            interrupted_cleanup_progress_for_job(Some(&latest), provider_job_id),
            "Remote build succeeded before cancellation; cleanup confirmed"
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    enum FakeManualSigningEvent {
        Policy {
            phase: &'static str,
            source_repository: String,
            execution_repository: String,
            environment: String,
            config_signed: bool,
        },
        Secret {
            execution_repository: String,
            environment: String,
            name: String,
            value: Vec<u8>,
            config_signed: bool,
        },
    }

    #[derive(Default)]
    struct FakeManualSigningState {
        events: Vec<FakeManualSigningEvent>,
    }

    struct FakeManualSigningRemote {
        policy_results: VecDeque<Result<BTreeSet<String>, CliError>>,
        secret_results: VecDeque<Result<(), TransportError>>,
        state: Rc<RefCell<FakeManualSigningState>>,
        config_path: camino::Utf8PathBuf,
        project_mutation: Option<FakeProjectMutation>,
    }

    struct FakeProjectMutation {
        phase: &'static str,
        path: camino::Utf8PathBuf,
        bytes: Vec<u8>,
    }

    impl ManualSigningRemote for FakeManualSigningRemote {
        fn verify_policy(
            &mut self,
            source_repository: &Repository,
            execution_repository: &Repository,
            environment: &ProtectedEnvironment,
            _stored: &StoredGithubConfig,
            phase: &'static str,
        ) -> Result<BTreeSet<String>, CliError> {
            self.state
                .borrow_mut()
                .events
                .push(FakeManualSigningEvent::Policy {
                    phase,
                    source_repository: format!(
                        "{}/{}",
                        source_repository.owner(),
                        source_repository.name()
                    ),
                    execution_repository: format!(
                        "{}/{}",
                        execution_repository.owner(),
                        execution_repository.name()
                    ),
                    environment: environment.as_str().to_owned(),
                    config_signed: stored_config_is_signed(&self.config_path),
                });
            if self
                .project_mutation
                .as_ref()
                .is_some_and(|mutation| mutation.phase == phase)
            {
                let mutation = self
                    .project_mutation
                    .take()
                    .expect("matched project mutation");
                std::fs::write(mutation.path, mutation.bytes).expect("mutate project state");
            }
            self.policy_results
                .pop_front()
                .expect("unexpected policy verification")
        }

        fn set_secret(
            &mut self,
            request: &EnvironmentSecretWriteRequest,
            value: &SecretBytes,
        ) -> Result<(), TransportError> {
            self.state
                .borrow_mut()
                .events
                .push(FakeManualSigningEvent::Secret {
                    execution_repository: format!(
                        "{}/{}",
                        request.repository().owner(),
                        request.repository().name()
                    ),
                    environment: request.environment().as_str().to_owned(),
                    name: request.name().as_str().to_owned(),
                    value: value.expose_secret_bytes().to_vec(),
                    config_signed: stored_config_is_signed(&self.config_path),
                });
            self.secret_results
                .pop_front()
                .expect("unexpected secret write")
        }
    }

    fn stored_config_is_signed(path: &camino::Utf8Path) -> bool {
        let config = std::fs::read(path).expect("provider config bytes");
        serde_json::from_slice::<StoredGithubConfig>(&config)
            .expect("provider config JSON")
            .signing
            .is_some()
    }

    fn recorded_secret_count(state: &FakeManualSigningState) -> usize {
        state
            .events
            .iter()
            .filter(|event| matches!(event, FakeManualSigningEvent::Secret { .. }))
            .count()
    }

    fn manual_plan_and_assets() -> (SigningPlan, rustferry_apple::ValidatedManualSigningAssets) {
        let team = DevelopmentTeam::new("ABCDE12345", Some("Example Team".to_owned()))
            .expect("development team");
        let certificate = SigningCertificate {
            common_name: "Apple Development: Example".to_owned(),
            sha256_fingerprint: "A".repeat(64),
            team: team.clone(),
            expires_at_unix_seconds: 4_000_000_000,
        };
        let device = DevicePlan::from_sha256("0".repeat(64), None).expect("device hash");
        let secret = |name| {
            SecretReference::new(SecretReferenceKind::GithubActions, name)
                .expect("GitHub secret reference")
        };
        let plan = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: certificate.clone(),
                    private_key: SigningPrivateKeyReference {
                        reference: secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12"),
                    },
                },
                password: Some(secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD")),
            }),
            team: Some(DevelopmentTeamPlan {
                expected: team.clone(),
            }),
            device: Some(device.clone()),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle ID"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: secret("RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::default(),
            }],
            allow_provisioning_updates: false,
        };
        plan.validate().expect("manual signing plan");
        let profile = ProvisioningProfile {
            uuid: "12345678-1234-1234-1234-123456789ABC".to_owned(),
            name: "Development Profile".to_owned(),
            team,
            application_identifier: "ABCDE12345.com.example.app".to_owned(),
            bundle_identifier_pattern: "com.example.app".to_owned(),
            wildcard: false,
            created_at_unix_seconds: 1,
            expires_at_unix_seconds: 4_000_000_000,
            device_udid_sha256s: vec![device.udid_sha256().to_owned()],
            entitlements: EntitlementSet::default(),
            platforms: BTreeSet::from([ProvisioningPlatform::Ios]),
            profile_type: ProvisioningProfileType::Development,
            certificate_fingerprints: vec![certificate.sha256_fingerprint.clone()],
        };
        profile.validate_metadata().expect("profile metadata");
        (
            plan,
            rustferry_apple::ValidatedManualSigningAssets {
                certificate,
                profile,
            },
        )
    }

    #[test]
    fn manual_assets_bind_team_id_not_optional_display_name() {
        let (mut plan, validated) = manual_plan_and_assets();
        let certificate_team =
            DevelopmentTeam::new(validated.certificate.team.id(), None).expect("certificate team");
        let mut certificate = validated.certificate;
        certificate.team = certificate_team.clone();
        plan.signing
            .as_mut()
            .expect("signing identity")
            .identity
            .certificate = certificate.clone();
        plan.team.as_mut().expect("team plan").expected = certificate_team;
        plan.validate().expect("display-name-independent plan");

        let assets = ManualGithubSigningAssets::new(
            certificate.clone(),
            BTreeMap::from([("App".to_owned(), validated.profile.clone())]),
        )
        .expect("same Team ID with different display names");
        validate_manual_assets_match_plan(&plan, &assets)
            .expect("plan comparison uses Team ID only");

        let mut wrong_profile = validated.profile;
        wrong_profile.team = DevelopmentTeam::new("OTHER12345", Some("Example Team".to_owned()))
            .expect("different team");
        assert!(
            ManualGithubSigningAssets::new(
                certificate,
                BTreeMap::from([("App".to_owned(), wrong_profile)]),
            )
            .is_err()
        );
    }

    #[allow(clippy::type_complexity)]
    fn manual_signing_session(
        policy_results: Vec<Result<BTreeSet<String>, CliError>>,
        secret_results: Vec<Result<(), TransportError>>,
    ) -> (
        tempfile::TempDir,
        ManualGithubSigningSession<FakeManualSigningRemote>,
        ManualGithubSecretValues,
        Rc<RefCell<FakeManualSigningState>>,
    ) {
        let (temporary, root, paths, stored) = provider_config_fixture();
        let expected_project_state =
            load_signing_project_state(&root).expect("project signing state");
        ensure_workflow_directory(&root).expect("workflow directory");
        let expected_workflow = b"trusted workflow\n".to_vec();
        write_create_only(&paths.workflow, &expected_workflow, false).expect("workflow fixture");
        let (original_config_identity, original_config_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("config snapshot");
        let config_lock =
            acquire_provider_config_lock(&root, &paths.config_lock).expect("config lock");
        let (plan, assets) = manual_plan_and_assets();
        let secret_names = SigningSecretNames::goal3_defaults();
        let state = Rc::new(RefCell::new(FakeManualSigningState::default()));
        let remote = FakeManualSigningRemote {
            policy_results: policy_results.into(),
            secret_results: secret_results.into(),
            state: Rc::clone(&state),
            config_path: paths.config.clone(),
            project_mutation: None,
        };
        let values = ManualGithubSecretValues {
            certificate_p12: CanonicalBase64SigningBlob::try_from_encoded(
                SecretBytes::new(b"Y2VydA==".to_vec()),
                "certificate_p12",
            )
            .expect("certificate base64"),
            certificate_password: RawSigningPassword::new(SecretBytes::new(
                b"top-secret-canary".to_vec(),
            ))
            .expect("password"),
            profiles: BTreeMap::from([(
                "App".to_owned(),
                CanonicalBase64SigningBlob::try_from_encoded(
                    SecretBytes::new(b"cHJvZmlsZQ==".to_vec()),
                    "provisioning_profile",
                )
                .expect("profile base64"),
            )]),
        };
        let assets = ManualGithubSigningAssets::new(
            assets.certificate,
            BTreeMap::from([("App".to_owned(), assets.profile)]),
        )
        .expect("manual signing assets");
        let session = ManualGithubSigningSession {
            root,
            expected_project_state,
            paths,
            stored,
            original_config_identity: Some(original_config_identity),
            original_config_bytes,
            expected_workflow,
            plan,
            assets,
            source_repository: Repository::new("example", "public-app").expect("source repo"),
            execution_repository: Repository::new("example", "private-builds")
                .expect("execution repo"),
            environment: ProtectedEnvironment::new(PROTECTED_ENVIRONMENT).expect("environment"),
            secret_names,
            remote,
            config_lock: Some(config_lock),
        };
        (temporary, session, values, state)
    }

    fn add_widget_profile_to_manual_signing_session(
        session: &mut ManualGithubSigningSession<FakeManualSigningRemote>,
        values: &mut ManualGithubSecretValues,
    ) -> SigningSecretNames {
        let mut project_config = session.expected_project_state.ferry_config.clone();
        project_config.extensions.widget.enabled = true;
        project_config.extensions.widget.app_group = Some("group.com.example.app".to_owned());
        project_config.ios.min_version = "16.1".to_owned();
        std::fs::write(
            session.root.join("ferry.toml"),
            project_config
                .to_pretty_toml()
                .expect("widget project config"),
        )
        .expect("replace project config fixture");
        let project_state =
            load_signing_project_state(&session.root).expect("widget signing project state");
        let extension = project_state
            .targets
            .iter()
            .find(|target| target.kind == SigningTargetKind::Extension)
            .expect("widget extension target")
            .clone();
        session.plan.targets = project_state.targets.clone();
        let names = SigningSecretNames::for_targets(&session.plan.targets).expect("secret map");
        session.plan.provisioning.push(ProvisioningPlan {
            target: extension.name.clone(),
            profile: SecretReference::new(
                SecretReferenceKind::GithubActions,
                names
                    .profile_for_target(&extension.name)
                    .expect("extension secret")
                    .as_str(),
            )
            .expect("profile reference"),
            profile_type: ProvisioningProfileType::Development,
        });
        session.plan.entitlements.push(EntitlementPlan {
            target: extension.name.clone(),
            required: EntitlementSet::default(),
        });
        session.plan.validate().expect("multi-profile plan");
        session.stored.signing_targets = session.plan.targets.clone();
        session.expected_project_state = project_state;
        session.secret_names = names.clone();

        let mut extension_profile = session
            .assets
            .profiles
            .get("App")
            .expect("app profile")
            .clone();
        extension_profile.uuid = "87654321-4321-4321-4321-CBA987654321".to_owned();
        extension_profile.name = "Widget Development Profile".to_owned();
        extension_profile.application_identifier =
            format!("ABCDE12345.{}", extension.bundle_identifier.as_str());
        extension_profile.bundle_identifier_pattern =
            extension.bundle_identifier.as_str().to_owned();
        extension_profile
            .validate_metadata()
            .expect("extension profile metadata");
        session
            .assets
            .profiles
            .insert(extension.name.clone(), extension_profile);
        values.profiles.insert(
            extension.name,
            CanonicalBase64SigningBlob::try_from_encoded(
                SecretBytes::new(b"d2lkZ2V0".to_vec()),
                "provisioning_profile",
            )
            .expect("extension profile base64"),
        );

        let stored_bytes = encode_stored_config(&session.stored).expect("multi stored config");
        drop(session.original_config_identity.take());
        std::fs::write(&session.paths.config, stored_bytes).expect("replace config fixture");
        let (identity, bytes) = read_private_config_snapshot(&session.root, &session.paths.config)
            .expect("multi config snapshot");
        session.original_config_identity = Some(identity);
        session.original_config_bytes = bytes;

        let generated =
            generate_workflow(&workflow_from_stored(&session.stored).expect("workflow"));
        session.expected_workflow = generated.yaml().as_bytes().to_vec();
        std::fs::write(&session.paths.workflow, &session.expected_workflow)
            .expect("replace workflow fixture");
        names
    }

    fn mutate_project_on_policy(
        session: &mut ManualGithubSigningSession<FakeManualSigningRemote>,
        phase: &'static str,
    ) {
        let mut changed = session.expected_project_state.ferry_config.clone();
        changed.app.name.push_str(" changed");
        session.remote.project_mutation = Some(FakeProjectMutation {
            phase,
            path: session.root.join("ferry.toml"),
            bytes: changed
                .to_pretty_toml()
                .expect("changed project config")
                .into_bytes(),
        });
    }

    fn assert_no_fake_signing_values(details: &[String]) {
        for value in ["Y2VydA==", "cHJvZmlsZQ==", "d2lkZ2V0", "top-secret-canary"] {
            assert!(
                details.iter().all(|detail| !detail.contains(value)),
                "secret value leaked in error details"
            );
        }
    }

    #[test]
    fn parses_credential_free_github_remote_forms() {
        for remote in [
            "ShiroKSH/rustferry",
            "https://github.com/ShiroKSH/rustferry.git",
            "git@github.com:ShiroKSH/rustferry.git",
            "ssh://git@github.com/ShiroKSH/rustferry.git",
        ] {
            let (_, slug, source) = parse_repository_spec(remote).expect("valid remote");
            assert_eq!(slug, "shiroksh/rustferry");
            assert_eq!(source, "https://github.com/shiroksh/rustferry");
        }
        assert!(parse_repository_spec("https://token@github.com/owner/repo").is_err());
    }

    #[test]
    fn split_provider_config_binds_canonical_public_source_and_private_execution_names() {
        let config = unsigned_stored_config();
        validate_stored_config(&config).expect("split provider config");

        let mut mixed_case_source = config.clone();
        mixed_case_source.source_repository = "https://github.com/Example/public-app".to_owned();
        assert!(validate_stored_config(&mixed_case_source).is_err());
        let mut leaked_execution = config.clone();
        leaked_execution.worker_repository = "https://github.com/example/private-builds".to_owned();
        assert!(validate_stored_config(&leaked_execution).is_err());
        for invalid in ["", "-origin", "owner/source", "${{ github.token }}"] {
            assert!(
                validate_git_remote_name(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_stored_config_rejects_any_https_execution_endpoint_before_use() {
        let temporary = tempfile::tempdir().expect("fixture");
        let root =
            camino::Utf8PathBuf::from_path_buf(temporary.path().to_owned()).expect("UTF-8 root");
        let paths = GithubPaths::new(&root, &root);
        for endpoint in ["fetch", "push"] {
            let mut config = unsigned_stored_config();
            let https = GithubGitEndpoint::parse("https://github.com/example/private-builds")
                .expect("HTTPS execution endpoint fixture");
            match endpoint {
                "fetch" => config.execution_fetch_endpoint = https,
                "push" => config.execution_push_endpoint = https,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_stored_config(&config)
                    .expect_err("Unix HTTPS execution endpoint must fail closed")
                    .code(),
                "secure_git_execution_transport_unsupported"
            );
            assert!(!paths.workflow.exists());
            assert!(!paths.config.exists());
        }
    }

    #[test]
    fn stored_target_map_renders_static_secrets_and_legacy_schema_fails_closed() {
        let mut stored = unsigned_stored_config();
        stored.signing_targets.push(SigningTarget {
            name: "Widget".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app.widget")
                .expect("widget bundle ID"),
            kind: SigningTargetKind::Extension,
        });
        validate_stored_config(&stored).expect("current target map");
        let names = SigningSecretNames::for_targets(&stored.signing_targets).expect("secret map");
        let generated = generate_workflow(&workflow_from_stored(&stored).expect("workflow"));
        for name in names.all_names() {
            assert!(
                generated
                    .yaml()
                    .contains(&format!("secrets.{}", name.as_str())),
                "workflow omits {}",
                name.as_str()
            );
        }

        for schema_version in 1..CONFIG_SCHEMA_VERSION {
            let mut legacy = unsigned_stored_config();
            legacy.schema_version = schema_version;
            legacy.signing_targets.clear();
            let encoded = serde_json::to_vec(&legacy).expect("legacy config JSON");
            let decoded = serde_json::from_slice::<StoredGithubConfig>(&encoded)
                .expect("bounded legacy fixture");
            assert_eq!(
                validate_stored_config(&decoded)
                    .expect_err("legacy schema must require setup")
                    .code(),
                "configuration_upgrade_required"
            );
        }

        let mut name_only = serde_json::to_value(unsigned_stored_config()).expect("config value");
        let object = name_only.as_object_mut().expect("config object");
        for field in [
            "source_fetch_endpoint",
            "source_push_endpoint",
            "execution_fetch_endpoint",
            "execution_push_endpoint",
        ] {
            object.remove(field);
        }
        object.insert(
            "source_remote_name".to_owned(),
            serde_json::Value::String("public".to_owned()),
        );
        object.insert(
            "execution_remote_name".to_owned(),
            serde_json::Value::String("signing".to_owned()),
        );
        object.insert(
            "schema_version".to_owned(),
            serde_json::Value::from(CONFIG_SCHEMA_VERSION - 1),
        );
        let name_only = serde_json::to_vec(&name_only).expect("legacy name-only JSON");
        assert_eq!(
            decode_stored_config(&name_only)
                .expect_err("legacy name-only config must require setup")
                .code(),
            "configuration_upgrade_required"
        );

        let mut malformed = unsigned_stored_config();
        malformed.signing_targets.clear();
        assert_eq!(
            validate_stored_config(&malformed)
                .expect_err("current schema requires exact targets")
                .code(),
            "invalid_provider_config"
        );
    }

    #[test]
    fn stored_config_round_trip_preserves_distinct_canonical_fetch_and_push_endpoints() {
        let mut stored = unsigned_stored_config();
        stored.source_push_endpoint = GithubGitEndpoint::parse("git@github.com:example/public-app")
            .expect("source SSH endpoint");
        stored.execution_push_endpoint =
            GithubGitEndpoint::parse("git@github.com:example/private-builds")
                .expect("execution SSH endpoint");
        stored.execution_fetch_endpoint =
            GithubGitEndpoint::parse("git@github.com:example/private-builds")
                .expect("execution SSH fetch endpoint");
        let encoded = encode_stored_config(&stored).expect("stored config JSON");
        let decoded = decode_stored_config(&encoded).expect("typed stored config");
        validate_stored_config(&decoded).expect("mixed transport config");
        assert_eq!(decoded, stored);
        assert_eq!(
            decoded.source_fetch_endpoint.canonical_url(),
            "https://github.com/example/public-app"
        );
        assert_eq!(
            decoded.source_push_endpoint.canonical_url(),
            "git@github.com:example/public-app"
        );
        assert_eq!(
            decoded.execution_fetch_endpoint.canonical_url(),
            "git@github.com:example/private-builds"
        );
        assert_eq!(
            decoded.execution_push_endpoint.canonical_url(),
            "git@github.com:example/private-builds"
        );
    }

    #[test]
    fn signing_blob_encoding_is_canonical_and_exactly_bounded() {
        let maximum_raw = (MAX_ENVIRONMENT_SECRET_BYTES / 4) * 3;
        let maximum = SecretBytes::new(vec![0x5a; maximum_raw]);
        let encoded = CanonicalBase64SigningBlob::from_raw(&maximum, "certificate_p12")
            .expect("exact maximum should encode");
        assert_eq!(encoded.as_secret().len(), MAX_ENVIRONMENT_SECRET_BYTES);

        let oversized = SecretBytes::new(vec![0x5a; maximum_raw + 1]);
        assert_eq!(
            CanonicalBase64SigningBlob::from_raw(&oversized, "certificate_p12")
                .err()
                .expect("one extra raw byte must fail")
                .code(),
            "github_signing_secret_too_large"
        );
        let canonical = CanonicalBase64SigningBlob::try_from_encoded(
            SecretBytes::new(b"AA==".to_vec()),
            "provisioning_profile",
        )
        .expect("canonical padded base64");
        assert_eq!(canonical.as_secret().expose_secret_bytes(), b"AA==");
        for invalid in [
            b"".as_slice(),
            b"raw".as_slice(),
            b"AAE".as_slice(),
            b"AB==".as_slice(),
            b"AA==\n".as_slice(),
        ] {
            assert!(
                CanonicalBase64SigningBlob::try_from_encoded(
                    SecretBytes::new(invalid.to_vec()),
                    "provisioning_profile",
                )
                .is_err(),
                "accepted noncanonical base64"
            );
        }
    }

    #[test]
    fn raw_signing_password_preserves_empty_and_enforces_final_boundary() {
        assert!(RawSigningPassword::new(SecretBytes::new(Vec::new())).is_ok());
        let maximum = RawSigningPassword::new(SecretBytes::new(vec![b'x'; 4 * 1024]))
            .expect("exact password maximum");
        assert_eq!(maximum.as_secret().len(), 4 * 1024);
        assert!(RawSigningPassword::new(SecretBytes::new(vec![b'x'; 4 * 1024 + 1])).is_err());
        for invalid in [b"secret\n".as_slice(), b"secret\0".as_slice(), &[0xff]] {
            assert!(RawSigningPassword::new(SecretBytes::new(invalid.to_vec())).is_err());
        }
    }

    #[test]
    fn provider_config_lock_rejects_a_concurrent_writer() {
        let (_temporary, root, paths, _config) = provider_config_fixture();
        let first = acquire_provider_config_lock(&root, &paths.config_lock).expect("first lock");
        let error = acquire_provider_config_lock(&root, &paths.config_lock)
            .err()
            .expect("concurrent lock must fail");
        assert_eq!(error.code(), "provider_config_busy");
        drop(first);
        acquire_provider_config_lock(&root, &paths.config_lock).expect("released lock");
    }

    #[cfg(windows)]
    #[test]
    fn github_provider_objects_use_private_windows_access_controls() {
        let (_temporary, root, paths, _config) = provider_config_fixture();
        for directory in [
            paths.config.parent().expect("provider parent"),
            paths.cache.as_path(),
            paths.git_isolation.as_path(),
        ] {
            rustferry_core::windows_private_directory::open_private_directory(
                directory.as_std_path(),
            )
            .expect("protected private provider directory");
        }
        rustferry_core::windows_private_directory::open_private_file(paths.config.as_std_path())
            .expect("protected private provider config");

        drop(acquire_provider_config_lock(&root, &paths.config_lock).expect("provider lock"));
        rustferry_core::windows_private_directory::open_private_file(
            paths.config_lock.as_std_path(),
        )
        .expect("protected private provider lock");
    }

    #[cfg(windows)]
    #[test]
    fn github_provider_rejects_permissive_windows_directory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8PathBuf::from_path_buf(temporary.path().to_owned())
            .expect("UTF-8 temp path");
        std::fs::create_dir_all(root.join("target/ferry/github"))
            .expect("ordinary inherited provider directory");
        let paths = GithubPaths::new(&root, &root);

        let error = ensure_provider_directories(&root, &paths)
            .expect_err("permissive provider directory must be rejected");
        assert_eq!(error.code(), "private_permissions_required");
    }

    #[cfg(windows)]
    #[test]
    fn github_provider_rejects_inherited_and_hardlinked_windows_config() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8PathBuf::from_path_buf(temporary.path().to_owned())
            .expect("UTF-8 temp path");
        let paths = GithubPaths::new(&root, &root);
        ensure_provider_directories(&root, &paths).expect("private provider directories");
        std::fs::write(&paths.config, b"{}\n").expect("ordinary inherited config");
        assert_eq!(
            load_config(&root)
                .expect_err("inherited config must be rejected")
                .code(),
            "private_permissions_required"
        );
        std::fs::remove_file(&paths.config).expect("remove inherited config");

        let stored = unsigned_stored_config();
        let bytes = encode_stored_config(&stored).expect("provider bytes");
        write_create_only(&paths.config, &bytes, true).expect("private provider config");
        let linked = paths.config.with_extension("linked");
        std::fs::hard_link(&paths.config, &linked).expect("provider config hard link");
        assert_eq!(
            load_config(&root)
                .expect_err("hard-linked config must be rejected")
                .code(),
            "private_permissions_required"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_replace_keeps_one_private_final_link() {
        let (_temporary, root, paths, original_config) = provider_config_fixture();
        let config_lock =
            acquire_provider_config_lock(&root, &paths.config_lock).expect("config lock");
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = original_config;
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");

        replace_private_config(
            &root,
            &paths.config,
            &installed_bytes,
            identity,
            &original_bytes,
            &installed,
            &config_lock,
        )
        .expect("private Windows config replacement");
        rustferry_core::windows_private_directory::open_private_file(paths.config.as_std_path())
            .expect("single-link private final config");
        let leftovers = std::fs::read_dir(paths.config.parent().expect("provider parent"))
            .expect("provider directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.starts_with(CONFIG_BACKUP_PREFIX)
                    || (name.starts_with(".provider.json.")
                        && std::path::Path::new(name)
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp")))
            })
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "unexpected recovery entries: {leftovers:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_staging_cleanup_failure_is_reported() {
        let (_temporary, root, paths, config) = provider_config_fixture();
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = config;
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");
        let displaced = paths.config.with_extension("displaced");
        let replacement = paths.config.with_extension("replacement");
        let mut staging_paths = None;

        let Err(error) = super::stage_private_config_with(
            &root,
            &paths.config,
            &installed_bytes,
            &identity,
            &original_bytes,
            |staging| {
                let linked = staging.with_extension("linked");
                std::fs::hard_link(staging, &linked).expect("add staging hard link");
                staging_paths = Some((staging.to_owned(), linked));
                write_create_only(&replacement, &original_bytes, true)
                    .expect("private replacement");
                std::fs::rename(&paths.config, &displaced).expect("displace original config");
                std::fs::rename(&replacement, &paths.config).expect("replace config path");
            },
        ) else {
            panic!("staging cleanup with an added link must fail");
        };
        assert_eq!(error.code(), "provider_config_cleanup_uncertain");

        std::fs::remove_file(&paths.config).expect("remove replacement config");
        std::fs::rename(&displaced, &paths.config).expect("restore original config");
        drop(identity);
        let (staging, linked) = staging_paths.expect("captured staging paths");
        std::fs::remove_file(&linked).expect("remove added staging link");
        std::fs::remove_file(&staging).expect("remove retained staging link");
    }

    #[cfg(windows)]
    #[test]
    fn windows_downstream_failure_reports_staging_cleanup_uncertainty() {
        let (_temporary, root, paths, config) = provider_config_fixture();
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = config;
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");
        let config_link = paths.config.with_extension("linked");
        let mut staging_paths = None;

        let error = super::replace_private_config_with(
            &root,
            &paths.config,
            &installed_bytes,
            identity,
            &original_bytes,
            &installed,
            |staging| {
                let linked = staging.with_extension("linked");
                std::fs::hard_link(staging, &linked).expect("add staging hard link");
                staging_paths = Some((staging.to_owned(), linked));
                std::fs::hard_link(&paths.config, &config_link)
                    .expect("make quarantine capture reject config");
            },
            |_| {},
        )
        .expect_err("downstream quarantine failure must surface staging cleanup");
        let ConfigCommitError::NotCommitted(error) = error else {
            panic!("quarantine capture did not mutate the provider config");
        };
        assert_eq!(error.code(), "provider_config_cleanup_uncertain");

        std::fs::remove_file(config_link).expect("remove config hard link");
        let (staging, linked) = staging_paths.expect("captured staging paths");
        std::fs::remove_file(&linked).expect("remove added staging link");
        std::fs::remove_file(&staging).expect("remove retained staging link");
    }

    #[cfg(windows)]
    #[test]
    fn windows_quarantine_capture_reports_directory_cleanup_failure() {
        let (_temporary, _root, paths, _config) = provider_config_fixture();
        let linked = paths.config.with_extension("linked");
        std::fs::hard_link(&paths.config, &linked).expect("hard-link provider config");
        let parent = paths.config.parent().expect("provider parent");
        let mut recovery_root = None;

        let Err(error) =
            super::ConfigQuarantine::capture_with_interlock(parent, &paths.config, |root| {
                std::fs::write(root.join("blocker"), b"block\n")
                    .expect("make backup directory non-empty");
                recovery_root = Some(root.to_owned());
            })
        else {
            panic!("hard-linked config must fail quarantine capture");
        };
        assert_eq!(error.code(), "provider_config_recovery_required");

        let recovery_root = recovery_root.expect("recovery root");
        std::fs::remove_file(recovery_root.join("blocker")).expect("remove blocker");
        std::fs::remove_dir(&recovery_root).expect("remove recovery directory");
        std::fs::remove_file(linked).expect("remove config hard link");
    }

    #[cfg(windows)]
    #[test]
    fn windows_restore_failure_reports_post_rename_locations() {
        let (_temporary, _root, paths, _config) = provider_config_fixture();
        let parent = paths.config.parent().expect("provider parent");
        let quarantine =
            super::ConfigQuarantine::capture(parent, &paths.config).expect("quarantine config");
        let recovery_file = quarantine.path.clone();
        let recovery_root = recovery_file.parent().expect("recovery root").to_owned();

        let failure = quarantine
            .restore_noclobber_with(&paths.config, || {
                Err(std::io::Error::other("injected post-rename failure"))
            })
            .expect_err("post-rename failure");
        assert!(paths.config.exists());
        assert!(!recovery_file.exists());
        assert!(failure.inspection_paths.contains(&paths.config));
        assert!(failure.inspection_paths.contains(&recovery_root));
        assert!(!failure.inspection_paths.contains(&recovery_file));

        std::fs::remove_file(&paths.config).expect("remove restored config");
        std::fs::remove_dir(recovery_root).expect("remove recovery directory");
    }

    #[cfg(windows)]
    #[test]
    fn windows_delete_failure_reports_remaining_directory() {
        let (_temporary, _root, paths, _config) = provider_config_fixture();
        let parent = paths.config.parent().expect("provider parent");
        let quarantine =
            super::ConfigQuarantine::capture(parent, &paths.config).expect("quarantine config");
        let recovery_file = quarantine.path.clone();
        let recovery_root = recovery_file.parent().expect("recovery root").to_owned();

        let failure = quarantine
            .delete_with_interlock(|root| {
                std::fs::write(root.join("blocker"), b"block\n")?;
                Ok(())
            })
            .expect_err("non-empty recovery directory must remain");
        assert!(!paths.config.exists());
        assert!(!recovery_file.exists());
        assert_eq!(failure.inspection_paths, vec![recovery_root.clone()]);

        std::fs::remove_file(recovery_root.join("blocker")).expect("remove blocker");
        std::fs::remove_dir(recovery_root).expect("remove recovery directory");
    }

    #[test]
    fn signing_dry_run_does_not_create_a_provider_config_lock() {
        let (_temporary, root, paths, _config) = provider_config_fixture();
        assert!(!paths.config_lock.exists());
        assert!(
            provider_config_lock_for_signing(&root, &paths.config_lock, false)
                .expect("read-only signing session")
                .is_none()
        );
        assert!(!paths.config_lock.exists());
        drop(
            provider_config_lock_for_signing(&root, &paths.config_lock, true)
                .expect("mutating signing session")
                .expect("mutating session lock"),
        );
        assert!(paths.config_lock.exists());
    }

    #[test]
    fn provider_config_snapshot_detects_content_and_path_replacement() {
        let (_temporary, root, paths, _config) = provider_config_fixture();
        let (identity, original) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        #[cfg(windows)]
        {
            let mut same_length_mutation = original.clone();
            same_length_mutation[0] ^= 1;
            assert!(
                std::fs::write(&paths.config, &same_length_mutation).is_err(),
                "the retained Windows snapshot handle must deny concurrent writes"
            );
            let replacement = paths.config.with_extension("replacement");
            write_create_only(&replacement, &original, true).expect("replacement config");
            let displaced = paths.config.with_extension("displaced");
            std::fs::rename(&paths.config, &displaced).expect("displace original config");
            std::fs::rename(&replacement, &paths.config).expect("replace config path");
            assert_eq!(
                ensure_config_snapshot_unchanged(&root, &paths.config, &identity, &original)
                    .expect_err("path replacement must fail")
                    .code(),
                "provider_config_changed"
            );
            drop(identity);
        }
        #[cfg(not(windows))]
        {
            let mut same_length_mutation = original.clone();
            same_length_mutation[0] ^= 1;
            std::fs::write(&paths.config, &same_length_mutation).expect("same-length mutation");
            assert_eq!(
                ensure_config_snapshot_unchanged(&root, &paths.config, &identity, &original)
                    .expect_err("content mutation must fail")
                    .code(),
                "provider_config_changed"
            );

            std::fs::write(&paths.config, &original).expect("restore original bytes");
            let (identity, original) =
                read_private_config_snapshot(&root, &paths.config).expect("restored snapshot");
            let replacement = paths.config.with_extension("replacement");
            write_create_only(&replacement, &original, true).expect("replacement config");
            let displaced = paths.config.with_extension("displaced");
            std::fs::rename(&paths.config, &displaced).expect("displace original config");
            std::fs::rename(&replacement, &paths.config).expect("replace config path");
            assert_eq!(
                ensure_config_snapshot_unchanged(&root, &paths.config, &identity, &original)
                    .expect_err("identity replacement must fail")
                    .code(),
                "provider_config_changed"
            );
        }
    }

    #[test]
    fn build_config_rejects_an_unresolved_recovery_backup() {
        let (_temporary, root, paths, expected) = provider_config_fixture();
        let recovery = paths
            .config
            .parent()
            .expect("provider parent")
            .join(format!("{}fixture", super::CONFIG_BACKUP_PREFIX));
        std::fs::create_dir(&recovery).expect("recovery directory");

        assert_eq!(load_config(&root).expect("inspectable config"), expected);
        let Err(error) = super::load_config_for_build(&root) else {
            panic!("build must stop for unresolved recovery");
        };
        assert_eq!(error.code(), "provider_config_recovery_required");
    }

    #[test]
    fn config_lock_rechecks_recovery_after_the_preflight_window() {
        let (_temporary, root, paths, _config) = provider_config_fixture();
        let recovery = paths
            .config
            .parent()
            .expect("provider parent")
            .join(format!("{}interleaved", super::CONFIG_BACKUP_PREFIX));

        let Err(error) =
            super::acquire_provider_config_lock_with_interlock(&root, &paths.config_lock, || {
                std::fs::create_dir(&recovery).expect("interleaved recovery directory");
            })
        else {
            panic!("post-lock recovery recheck must fail");
        };

        assert_eq!(error.code(), "provider_config_recovery_required");
    }

    #[test]
    fn post_replace_verification_failure_reports_committed_state() {
        let (_temporary, root, paths, original_config) = provider_config_fixture();
        let config_lock =
            acquire_provider_config_lock(&root, &paths.config_lock).expect("config lock");
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = original_config.clone();
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");
        let mut wrong_expectation = installed.clone();
        wrong_expectation.worker_version = "0.1.2".to_owned();

        let error = replace_private_config(
            &root,
            &paths.config,
            &installed_bytes,
            identity,
            &original_bytes,
            &wrong_expectation,
            &config_lock,
        )
        .expect_err("post-commit mismatch must be typed");
        assert!(
            matches!(error, ConfigCommitError::CommittedNeedsInspection(_)),
            "unexpected commit state: {error:?}"
        );
        assert_eq!(load_config(&root).expect("committed config"), installed);
    }

    #[test]
    fn provider_config_commit_does_not_overwrite_a_late_replacement() {
        let (_temporary, root, paths, original_config) = provider_config_fixture();
        let config_lock =
            acquire_provider_config_lock(&root, &paths.config_lock).expect("config lock");
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = original_config.clone();
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");
        let late = paths.config.with_extension("late");

        let error = super::replace_private_config_with(
            &root,
            &paths.config,
            &installed_bytes,
            identity,
            &original_bytes,
            &installed,
            |_| {
                write_create_only(&late, &original_bytes, true).expect("late replacement");
                std::fs::remove_file(&paths.config).expect("remove original path");
                std::fs::rename(&late, &paths.config).expect("install late replacement");
            },
            |_| {},
        )
        .expect_err("late replacement must abort commit");

        assert!(matches!(error, ConfigCommitError::NotCommitted(_)));
        assert_eq!(
            std::fs::read(&paths.config).expect("preserved late replacement"),
            original_bytes
        );
        assert_eq!(
            load_config(&root).expect("restored config"),
            original_config
        );
        drop(config_lock);
    }

    #[test]
    fn provider_config_commit_preserves_an_occupied_path_and_backup() {
        let (_temporary, root, paths, original_config) = provider_config_fixture();
        let config_lock =
            acquire_provider_config_lock(&root, &paths.config_lock).expect("config lock");
        let (identity, original_bytes) =
            read_private_config_snapshot(&root, &paths.config).expect("original snapshot");
        let mut installed = original_config.clone();
        installed.worker_version = "0.1.1".to_owned();
        let installed_bytes = encode_stored_config(&installed).expect("installed bytes");
        let occupied = b"concurrent provider config";

        let error = super::replace_private_config_with(
            &root,
            &paths.config,
            &installed_bytes,
            identity,
            &original_bytes,
            &installed,
            |_| {},
            |_| {
                std::fs::write(&paths.config, occupied).expect("occupy provider config path");
            },
        )
        .expect_err("occupied path must make commit uncertain");

        assert!(
            matches!(error, ConfigCommitError::CommittedNeedsInspection(_)),
            "unexpected commit state: {error:?}"
        );
        assert_eq!(
            std::fs::read(&paths.config).expect("preserved occupied path"),
            occupied
        );
        let parent = paths.config.parent().expect("provider parent");
        let recovery = std::fs::read_dir(parent)
            .expect("provider directory")
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(super::CONFIG_BACKUP_PREFIX)
            })
            .expect("preserved backup");
        assert_eq!(
            std::fs::read(recovery.path().join("provider.json")).expect("backup bytes"),
            original_bytes
        );
        assert_eq!(
            super::reject_config_recovery_entries(parent)
                .expect_err("recovery entry must block another mutation")
                .code(),
            "provider_config_recovery_required"
        );
        drop(config_lock);
    }

    #[test]
    fn manual_signing_install_writes_password_last_and_commits_config_last() {
        let names = SigningSecretNames::goal3_defaults();
        let required = required_signing_secret_names(&names);
        let (_temporary, session, values, state) = manual_signing_session(
            vec![Ok(BTreeSet::new()), Ok(required)],
            vec![Ok(()), Ok(()), Ok(())],
        );
        let config_root = session.root.clone();
        let preview = session.install(&values).expect("signing install");
        assert!(preview.installed);
        assert_eq!(preview.profiles.len(), 1);
        assert_eq!(
            preview.profiles[0].secret_name,
            names.provisioning_profile().as_str()
        );
        let state = state.borrow();
        assert_eq!(
            state.events,
            vec![
                FakeManualSigningEvent::Policy {
                    phase: "before_upload",
                    source_repository: "example/public-app".to_owned(),
                    execution_repository: "example/private-builds".to_owned(),
                    environment: PROTECTED_ENVIRONMENT.to_owned(),
                    config_signed: false,
                },
                FakeManualSigningEvent::Secret {
                    execution_repository: "example/private-builds".to_owned(),
                    environment: PROTECTED_ENVIRONMENT.to_owned(),
                    name: names.certificate_p12().as_str().to_owned(),
                    value: b"Y2VydA==".to_vec(),
                    config_signed: false,
                },
                FakeManualSigningEvent::Secret {
                    execution_repository: "example/private-builds".to_owned(),
                    environment: PROTECTED_ENVIRONMENT.to_owned(),
                    name: names.provisioning_profile().as_str().to_owned(),
                    value: b"cHJvZmlsZQ==".to_vec(),
                    config_signed: false,
                },
                FakeManualSigningEvent::Secret {
                    execution_repository: "example/private-builds".to_owned(),
                    environment: PROTECTED_ENVIRONMENT.to_owned(),
                    name: names.certificate_password().as_str().to_owned(),
                    value: b"top-secret-canary".to_vec(),
                    config_signed: false,
                },
                FakeManualSigningEvent::Policy {
                    phase: "after_upload",
                    source_repository: "example/public-app".to_owned(),
                    execution_repository: "example/private-builds".to_owned(),
                    environment: PROTECTED_ENVIRONMENT.to_owned(),
                    config_signed: false,
                },
            ]
        );
        assert!(
            load_config(&config_root)
                .expect("installed config")
                .signing
                .is_some()
        );
    }

    #[test]
    fn multi_profile_install_uses_canonical_exact_set_and_password_last() {
        let (_temporary, mut session, mut values, state) =
            manual_signing_session(Vec::new(), vec![Ok(()), Ok(()), Ok(()), Ok(())]);
        let names = add_widget_profile_to_manual_signing_session(&mut session, &mut values);
        session.remote.policy_results = VecDeque::from([
            Ok(BTreeSet::new()),
            Ok(required_signing_secret_names(&names)),
        ]);

        let preview = session.install(&values).expect("multi-profile install");
        assert_eq!(preview.profiles.len(), 2);
        for profile in &preview.profiles {
            assert_eq!(
                profile.secret_name,
                names
                    .profile_for_target(&profile.target)
                    .expect("preview target secret")
                    .as_str()
            );
        }
        let state = state.borrow();
        let secret_names = state
            .events
            .iter()
            .filter_map(|event| match event {
                FakeManualSigningEvent::Secret { name, .. } => Some(name.as_str()),
                FakeManualSigningEvent::Policy { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            secret_names,
            vec![
                names.certificate_p12().as_str(),
                names
                    .profile_for_target("App")
                    .expect("app secret")
                    .as_str(),
                names
                    .profile_for_target("FerryWidgetExtension")
                    .expect("widget secret")
                    .as_str(),
                names.certificate_password().as_str(),
            ]
        );
    }

    #[test]
    fn read_only_signing_session_cannot_upload_secrets() {
        let (_temporary, mut session, values, state) =
            manual_signing_session(vec![Ok(BTreeSet::new())], vec![Ok(()), Ok(()), Ok(())]);
        let config_root = session.root.clone();
        session.config_lock = None;
        let error = session
            .install(&values)
            .expect_err("read-only session must fail before remote mutation");
        assert_eq!(error.code(), "provider_config_lock_required");
        assert!(state.borrow().events.is_empty());
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );
    }

    #[test]
    fn manual_signing_install_treats_each_failed_write_as_possibly_uploaded() {
        let logical_roles = [
            "certificate_p12",
            "provisioning_profile:App",
            "provisioning_profile:FerryWidgetExtension",
            "certificate_password",
        ];
        for (failure_index, logical_role) in logical_roles.iter().enumerate() {
            let mut results = vec![Ok(()); failure_index];
            results.push(Err(TransportError::Execution(GhExecutionError::TimedOut)));
            let (_temporary, mut session, mut values, state) =
                manual_signing_session(vec![Ok(BTreeSet::new())], results);
            let names = add_widget_profile_to_manual_signing_session(&mut session, &mut values);
            let ordered_secret_names = [
                names.certificate_p12().as_str(),
                names
                    .profile_for_target("App")
                    .expect("app secret")
                    .as_str(),
                names
                    .profile_for_target("FerryWidgetExtension")
                    .expect("widget secret")
                    .as_str(),
                names.certificate_password().as_str(),
            ];
            let config_root = session.root.clone();
            let error = session
                .install(&values)
                .expect_err("indeterminate secret write must fail");
            assert_eq!(error.code(), "github_signing_secret_upload_indeterminate");
            let expected_detail = format!("possibly_uploaded_role={logical_role}");
            let CliError::Remote { details, .. } = error else {
                panic!("expected structured remote error");
            };
            assert!(details.contains(&expected_detail));
            assert!(details.contains(&format!(
                "possibly_uploaded_secret={}",
                ordered_secret_names[failure_index]
            )));
            for uploaded_index in 0..failure_index {
                assert!(
                    details.contains(&format!("uploaded_role={}", logical_roles[uploaded_index]))
                );
                assert!(details.contains(&format!(
                    "uploaded_secret={}",
                    ordered_secret_names[uploaded_index]
                )));
            }
            assert_no_fake_signing_values(&details);
            assert_eq!(recorded_secret_count(&state.borrow()), failure_index + 1);
            assert!(
                load_config(&config_root)
                    .expect("unsigned config")
                    .signing
                    .is_none()
            );
        }
    }

    #[test]
    fn manual_signing_install_binds_project_state_across_confirmation_and_preflight() {
        let (_temporary, session, values, state) = manual_signing_session(Vec::new(), Vec::new());
        let mut changed = session.expected_project_state.ferry_config.clone();
        changed.app.name.push_str(" changed");
        std::fs::write(
            session.root.join("ferry.toml"),
            changed.to_pretty_toml().expect("changed project config"),
        )
        .expect("mutate project during confirmation");
        let error = session
            .install(&values)
            .expect_err("confirmation-time project drift must fail");
        assert_eq!(error.code(), "signing_project_state_changed");
        assert!(state.borrow().events.is_empty());

        let (_temporary, mut session, values, state) =
            manual_signing_session(vec![Ok(BTreeSet::new())], Vec::new());
        mutate_project_on_policy(&mut session, "before_upload");
        let error = session
            .install(&values)
            .expect_err("pre-upload project drift must fail");
        assert_eq!(error.code(), "signing_project_state_changed");
        assert_eq!(recorded_secret_count(&state.borrow()), 0);
    }

    #[test]
    fn project_drift_after_upload_reports_exact_cleanup_secret_names() {
        let names = SigningSecretNames::goal3_defaults();
        let required = required_signing_secret_names(&names);
        let (_temporary, mut session, values, state) = manual_signing_session(
            vec![Ok(BTreeSet::new()), Ok(required)],
            vec![Ok(()), Ok(()), Ok(())],
        );
        let config_root = session.root.clone();
        mutate_project_on_policy(&mut session, "after_upload");
        let error = session
            .install(&values)
            .expect_err("post-upload project drift must fail safely");
        assert_eq!(error.code(), "github_signing_post_upload_failed");
        let CliError::Remote { details, .. } = error else {
            panic!("expected structured remote error");
        };
        assert!(details.contains(&"cause_code=signing_project_state_changed".to_owned()));
        for name in names.all_names() {
            assert!(details.contains(&format!("uploaded_secret={}", name.as_str())));
        }
        assert_no_fake_signing_values(&details);
        assert_eq!(recorded_secret_count(&state.borrow()), 3);
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );
    }

    #[test]
    fn uncertain_config_commit_reports_roles_and_exact_secret_names_only() {
        let targets = vec![
            SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("app bundle ID"),
                kind: SigningTargetKind::Application,
            },
            SigningTarget {
                name: "FerryWidgetExtension".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app.widget")
                    .expect("widget bundle ID"),
                kind: SigningTargetKind::Extension,
            },
        ];
        let names = SigningSecretNames::for_targets(&targets).expect("secret names");
        let uploads = vec![
            SigningSecretUpload {
                role: "certificate_p12".to_owned(),
                secret_name: names.certificate_p12().as_str().to_owned(),
            },
            SigningSecretUpload {
                role: "provisioning_profile:App".to_owned(),
                secret_name: names
                    .profile_for_target("App")
                    .expect("app profile")
                    .as_str()
                    .to_owned(),
            },
            SigningSecretUpload {
                role: "provisioning_profile:FerryWidgetExtension".to_owned(),
                secret_name: names
                    .profile_for_target("FerryWidgetExtension")
                    .expect("widget profile")
                    .as_str()
                    .to_owned(),
            },
            SigningSecretUpload {
                role: "certificate_password".to_owned(),
                secret_name: names.certificate_password().as_str().to_owned(),
            },
        ];
        let cause = remote_error(
            "provider_config_commit_uncertain",
            "provider config commit state is uncertain",
            "Inspect the provider config.",
        );
        let error = signing_config_commit_uncertain(&cause, &uploads);
        assert_eq!(error.code(), "github_signing_config_commit_uncertain");
        let CliError::Remote { details, help, .. } = error else {
            panic!("expected structured remote error");
        };
        for upload in uploads {
            assert!(details.contains(&format!("uploaded_role={}", upload.role)));
            assert!(details.contains(&format!("uploaded_secret={}", upload.secret_name)));
        }
        assert!(help.contains("secret names"));
        assert_no_fake_signing_values(&details);
    }

    #[test]
    fn manual_signing_install_fails_closed_on_policy_drift() {
        let (_temporary, session, values, state) = manual_signing_session(
            vec![Ok(BTreeSet::from(["UNEXPECTED".to_owned()]))],
            Vec::new(),
        );
        let config_root = session.root.clone();
        let error = session
            .install(&values)
            .expect_err("pre-upload drift must fail");
        assert_eq!(error.code(), "signing_environment_changed");
        assert_eq!(recorded_secret_count(&state.borrow()), 0);
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );

        let names = SigningSecretNames::goal3_defaults();
        let mut post_upload = required_signing_secret_names(&names);
        post_upload.insert("UNEXPECTED".to_owned());
        let (_temporary, session, values, state) = manual_signing_session(
            vec![Ok(BTreeSet::new()), Ok(post_upload)],
            vec![Ok(()), Ok(()), Ok(())],
        );
        let config_root = session.root.clone();
        let error = session
            .install(&values)
            .expect_err("post-upload drift must fail");
        assert_eq!(error.code(), "github_signing_secret_postcheck_failed");
        let CliError::Remote { details, .. } = error else {
            panic!("expected structured remote error");
        };
        for name in names.all_names() {
            assert!(details.contains(&format!("uploaded_secret={}", name.as_str())));
        }
        assert_no_fake_signing_values(&details);
        assert_eq!(recorded_secret_count(&state.borrow()), 3);
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );
    }

    #[test]
    fn manual_signing_install_handles_policy_check_errors_before_and_after_upload() {
        let policy_error = || {
            remote_error(
                "signing_environment_not_ready",
                "the protected signing policy changed",
                "Restore the exact reviewed policy and retry.",
            )
        };
        let (_temporary, session, values, state) =
            manual_signing_session(vec![Err(policy_error())], Vec::new());
        let config_root = session.root.clone();
        let error = session
            .install(&values)
            .expect_err("pre-upload policy error must fail");
        assert_eq!(error.code(), "signing_environment_not_ready");
        assert_eq!(recorded_secret_count(&state.borrow()), 0);
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );

        let names = SigningSecretNames::goal3_defaults();
        let (_temporary, session, values, state) = manual_signing_session(
            vec![Ok(BTreeSet::new()), Err(policy_error())],
            vec![Ok(()), Ok(()), Ok(())],
        );
        let config_root = session.root.clone();
        let error = session
            .install(&values)
            .expect_err("post-upload policy error must fail");
        assert_eq!(error.code(), "github_signing_post_upload_failed");
        let CliError::Remote { details, .. } = error else {
            panic!("expected structured remote error");
        };
        for role in [
            "certificate_p12",
            "provisioning_profile:App",
            "certificate_password",
        ] {
            assert!(details.contains(&format!("uploaded_role={role}")));
        }
        for name in names.all_names() {
            assert!(details.contains(&format!("uploaded_secret={}", name.as_str())));
        }
        assert_no_fake_signing_values(&details);
        let state = state.borrow();
        assert_eq!(recorded_secret_count(&state), 3);
        assert!(matches!(
            state.events.last(),
            Some(FakeManualSigningEvent::Policy {
                phase: "after_upload",
                config_signed: false,
                ..
            })
        ));
        assert!(
            load_config(&config_root)
                .expect("unsigned config")
                .signing
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_entrypoint_preserves_multicall_symlink_basename() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let canonical_root = temporary
            .path()
            .canonicalize()
            .expect("canonical temp path");
        let root = camino::Utf8Path::from_path(&canonical_root).expect("UTF-8 temp path");
        let multicall = root.join("rustup");
        std::fs::write(&multicall, b"multicall").expect("multicall fixture");
        let cargo = root.join("cargo");
        symlink(&multicall, &cargo).expect("cargo proxy symlink");

        let resolved = executable_entrypoint(&cargo, "cargo").expect("cargo entrypoint");
        assert_eq!(resolved, root.join("cargo"));
        assert_eq!(resolved.file_name(), Some("cargo"));
        assert_ne!(
            resolved,
            multicall.canonicalize_utf8().expect("multicall path")
        );
    }

    #[test]
    fn git_index_executable_parser_is_nul_safe_and_rejects_unmerged_entries() {
        let parsed = parse_git_index_executable_paths(
            b"100755 0123456789012345678901234567890123456789 0\tscripts/build tool\0\
              100644 0123456789012345678901234567890123456789 0\tsrc/main.rs\0",
        )
        .expect("Git executable modes");
        assert_eq!(
            parsed,
            BTreeSet::from([camino::Utf8PathBuf::from("scripts/build tool")])
        );

        let error = parse_git_index_executable_paths(
            b"100755 0123456789012345678901234567890123456789 2\tscripts/conflicted\0",
        )
        .expect_err("unmerged index entry must fail");
        assert_eq!(error.code(), "invalid_git_executable_metadata");
    }

    #[test]
    fn unsigned_plan_contains_the_complete_generated_product_graph() {
        let mut config = rustferry_core::FerryConfig::starter("Weather", "com.example.weather");
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
        let plan = unsigned_signing_plan(&config, "weather").expect("unsigned plan");
        assert_eq!(plan.mode, SigningMode::UnsignedCompileOnly);
        assert!(
            plan.targets
                .iter()
                .any(|target| target.kind == SigningTargetKind::Application)
        );
        assert!(plan.targets.iter().any(|target| {
            target.kind == SigningTargetKind::Extension
                && target.bundle_identifier.as_str() == "com.example.weather.widget"
        }));
        assert!(plan.targets.iter().any(|target| {
            target.kind == SigningTargetKind::Framework
                && target.bundle_identifier.as_str() == "org.rustferry.runtime-bridge"
        }));
        plan.validate().expect("valid unsigned plan");
    }

    #[test]
    fn exact_revision_manifest_digest_matches_protocol_planner() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("fixture manifest");
        let plan = plan_source_bundle(&SourceBundleRequest::new(root, root)).expect("source plan");
        let manifest = plan.manifest();
        assert_eq!(
            source_manifest_digest(
                &manifest.project_path,
                &manifest.entries,
                manifest.total_size
            ),
            manifest.sha256
        );
    }

    #[test]
    fn signed_doctor_requires_the_exact_reviewer_proof_code() {
        let report = |code: &str, status| ProviderDoctorReport {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            provider: "github".to_owned(),
            ready: true,
            checks: vec![ProviderCheck {
                code: code.to_owned(),
                status,
                message: "safe".to_owned(),
                help: None,
            }],
            capabilities: ProviderCapabilities::default(),
        };
        assert!(
            ensure_doctor_ready(
                &report("github.signing_environment", ProviderCheckStatus::Ready),
                true
            )
            .is_err()
        );
        assert!(
            ensure_doctor_ready(
                &report(
                    "github.signing_environment.reviewers",
                    ProviderCheckStatus::Warning
                ),
                true
            )
            .is_err()
        );
        ensure_doctor_ready(
            &report(
                "github.signing_environment.reviewers",
                ProviderCheckStatus::Ready,
            ),
            true,
        )
        .expect("exact reviewer proof");
    }

    #[test]
    fn ide_signing_readiness_retains_provider_evidence_when_assets_are_missing() {
        let readiness = map_ide_signing_readiness(Ok(signing_readiness_from_report(
            missing_asset_local_checks(),
            signing_readiness_report(),
        )))
        .expect("sanitized IDE readiness result");
        assert!(!readiness.ready);
        assert!(readiness.checks.iter().any(|check| {
            check.code == "github_actions_ios_signing.configured"
                && check.required
                && !check.ready
                && check.reason_code == Some("signing_not_configured")
        }));
        assert!(readiness.checks.iter().any(|check| {
            check.code == "github.authentication" && check.ready && check.reason_code.is_none()
        }));
    }

    #[test]
    fn signing_doctor_keeps_provider_evidence_when_assets_are_unconfigured() {
        let readiness =
            signing_readiness_from_report(missing_asset_local_checks(), signing_readiness_report());

        assert!(!readiness.ready);
        assert!(readiness.checks.iter().any(|check| {
            check.code == "github_actions_ios_signing.configured"
                && !check.ready
                && check.reason_code == Some("signing_not_configured")
        }));
        assert!(readiness.checks.iter().any(|check| {
            check.code == "github.authentication" && check.ready && check.reason_code.is_none()
        }));
        assert!(
            readiness
                .checks
                .iter()
                .any(|check| { check.code == "github.signing_repository_distinct" && check.ready })
        );
    }

    #[test]
    fn missing_asset_readiness_derives_static_target_namespace_and_phase_checks() {
        let checks = missing_asset_local_checks();
        for code in [
            "github.signing_config.public_metadata_only",
            "github.signing_target_graph",
            "github.temporary_ref_namespace",
            "github.workflow.phase_a_secret_isolation",
            "github.workflow.phase_b_no_source_execution",
        ] {
            assert!(
                checks
                    .iter()
                    .any(|check| check.code == code && check.required && check.ready),
                "missing derived ready check {code}"
            );
        }
        for code in [
            "github_actions_ios_signing.configured",
            "github.signing_team",
            "github.signing_profile_map",
        ] {
            assert!(
                checks
                    .iter()
                    .any(|check| check.code == code && check.required && !check.ready),
                "missing derived absent-assets check {code}"
            );
        }
    }

    #[test]
    fn signing_readiness_requires_every_required_local_or_provider_check() {
        let mut local_checks = missing_asset_local_checks();
        for check in &mut local_checks {
            check.ready = true;
            check.reason_code = None;
        }
        let ready = signing_readiness_from_report(local_checks.clone(), signing_readiness_report());
        assert!(ready.ready);

        local_checks
            .iter_mut()
            .find(|check| check.code == "github.signing_team")
            .expect("required Team check")
            .ready = false;
        let not_ready = signing_readiness_from_report(local_checks, signing_readiness_report());
        assert!(!not_ready.ready);
    }

    #[test]
    fn workflow_phase_checks_reject_compile_secrets_and_signing_source_execution() {
        let config = unsigned_stored_config();
        let workflow = generate_workflow(&workflow_from_stored(&config).expect("workflow config"));
        assert_eq!(signing_workflow_phase_policy(workflow.yaml()), (true, true));

        let compile_secret = workflow.yaml().replacen(
            "  compile:\n",
            "  compile:\n    env:\n      LEAK: '${{ secrets.BAD }}'\n",
            1,
        );
        assert_eq!(
            signing_workflow_phase_policy(&compile_secret),
            (false, true)
        );
        let compile_bracket_secret = workflow.yaml().replacen(
            "  compile:\n",
            "  compile:\n    env:\n      LEAK: '${{ secrets[\"BAD\"] }}'\n",
            1,
        );
        assert_eq!(
            signing_workflow_phase_policy(&compile_bracket_secret),
            (false, true)
        );
        let compile_signing_name = workflow.yaml().replacen(
            "  compile:\n",
            "  compile:\n    env:\n      RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12: forbidden\n",
            1,
        );
        assert_eq!(
            signing_workflow_phase_policy(&compile_signing_name),
            (false, true)
        );
        let signing_checkout = workflow.yaml().replacen(
            "\n  sign:\n",
            "\n  sign:\n    steps:\n      - uses: actions/checkout@forbidden\n",
            1,
        );
        assert_eq!(
            signing_workflow_phase_policy(&signing_checkout),
            (true, false)
        );
    }

    fn missing_asset_local_checks() -> Vec<super::IdeSigningReadinessCheck> {
        let (_temporary, root, _paths, mut config) = provider_config_fixture();
        let ferry_config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))
            .expect("fixture Ferry config");
        let cargo_targets =
            super::super::platform_build::read_cargo_targets(&root).expect("fixture Cargo target");
        config.signing_targets = unsigned_signing_plan(&ferry_config, cargo_targets.binary())
            .expect("fixture target graph")
            .targets;
        local_signing_readiness_checks(&root, &config).expect("local readiness checks")
    }

    fn signing_readiness_report() -> ProviderDoctorReport {
        ProviderDoctorReport {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            provider: "github".to_owned(),
            ready: true,
            checks: vec![
                ProviderCheck {
                    code: "github.authentication".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "safe".to_owned(),
                    help: None,
                },
                ProviderCheck {
                    code: "github.signing_repository_distinct".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "safe".to_owned(),
                    help: None,
                },
                ProviderCheck {
                    code: "github.signing_environment.reviewers".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "safe".to_owned(),
                    help: None,
                },
            ],
            capabilities: ProviderCapabilities::default(),
        }
    }

    #[test]
    fn ide_readiness_check_code_rejects_endpoint_or_freeform_text() {
        assert_eq!(
            safe_ide_readiness_code("github.signing_environment.reviewers"),
            "github.signing_environment.reviewers"
        );
        for unsafe_code in [
            "https://github.com/example/private",
            "github check with spaces",
            "GITHUB.SECRET",
            "",
        ] {
            assert_eq!(
                safe_ide_readiness_code(unsafe_code),
                "github.readiness.unknown"
            );
        }
    }

    #[test]
    fn signed_default_downloads_are_exact_and_product_named() {
        let root = camino::Utf8Path::new("/project");
        let requested = select_requested_artifacts(SigningMode::ManualDevelopment, None, false)
            .expect("default artifact selection");
        let downloads = expected_artifact_downloads(
            root,
            "Weather",
            false,
            SigningMode::ManualDevelopment,
            &requested,
        )
        .expect("download plan");
        assert_eq!(
            downloads
                .iter()
                .map(|download| download.kind)
                .collect::<Vec<_>>(),
            [
                ArtifactKind::Ipa,
                ArtifactKind::Manifest,
                ArtifactKind::SigningReport,
                ArtifactKind::ValidationReport,
                ArtifactKind::SanitizedLog,
            ]
        );
        assert!(downloads[0].path.ends_with("Weather-development.ipa"));
    }

    #[test]
    fn signed_artifact_selection_keeps_ipa_and_adds_only_requested_outputs() {
        let cases = [
            (BuildArtifactSelection::Ipa, Vec::new()),
            (
                BuildArtifactSelection::App,
                vec![IosArtifactType::AppBundle],
            ),
            (
                BuildArtifactSelection::Archive,
                vec![IosArtifactType::Xcarchive],
            ),
            (
                BuildArtifactSelection::All,
                vec![IosArtifactType::AppBundle, IosArtifactType::Xcarchive],
            ),
        ];
        for (selection, optional) in cases {
            let requested =
                select_requested_artifacts(SigningMode::ManualDevelopment, Some(selection), false)
                    .expect("signed artifact selection");
            assert!(requested.contains(&IosArtifactType::Ipa));
            assert!(requested.contains(&IosArtifactType::SigningReport));
            assert_eq!(
                requested.len(),
                optional.len() + 2,
                "selection={selection:?}"
            );
            for artifact in optional {
                assert!(requested.contains(&artifact), "selection={selection:?}");
            }
        }

        let with_dsym = select_requested_artifacts(
            SigningMode::ManualDevelopment,
            Some(BuildArtifactSelection::Ipa),
            true,
        )
        .expect("dSYM selection");
        assert!(with_dsym.contains(&IosArtifactType::Dsym));
        assert!(with_dsym.contains(&IosArtifactType::Ipa));
    }

    #[test]
    fn unsigned_artifact_selection_accepts_only_the_archive() {
        for selection in [None, Some(BuildArtifactSelection::Archive)] {
            assert_eq!(
                select_requested_artifacts(SigningMode::UnsignedCompileOnly, selection, false)
                    .expect("unsigned archive selection"),
                BTreeSet::from([IosArtifactType::Xcarchive])
            );
        }
        for selection in [
            BuildArtifactSelection::Ipa,
            BuildArtifactSelection::App,
            BuildArtifactSelection::All,
        ] {
            assert!(
                select_requested_artifacts(
                    SigningMode::UnsignedCompileOnly,
                    Some(selection),
                    false,
                )
                .is_err(),
                "selection={selection:?}"
            );
        }
        assert!(select_requested_artifacts(SigningMode::UnsignedCompileOnly, None, true).is_err());
    }

    #[test]
    fn optional_signed_downloads_use_portable_zip_destinations() {
        let root = camino::Utf8Path::new("/project");
        let requested = select_requested_artifacts(
            SigningMode::ManualDevelopment,
            Some(BuildArtifactSelection::All),
            true,
        )
        .expect("all signed artifacts");
        let downloads = expected_artifact_downloads(
            root,
            "Weather",
            true,
            SigningMode::ManualDevelopment,
            &requested,
        )
        .expect("download plan");
        let optional = downloads
            .iter()
            .filter(|download| {
                matches!(
                    download.kind,
                    ArtifactKind::App | ArtifactKind::Xcarchive | ArtifactKind::Dsym
                )
            })
            .map(|download| (download.kind, download.path.file_name().unwrap_or_default()))
            .collect::<Vec<_>>();
        assert_eq!(
            optional,
            [
                (ArtifactKind::App, "Weather.app.zip"),
                (ArtifactKind::Xcarchive, "Weather.xcarchive.zip"),
                (ArtifactKind::Dsym, "Weather.dSYM.zip"),
            ]
        );
        assert_eq!(
            downloads
                .iter()
                .map(|download| download.kind)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ArtifactKind::Ipa,
                ArtifactKind::App,
                ArtifactKind::Xcarchive,
                ArtifactKind::Dsym,
                ArtifactKind::Manifest,
                ArtifactKind::SigningReport,
                ArtifactKind::ValidationReport,
                ArtifactKind::SanitizedLog,
            ])
        );
    }

    #[test]
    fn handshake_and_manifest_require_every_selected_artifact_type() {
        let requested = select_requested_artifacts(
            SigningMode::ManualDevelopment,
            Some(BuildArtifactSelection::All),
            true,
        )
        .expect("all signed artifacts");
        let features = required_build_features_for_source(
            SourceMode::Git,
            SigningMode::ManualDevelopment,
            &requested,
        );
        let manifest_kinds = requested
            .iter()
            .copied()
            .map(IosArtifactType::artifact_kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            manifest_kinds,
            BTreeSet::from([
                ArtifactKind::Ipa,
                ArtifactKind::App,
                ArtifactKind::Xcarchive,
                ArtifactKind::Dsym,
                ArtifactKind::SigningReport,
            ])
        );
        for artifact in requested {
            assert!(features.contains(&ProviderFeature::ArtifactType(artifact)));
        }
    }

    #[test]
    fn every_download_accepts_only_the_client_verified_manifest_state() {
        let listed = ArtifactManifest::new("operation", "job");
        let downloaded = downloaded_manifest(&listed);
        assert_ne!(downloaded, listed);
        assert!(
            downloaded
                .validation_levels
                .contains(&rustferry_remote::ValidationLevel::DownloadedToClient)
        );
        let requested = select_requested_artifacts(SigningMode::ManualDevelopment, None, false)
            .expect("default artifact selection");
        for _ in expected_artifact_downloads(
            camino::Utf8Path::new("/project"),
            "Weather",
            false,
            SigningMode::ManualDevelopment,
            &requested,
        )
        .expect("download plan")
        {
            assert_eq!(downloaded_manifest(&listed), downloaded);
        }
    }

    #[test]
    fn artifact_listing_retries_retryable_and_not_yet_indexed_results() {
        let reporter = Reporter::new(false, true, false);
        let expected = ArtifactManifest::new("operation", "job");
        let mut calls = 0;
        let listed = retry_artifact_listing(
            || Ok(()),
            || {
                calls += 1;
                ImmediateProviderResult::Ready(match calls {
                    1 => Err(RemoteBuildError::ProviderFailure {
                        provider: "github".to_owned(),
                        code: "artifacts_pending".to_owned(),
                        message: "artifact indexing is pending".to_owned(),
                        retryable: true,
                    }),
                    2 => Ok(Vec::new()),
                    _ => Ok(vec![expected.clone()]),
                })
            },
            Instant::now() + Duration::from_secs(1),
            &reporter,
            6,
            Duration::ZERO,
        )
        .expect("artifact listing eventually succeeds");
        assert_eq!(calls, 3);
        assert_eq!(listed, [expected]);
    }

    #[test]
    fn completed_default_downloads_make_retries_fail_without_clobbering() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let requested = select_requested_artifacts(SigningMode::ManualDevelopment, None, false)
            .expect("default artifact selection");
        let downloads = expected_artifact_downloads(
            root,
            "Weather",
            false,
            SigningMode::ManualDevelopment,
            &requested,
        )
        .expect("download plan");
        for download in &downloads {
            prepare_artifact_destination(root, &download.path).expect("new destination");
            std::fs::write(&download.path, [download.kind as u8]).expect("downloaded bytes");
        }
        for download in &downloads {
            assert!(prepare_artifact_destination(root, &download.path).is_err());
            assert_eq!(
                std::fs::read(&download.path)
                    .expect("preserved bytes")
                    .len(),
                1
            );
        }
    }

    #[test]
    fn partial_download_failure_removes_only_files_created_by_the_attempt() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let existing = root.join("existing.ipa");
        let primary = root.join("new.ipa");
        let supporting = root.join("new-manifest.json");
        std::fs::write(&existing, b"preserve").expect("existing artifact");
        {
            let mut rollback = ArtifactDownloadRollback::default();
            std::fs::write(&primary, b"primary").expect("primary download");
            rollback.record(&primary).expect("record primary download");
            std::fs::write(&supporting, b"supporting").expect("supporting download");
            rollback
                .record(&supporting)
                .expect("record supporting download");
        }
        assert_eq!(
            std::fs::read(&existing).expect("preserved existing artifact"),
            b"preserve"
        );
        assert!(!primary.exists());
        assert!(!supporting.exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn hard_link_rollback_binds_the_open_source_file_before_publication_cleanup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let source = root.join("staged-events.jsonl");
        let published = root.join("events.jsonl");
        std::fs::write(&source, b"event\n").expect("staged event log");
        let source_file = std::fs::File::open(&source).expect("open staged event log");
        std::fs::hard_link(&source, &published).expect("publish event log");
        let mut rollback = ArtifactDownloadRollback::default();
        rollback
            .record_hard_link_from_file(&source_file, &published)
            .expect("bind publication to open file");
        rollback.abort().expect("explicit rollback");
        rollback.abort().expect("idempotent rollback");
        assert_eq!(
            std::fs::read(&source).expect("preserved staged event log"),
            b"event\n"
        );
        assert!(!published.exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn partial_download_rollback_preserves_a_replaced_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let primary = root.join("new.ipa");
        let replacement = root.join("replacement.ipa");
        let supporting = root.join("new-manifest.json");
        {
            let mut rollback = ArtifactDownloadRollback::default();
            std::fs::write(&primary, b"downloaded primary").expect("primary download");
            rollback.record(&primary).expect("record primary download");

            std::fs::write(&replacement, b"user replacement").expect("replacement bytes");
            std::fs::remove_file(&primary).expect("unlink downloaded primary");
            std::fs::rename(&replacement, &primary).expect("install replacement");

            std::fs::write(&supporting, b"supporting").expect("supporting download");
            rollback
                .record(&supporting)
                .expect("record supporting download");
        }
        assert_eq!(
            std::fs::read(&primary).expect("preserved replacement"),
            b"user replacement"
        );
        assert!(!supporting.exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn partial_download_rollback_never_unlinks_a_new_path_occupant() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let primary = root.join("new.ipa");
        std::fs::write(&primary, b"downloaded primary").expect("primary download");
        let artifact = super::CreatedArtifact {
            identity: super::ArtifactFileIdentity::capture(&primary)
                .expect("record primary identity"),
            path: primary.clone(),
        };

        super::rollback_created_artifact_with(artifact, |_| {
            std::fs::write(&primary, b"concurrent replacement")
                .expect("install concurrent replacement");
        })
        .expect("owned artifact removed while replacement preserved");

        assert_eq!(
            std::fs::read(&primary).expect("preserved concurrent replacement"),
            b"concurrent replacement"
        );
    }

    #[test]
    #[cfg(windows)]
    fn partial_download_rollback_removes_only_the_retained_windows_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let primary = root.join("new.ipa");
        std::fs::write(&primary, b"downloaded primary").expect("primary download");
        let mut rollback = ArtifactDownloadRollback::default();
        rollback.record(&primary).expect("retained removal handle");

        assert!(std::fs::write(&primary, b"replacement").is_err());
        assert!(std::fs::remove_file(&primary).is_err());
        rollback.abort().expect("exact retained-handle rollback");
        assert!(!primary.exists());
    }

    #[test]
    fn create_only_setup_is_idempotent_and_refuses_different_bytes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        #[cfg(windows)]
        let root = {
            let private = root.join("private");
            rustferry_core::windows_private_directory::create_private_directory(
                private.as_std_path(),
            )
            .expect("private test directory");
            private
        };
        let path = root.join("provider.json");
        write_create_only(&path, b"same", true).expect("first create");
        assert_eq!(
            preflight_file(&path, b"same", true).expect("same file"),
            ExistingFile::Identical
        );
        assert!(preflight_file(&path, b"different", true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_only_setup_rejects_a_symlink_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let outside = root.join("outside");
        std::fs::write(&outside, "preserve").expect("outside file");
        let target = root.join("provider.json");
        symlink(&outside, &target).expect("symlink target");
        assert!(preflight_file(&target, b"replacement", true).is_err());
        assert_eq!(
            std::fs::read_to_string(outside).expect("preserved outside file"),
            "preserve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_destination_rejects_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
        let destination = root.join("target/ferry/ios/device/debug/Weather-development.ipa");
        std::fs::create_dir_all(destination.parent().expect("artifact parent"))
            .expect("artifact parent");
        symlink(root.join("missing"), &destination).expect("dangling symlink");
        assert!(prepare_artifact_destination(root, &destination).is_err());
    }

    #[test]
    fn provider_paths_stay_project_local() {
        let repository = camino::Utf8Path::new("/repository");
        let project = repository.join("apps/weather");
        let paths = GithubPaths::new(&project, repository);
        assert_eq!(
            paths.config,
            project.join("target/ferry/github/provider.json")
        );
        assert_eq!(
            paths.workflow,
            repository.join(".github/workflows/rustferry-goal3-iphone.yml")
        );
    }

    #[test]
    fn provider_metadata_ignore_preserves_portable_pathspec() {
        let path = camino::Utf8Path::new("examples/counter/target/ferry/github/provider.json");

        assert_eq!(
            super::repository_relative_git_pathspec(path).expect("portable Git pathspec"),
            "examples/counter/target/ferry/github/provider.json"
        );
    }

    #[cfg(windows)]
    #[test]
    fn provider_metadata_ignore_normalizes_windows_native_pathspec() {
        let path = camino::Utf8PathBuf::from("examples")
            .join("counter")
            .join("target")
            .join("ferry")
            .join("github")
            .join("provider.json");
        assert!(path.as_str().contains('\\'));

        assert_eq!(
            super::repository_relative_git_pathspec(&path).expect("normalized Git pathspec"),
            "examples/counter/target/ferry/github/provider.json"
        );
    }

    #[test]
    fn provider_metadata_ignore_rejects_unsafe_paths() {
        #[cfg(windows)]
        let absolute = camino::Utf8Path::new(r"C:\repository\target\provider.json");
        #[cfg(not(windows))]
        let absolute = camino::Utf8Path::new("/repository/target/provider.json");
        assert!(super::repository_relative_git_pathspec(absolute).is_err());

        for invalid in [
            "",
            ".",
            "../provider.json",
            "target/../provider.json",
            "-target/provider.json",
            "target//provider.json",
            "target/provider.json/",
            "target/\0/provider.json",
            "target/\r/provider.json",
            "target/\n/provider.json",
            "target/\u{1f}/provider.json",
        ] {
            assert!(
                super::repository_relative_git_pathspec(camino::Utf8Path::new(invalid)).is_err(),
                "accepted unsafe path"
            );
        }

        let overlong = camino::Utf8PathBuf::from("a".repeat(4_097));
        assert!(super::repository_relative_git_pathspec(&overlong).is_err());
    }
}
