use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use camino::{Utf8Path, Utf8PathBuf};
use rustferry_github::provider::{
    GitProcessRunner, GitTemporaryRefPublisher, GithubBuildProvider, GithubMutationAuthorization,
    GithubPollingPolicy, GithubProviderConfig, SystemProviderClock, WorkflowFingerprint,
};
use rustferry_github::transport::{
    EnvironmentSecretWriteRequest, GhAuthentication, GhProcessRunner, GithubTransport,
    MAX_ENVIRONMENT_SECRET_BYTES, Repository, TokenEnvironmentVariable, TransportError,
    TransportLimits,
};
use rustferry_github::workflow::PublicSourceRepository;
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
    SourceMode, UnsignedNestedBundleKind, ValidationLevel, create_source_bundle_archive,
    plan_source_bundle, validate_source_manifest, verify_and_extract_source_bundle,
    write_source_bundle_descriptor_file,
};
use same_file::Handle as FileIdentityHandle;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cli::{
    BuildArtifactSelection, RemoteArgs, RemoteBundleArgs, RemoteBundleCommand,
    RemoteBundleCreateArgs, RemoteBundleInspectArgs, RemoteBundleVerifyArgs, RemoteCommand,
    RemoteDoctorArgs, RemoteProviderChoice, RemoteSetupArgs, RemoteStatusArgs,
};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{
    find_in_path, find_project_root, run_captured_bounded, run_captured_bounded_isolated,
};

const CONFIG_SCHEMA_VERSION: u32 = 3;
const LEGACY_CONFIG_SCHEMA_VERSION: u32 = 2;
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
const ARTIFACT_LIST_ATTEMPTS: usize = 6;
const ARTIFACT_LIST_BACKOFF: Duration = Duration::from_secs(2);

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
    source_remote_name: String,
    execution_remote_name: String,
    trusted_source_ref: String,
    workflow_file: String,
    protected_environment: String,
    temporary_namespace: String,
    worker_repository: String,
    worker_revision: String,
    worker_version: String,
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
    root: Utf8PathBuf,
    repository: Repository,
    repository_slug: String,
    source_repository: String,
    revision: String,
}

#[derive(Debug)]
struct GitRemoteContext {
    repository: Repository,
    repository_slug: String,
    source_repository: String,
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
    original_config_identity: ArtifactFileIdentity,
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
}

#[derive(Default)]
pub(super) struct ArtifactDownloadRollback {
    created: Vec<CreatedArtifact>,
    committed: bool,
}

impl ArtifactDownloadRollback {
    pub(super) fn record(&mut self, path: &Utf8Path) -> std::io::Result<()> {
        self.created.push(CreatedArtifact {
            path: path.to_owned(),
            identity: ArtifactFileIdentity::capture(path)?,
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
        executable_modes.extend(
            git_index_executable_paths(&workspace, reporter)?
                .into_iter()
                .filter(|path| selected.contains(path.as_str())),
        );
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
    let output = checked_output(
        &cargo,
        &[
            OsString::from("metadata"),
            OsString::from("--format-version"),
            OsString::from("1"),
            OsString::from("--locked"),
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
    let git = git_context(
        root,
        &stored.source_remote_name,
        &Reporter::new(false, true, false),
    )?;
    let execution = git_remote_context(
        &git.root,
        &stored.execution_remote_name,
        &Reporter::new(false, true, false),
    )?;
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
        original_config_identity,
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
        match replace_private_config(
            &self.root,
            &self.paths.config,
            &bytes,
            &self.original_config_identity,
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
        if identity != self.original_config_identity || bytes != self.original_config_bytes {
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

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub fn build_iphone(
    root: &Utf8Path,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    provider: RemoteProviderChoice,
    expected_team: Option<&str>,
    release: bool,
    unsigned: bool,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = provider;
    if unsigned {
        select_requested_artifacts(SigningMode::UnsignedCompileOnly, artifact, include_dsym)?;
    }
    let (stored, _config_lock) = load_config_for_build(root)?;
    let signing = select_signing_plan(&stored, ferry_config, binary_name, expected_team, unsigned)?;
    let git = git_context(root, &stored.source_remote_name, reporter)?;
    let execution = git_remote_context(&git.root, &stored.execution_remote_name, reporter)?;
    ensure_configured_repositories(&stored, &git, &execution)?;
    ensure_clean(&git, reporter)?;
    let mut source = source_manifest(root, &git, reporter)?;
    bind_manifest_to_revision(&git, &mut source, reporter)?;
    ensure_clean_revision(&git, reporter)?;
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

    let expected_downloads = expected_artifact_downloads(
        root,
        &request.product_name,
        release,
        signing_mode,
        &request.requested_artifacts,
    )?;
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
        job_id: None,
        validated: false,
        cleanup_confirmed: false,
        dry_run: true,
    };
    if dry_run {
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
        prepare_artifact_destination(root, &download.path)?;
    }
    let provider = build_provider(root, &git.root, &stored)?;
    handshake(&provider, signing_mode, &request.requested_artifacts)?;
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

    reporter.progress(format!(
        "Submitting GitHub iPhone build for {} at {}",
        package_name, git.revision
    ));
    let build_deadline = Instant::now() + BUILD_TIMEOUT;
    let handle = provider_call(
        provider.submit(request.clone(), CancellationToken::new()),
        "remote_submit_failed",
        "the GitHub provider did not accept the iPhone build",
    )?;
    let job_id = handle.job_id;
    let terminal = match poll_job(&provider, &job_id, build_deadline, reporter) {
        Ok(terminal) => terminal,
        Err(error) => {
            let cleanup = cleanup_job(&provider, &job_id);
            if matches!(error, CliError::CommandInterrupted { .. }) {
                reporter.progress(if cleanup.is_ok() {
                    "Remote cancellation and cleanup confirmed"
                } else {
                    "Remote cancellation cleanup was not confirmed; inspect the exact job"
                });
                return Err(error);
            }
            if cleanup.is_ok() {
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
        let cleanup = cleanup_job(&provider, &job_id);
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

    let manifests = list_artifacts_with_retry(&provider, &job_id, build_deadline, reporter);
    let mut downloaded_files = ArtifactDownloadRollback::default();
    let download = manifests.and_then(|manifests| {
        if manifests.len() != 1 {
            return Err(remote_error(
                "artifact_manifest_ambiguous",
                "the GitHub job did not produce exactly one verified artifact manifest",
                "Retain the job and inspect its uploaded artifact set before retrying.",
            ));
        }
        let manifest = &manifests[0];
        if manifest.operation_id != operation_id
            || manifest.job_id != job_id
            || manifest.source_revision.as_deref() != Some(git.revision.as_str())
        {
            return Err(remote_error(
                "artifact_identity_mismatch",
                "the verified artifact manifest does not match this exact build request",
                "Do not use the artifact; retain the job metadata for investigation and retry with a new operation ID.",
            ));
        }
        for artifact_type in &request.requested_artifacts {
            require_one_artifact(manifest, artifact_type.artifact_kind())?;
        }

        let mut primary_sha256 = None;
        for expected in &expected_downloads {
            let artifact = require_one_artifact(manifest, expected.kind)?;
            let destination = ProtocolPath::new(
                ProtocolPathSemantics::ClientAbsolute,
                expected.path.to_string(),
            )
            .map_err(|error| {
                remote_error_with_details(
                    "artifact_destination_invalid",
                    "a local artifact destination is invalid",
                    "Choose a project location with a canonical absolute target directory.",
                    vec![error.to_string()],
                )
            })?;
            let result = provider_call(
                provider.download_artifact(
                    ArtifactDownloadRequest {
                        job_id: job_id.clone(),
                        artifact_id: artifact.artifact_id.clone(),
                        destination,
                    },
                    CancellationToken::new(),
                ),
                "artifact_download_failed",
                "an independently verified iPhone build artifact could not be downloaded",
            )?;
            downloaded_files.record(&expected.path).map_err(|error| {
                remote_error_with_details(
                    "artifact_rollback_identity_unavailable",
                    "the downloaded artifact could not be bound to its local file identity",
                    "Preserve the local artifact for inspection; remove it manually only after confirming its contents, then retry.",
                    vec![format!("artifact={}", expected.path), error.to_string()],
                )
            })?;
            let expected_manifest = downloaded_manifest(manifest);
            if result.local_path.value != expected.path.as_str()
                || result.manifest != expected_manifest
            {
                return Err(remote_error(
                    "artifact_destination_mismatch",
                    "the provider returned different artifact identity or local path metadata",
                    "Do not use the downloaded artifacts; preserve the job ID for investigation.",
                ));
            }
            if expected.path == artifact_path {
                primary_sha256 = Some(artifact.sha256.clone());
            }
        }
        primary_sha256.ok_or_else(|| {
            remote_error(
                "artifact_missing",
                "the primary iPhone artifact was not downloaded",
                "Inspect the verified manifest and retry after correcting the provider output.",
            )
        })
    });

    let cleanup = cleanup_job(&provider, &job_id);
    let artifact_sha256 = match (download, cleanup) {
        (Ok(sha256), Ok(_)) => sha256,
        (Ok(_), Err(error)) => {
            return Err(remote_error_with_details(
                "remote_cleanup_failed",
                "the artifact was verified, but exact temporary-ref cleanup failed",
                "Preserve the job ID and retry only after inspecting the exact provider-created temporary ref.",
                vec![
                    format!("job_id={job_id}"),
                    format!("artifact={artifact_path}"),
                    error.to_string(),
                ],
            ));
        }
        (Err(error), Ok(_)) => return Err(error),
        (Err(error), Err(cleanup_error)) => {
            return Err(remote_error_with_details(
                "artifact_retrieval_and_cleanup_failed",
                "artifact retrieval failed and remote cleanup was not confirmed",
                "Preserve the exact job ID and inspect both the artifact set and temporary ref before retrying.",
                vec![
                    format!("job_id={job_id}"),
                    error.to_string(),
                    cleanup_error.to_string(),
                ],
            ));
        }
    };
    downloaded_files.commit();

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
        job_id: Some(job_id),
        validated: true,
        cleanup_confirmed: true,
        dry_run: false,
    };
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
                "✓ Remote iPhone build completed and verified\n\nArtifact:\n  {}\n\nSHA-256:\n  {}{}",
                output.artifact.as_deref().unwrap_or("<missing>"),
                output.artifact_sha256.as_deref().unwrap_or("<missing>"),
                supporting
            )
        },
        &unsigned_warning(signing_mode),
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn setup(arguments: RemoteSetupArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = arguments.provider;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let git = git_context(&root, &arguments.source_remote_name, reporter)?;
    let execution = git_remote_context(&git.root, &arguments.execution_remote_name, reporter)?;
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
        source_remote_name: arguments.source_remote_name,
        execution_remote_name: arguments.execution_remote_name,
        trusted_source_ref,
        workflow_file: WORKFLOW_FILE.to_owned(),
        protected_environment: PROTECTED_ENVIRONMENT.to_owned(),
        temporary_namespace: TEMPORARY_NAMESPACE.to_owned(),
        worker_repository: worker_repository.clone(),
        worker_revision,
        worker_version: arguments.worker_version,
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
    let git = git_context(&root, &stored.source_remote_name, reporter)?;
    let execution = git_remote_context(&git.root, &stored.execution_remote_name, reporter)?;
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

fn status(arguments: &RemoteStatusArgs, reporter: &Reporter) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = arguments.provider;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let stored = load_config(&root)?;
    let git = git_context(&root, &stored.source_remote_name, reporter)?;
    let execution = git_remote_context(&git.root, &stored.execution_remote_name, reporter)?;
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
    let Some(signing) = &plan.signing else {
        return Err(remote_error(
            "invalid_signing_plan",
            "the public signing plan has no certificate reference",
            "Regenerate the manual-development signing plan.",
        ));
    };
    let references_match = signing.identity.private_key.reference.kind()
        == rustferry_remote::SecretReferenceKind::GithubActions
        && signing.identity.private_key.reference.name() == names.certificate_p12().as_str()
        && signing.password.as_ref().is_some_and(|reference| {
            reference.kind() == rustferry_remote::SecretReferenceKind::GithubActions
                && reference.name() == names.certificate_password().as_str()
        })
        && plan.provisioning.iter().all(|provisioning| {
            provisioning.profile.kind() == rustferry_remote::SecretReferenceKind::GithubActions
                && names
                    .profile_for_target(&provisioning.target)
                    .is_some_and(|name| provisioning.profile.name() == name.as_str())
        });
    if !references_match {
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
    let git = executable("git")?;
    let root_text = utf8_line(
        &checked_git_output(
            &git,
            &[
                OsString::from("rev-parse"),
                OsString::from("--show-toplevel"),
            ],
            project_root,
            "locate Git repository",
            reporter,
        )?,
        "Git repository root",
    )?;
    let root = Utf8PathBuf::from(root_text.clone())
        .canonicalize_utf8()
        .map_err(|source| CliError::Io {
            action: "resolve Git repository",
            path: Utf8PathBuf::from(root_text),
            source,
        })?;
    if !project_root.starts_with(&root) {
        return Err(remote_error(
            "project_outside_repository",
            "the RustFerry project is outside the selected Git repository",
            "Run the command from the repository containing the project.",
        ));
    }
    let remote = git_remote_context(&root, remote_name, reporter)?;
    let revision = utf8_line(
        &checked_git_output(
            &git,
            &[
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from("HEAD"),
            ],
            &root,
            "resolve exact Git revision",
            reporter,
        )?,
        "Git revision",
    )?;
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
    Ok(GitContext {
        root,
        repository: remote.repository,
        repository_slug: remote.repository_slug,
        source_repository: remote.source_repository,
        revision,
    })
}

fn git_remote_context(
    repository_root: &Utf8Path,
    remote_name: &str,
    reporter: &Reporter,
) -> Result<GitRemoteContext, CliError> {
    validate_git_remote_name(remote_name)?;
    let git = executable("git")?;
    let fetch_url = utf8_line(
        &checked_git_output(
            &git,
            &[
                OsString::from("remote"),
                OsString::from("get-url"),
                OsString::from(remote_name),
            ],
            repository_root,
            "inspect Git fetch remote",
            reporter,
        )?,
        "Git fetch remote URL",
    )?;
    let push_url = utf8_line(
        &checked_git_output(
            &git,
            &[
                OsString::from("remote"),
                OsString::from("get-url"),
                OsString::from("--push"),
                OsString::from(remote_name),
            ],
            repository_root,
            "inspect Git push remote",
            reporter,
        )?,
        "Git push remote URL",
    )?;
    let (repository, repository_slug, source_repository) = parse_repository_spec(&fetch_url)?;
    let (_, push_slug, push_repository) = parse_repository_spec(&push_url)?;
    if push_slug != repository_slug || push_repository != source_repository {
        return Err(remote_error(
            "git_remote_identity_mismatch",
            "the selected Git remote has different fetch and push repository identities",
            "Configure both URLs of the selected remote for the same exact GitHub repository.",
        ));
    }
    Ok(GitRemoteContext {
        repository,
        repository_slug,
        source_repository,
    })
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
    let executable = executable("git")?;
    let output = checked_git_output(
        &executable,
        &[
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
            OsString::from("--untracked-files=all"),
        ],
        &git.root,
        "inspect Git working tree",
        reporter,
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
    let executable = executable("git")?;
    let current = utf8_line(
        &checked_git_output(
            &executable,
            &[
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from("HEAD"),
            ],
            &git.root,
            "recheck exact Git revision",
            reporter,
        )?,
        "Git revision",
    )?;
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
    let executable = executable("git")?;
    let tree = git_tree_blobs(&executable, git, &manifest.entries, reporter)?;
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
    let digests = hash_git_blobs(&executable, git, &unique_blobs, reporter)?;
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
    executable: &Utf8Path,
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
        let mut arguments = vec![
            OsString::from("--literal-pathspecs"),
            OsString::from("ls-tree"),
            OsString::from("-l"),
            OsString::from("-z"),
            OsString::from(&git.revision),
            OsString::from("--"),
        ];
        arguments.extend(
            entries[start..end]
                .iter()
                .map(|entry| OsString::from(&entry.path)),
        );
        let output = checked_git_output(
            executable,
            &arguments,
            &git.root,
            "read exact Git tree",
            reporter,
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
    executable: &Utf8Path,
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
        let output = git_output(
            executable,
            &[OsString::from("cat-file"), OsString::from("--batch")],
            &git.root,
            "hash exact Git blobs",
            reporter,
            output_limit,
            Some(&input),
        )?;
        if !output.status.success() {
            return Err(remote_error(
                "git_blob_read_failed",
                "Git could not read the exact source blobs",
                "Verify the repository object database and retry.",
            ));
        }
        parse_git_blob_batch(&output.stdout, batch, &mut digests)?;
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
    let executable = executable("git")?;
    utf8_line(
        &checked_git_output(
            &executable,
            &[
                OsString::from("symbolic-ref"),
                OsString::from("--quiet"),
                OsString::from("--short"),
                OsString::from("HEAD"),
            ],
            &git.root,
            "resolve trusted Git branch",
            reporter,
        )?,
        "Git branch",
    )
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
    let executable = executable("git")?;
    let output = git_output(
        &executable,
        &[
            OsString::from("check-ignore"),
            OsString::from("--quiet"),
            OsString::from("--"),
            OsString::from(relative.as_str()),
        ],
        &git.root,
        "verify private provider metadata is ignored",
        reporter,
        1024,
        None,
    )?;
    match output.status.code() {
        Some(0) => Ok(()),
        Some(1) => Err(remote_error_with_details(
            "provider_config_not_ignored",
            "the private project-local GitHub provider directory is not ignored by Git",
            "Add target/ (or this exact target/ferry/github path) to the repository ignore rules before setup; never commit provider metadata or caches.",
            vec![format!("path={relative}")],
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
        },
        &worker_version,
        8,
    )
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
    let git_runner =
        GitProcessRunner::new(executable("git")?, repository_root).map_err(|error| {
            remote_error_with_details(
                "git_publisher_invalid",
                "the local Git publisher could not be configured",
                "Use a canonical Git executable and repository checkout.",
                vec![error.to_string()],
            )
        })?;
    let publisher = GitTemporaryRefPublisher::new(
        git_runner,
        &paths.git_isolation,
        stored.source_remote_name.clone(),
        stored.execution_remote_name.clone(),
        Duration::from_mins(2),
    )
    .map_err(|error| {
        remote_error_with_details(
            "git_publisher_invalid",
            "the temporary Git ref publisher could not be configured",
            "Rerun GitHub setup with a safe remote name and private generated directory.",
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
    let required_features = required_build_features(signing_mode, requested_artifacts);
    provider_call(
        provider.handshake(
            HandshakeRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("cargo package version is semantic version syntax"),
                required_features,
            },
            CancellationToken::new(),
        ),
        "provider_handshake_failed",
        "the GitHub worker/provider contract is incompatible with this client",
    )?;
    Ok(())
}

fn required_build_features(
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> Vec<ProviderFeature> {
    let mut required_features = vec![
        ProviderFeature::SourceMode(SourceMode::Git),
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

fn poll_job(
    provider: &GithubProvider,
    job_id: &str,
    deadline: Instant,
    reporter: &Reporter,
) -> Result<JobTerminal, CliError> {
    let mut sequence = None;
    let mut diagnostics = Vec::new();
    loop {
        if rustferry_core::process_control::interrupt_requested() {
            reporter
                .progress("Cancellation requested; waiting for exact-run termination and cleanup");
            let _ = cancel_and_wait(
                provider,
                job_id,
                "client_interrupted",
                &mut sequence,
                &mut diagnostics,
                reporter,
            );
            return Err(CliError::CommandInterrupted {
                tool: "GitHub Actions job".to_owned(),
                stage: "remote iPhone build",
            });
        }
        if Instant::now() >= deadline {
            reporter
                .progress("Build timeout reached; waiting for exact-run cancellation and cleanup");
            let mut details = vec![format!("job_id={job_id}")];
            details.extend(cancel_and_wait(
                provider,
                job_id,
                "client_timeout",
                &mut sequence,
                &mut diagnostics,
                reporter,
            ));
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
                CancellationToken::new(),
            ),
            "remote_events_failed",
            "GitHub build events could not be retrieved",
        ) {
            Ok(page) => page,
            Err(error) => {
                let mut details = vec![format!("job_id={job_id}"), error.to_string()];
                details.extend(cancel_and_wait(
                    provider,
                    job_id,
                    "client_tracking_failed",
                    &mut sequence,
                    &mut diagnostics,
                    reporter,
                ));
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
        sleep_interruptibly(POLL_INTERVAL);
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
) -> Result<Vec<rustferry_remote::ArtifactManifest>, CliError> {
    retry_artifact_listing(
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

fn retry_artifact_listing<F>(
    mut list: F,
    deadline: Instant,
    reporter: &Reporter,
    attempts: usize,
    backoff: Duration,
) -> Result<Vec<rustferry_remote::ArtifactManifest>, CliError>
where
    F: FnMut() -> ImmediateProviderResult<Vec<rustferry_remote::ArtifactManifest>>,
{
    let mut last_failure = "the verified artifact manifest is not indexed yet".to_owned();
    for attempt in 1..=attempts {
        check_artifact_listing_deadline(deadline)?;
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

fn cancel_and_wait(
    provider: &GithubProvider,
    job_id: &str,
    reason: &str,
    sequence: &mut Option<u64>,
    diagnostics: &mut Vec<String>,
    reporter: &Reporter,
) -> Vec<String> {
    let mut details = Vec::new();
    match provider_call(
        provider.cancel(
            CancellationRequest {
                job_id: job_id.to_owned(),
                reason: reason.to_owned(),
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
                details.push("terminal_after_cancel=true".to_owned());
                return details;
            }
        }
        Err(error) => details.push(format!("cancel_error={error}")),
    }
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
                    details.push(format!("terminal_state={}", state_name(page.state)));
                    return details;
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
    details.push("terminal_after_cancel=false".to_owned());
    details
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
    WorkflowConfig::new(
        filename,
        environment,
        secret_names,
        worker,
        public_source,
        trusted,
        namespace,
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
    if !matches!(
        stored.schema_version,
        LEGACY_CONFIG_SCHEMA_VERSION | CONFIG_SCHEMA_VERSION
    ) || stored.workflow_file != WORKFLOW_FILE
        || stored.protected_environment != PROTECTED_ENVIRONMENT
        || stored.temporary_namespace != TEMPORARY_NAMESPACE
    {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub provider config has an unsupported schema or fixed policy",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
    if (stored.schema_version == LEGACY_CONFIG_SCHEMA_VERSION && !stored.signing_targets.is_empty())
        || (stored.schema_version == CONFIG_SCHEMA_VERSION && stored.signing_targets.is_empty())
    {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub provider target-map schema is inconsistent",
            "Rerun GitHub setup from the current validated target graph.",
        ));
    }
    validate_git_remote_name(&stored.source_remote_name)?;
    validate_git_remote_name(&stored.execution_remote_name)?;
    let (_, execution_slug, execution_repository) = parse_repository_spec(&stored.repository)?;
    let (_, source_slug, source) = parse_repository_spec(&stored.source_repository)?;
    let (_, _, worker_repository) = parse_repository_spec(&stored.worker_repository)?;
    if execution_slug != stored.repository
        || source != stored.source_repository
        || worker_repository != stored.worker_repository
        || (worker_repository == execution_repository && execution_slug != source_slug)
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
    require_private_directory(parent, "GitHub provider config lock")?;
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

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
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
    Ok(ProviderConfigLock { _file: file })
}

fn require_single_link(metadata: &fs::Metadata, label: &'static str) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(remote_error_with_details(
                "unsafe_generated_path",
                "private provider metadata has multiple hard links",
                "Replace the generated entry with one private regular file and retry.",
                vec![format!("role={label}")],
            ));
        }
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
    let initial_metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect private provider file",
        path: path.to_owned(),
        source,
    })?;
    require_private_mode(path, &initial_metadata)?;
    let initial = ConfigFileState::capture(&initial_metadata)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| CliError::Io {
        action: "open GitHub provider config snapshot",
        path: path.to_owned(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect open GitHub provider config",
        path: path.to_owned(),
        source,
    })?;
    require_private_mode(path, &opened_metadata)?;
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
    let stored = serde_json::from_slice::<StoredGithubConfig>(&bytes).map_err(|_| {
        remote_error(
            "invalid_provider_config",
            "the GitHub provider config is malformed or contains unknown fields",
            "Remove the generated config and rerun GitHub setup.",
        )
    })?;
    validate_stored_config(&stored)?;
    Ok(stored)
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
    expected_original_identity: &ArtifactFileIdentity,
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
        || {},
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn replace_private_config_with(
    root: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    expected_original_identity: &ArtifactFileIdentity,
    expected_original_bytes: &[u8],
    expected_installed: &StoredGithubConfig,
    before_quarantine: impl FnOnce(),
    after_quarantine: impl FnOnce(&Utf8Path),
) -> Result<(), ConfigCommitError> {
    let StagedPrivateConfig { temporary, parent } = stage_private_config(
        root,
        path,
        bytes,
        expected_original_identity,
        expected_original_bytes,
    )
    .map_err(|error| ConfigCommitError::NotCommitted(Box::new(error)))?;
    before_quarantine();
    let quarantine = ConfigQuarantine::capture(&parent, path)
        .map_err(|error| ConfigCommitError::NotCommitted(Box::new(error)))?;
    let quarantined_snapshot = read_private_config_file(&quarantine.path);
    let quarantine_matches = quarantined_snapshot
        .as_ref()
        .is_ok_and(|(identity, current)| {
            identity == expected_original_identity && current == expected_original_bytes
        });
    if !quarantine_matches {
        let cause = quarantined_snapshot
            .err()
            .unwrap_or_else(provider_config_changed);
        return Err(restore_config_or_preserve(quarantine, path, cause));
    }
    drop(quarantined_snapshot);
    if let Err(error) = sync_private_config_directory(&parent) {
        return Err(restore_config_or_preserve(quarantine, path, error));
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
                    vec![format!("recovery={recovery}"), error.error.to_string()],
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
    quarantine.delete().map_err(|(recovery, source)| {
        ConfigCommitError::CommittedNeedsInspection(Box::new(CliError::Io {
            action: "remove verified provider-config backup",
            path: recovery,
            source,
        }))
    })?;
    sync_private_config_directory(&parent)
        .map_err(|error| ConfigCommitError::CommittedNeedsInspection(Box::new(error)))
}

struct StagedPrivateConfig {
    temporary: tempfile::NamedTempFile,
    parent: Utf8PathBuf,
}

struct ConfigQuarantine {
    directory: tempfile::TempDir,
    path: Utf8PathBuf,
}

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

    fn restore_noclobber(
        self,
        destination: &Utf8Path,
    ) -> Result<(), (Utf8PathBuf, std::io::Error)> {
        let recovery = self.path.clone();
        let temporary = match tempfile::TempPath::try_from_path(self.path.to_path_buf()) {
            Ok(temporary) => temporary,
            Err(source) => {
                let _ = self.directory.keep();
                return Err((recovery, source));
            }
        };
        match temporary.persist_noclobber(destination) {
            Ok(()) => {
                let _ = self.directory.close();
                Ok(())
            }
            Err(mut error) => {
                error.path.disable_cleanup(true);
                let source = error.error;
                drop(error.path);
                let _ = self.directory.keep();
                Err((recovery, source))
            }
        }
    }

    fn delete(self) -> Result<(), (Utf8PathBuf, std::io::Error)> {
        let recovery = self.path.clone();
        if let Err(source) = fs::remove_file(&self.path) {
            let _ = self.directory.keep();
            return Err((recovery, source));
        }
        match self.directory.close() {
            Ok(()) => Ok(()),
            Err(source) => Err((recovery, source)),
        }
    }
}

fn restore_config_or_preserve(
    quarantine: ConfigQuarantine,
    destination: &Utf8Path,
    cause: CliError,
) -> ConfigCommitError {
    match quarantine.restore_noclobber(destination) {
        Ok(()) => ConfigCommitError::NotCommitted(Box::new(cause)),
        Err((recovery, source)) => {
            ConfigCommitError::CommittedNeedsInspection(Box::new(remote_error_with_details(
                "provider_config_recovery_required",
                "the changed provider config could not be restored without overwriting another path",
                "Inspect the current provider config and preserved file before retrying.",
                vec![
                    format!("recovery={recovery}"),
                    source.to_string(),
                    cause.to_string(),
                ],
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
    let mut temporary = tempfile::Builder::new()
        .prefix(".provider.json.")
        .tempfile_in(parent)
        .map_err(|source| CliError::Io {
            action: "create private temporary provider config",
            path: parent.to_owned(),
            source,
        })?;
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
    temporary
        .as_file_mut()
        .write_all(bytes)
        .and_then(|()| temporary.as_file_mut().sync_all())
        .map_err(|source| CliError::Io {
            action: "write temporary provider config",
            path: path.to_owned(),
            source,
        })?;
    ensure_config_snapshot_unchanged(
        root,
        path,
        expected_original_identity,
        expected_original_bytes,
    )?;
    Ok(StagedPrivateConfig {
        temporary,
        parent: parent.to_owned(),
    })
}

fn finish_private_config_commit(
    root: &Utf8Path,
    parent: &Utf8Path,
    expected_installed: &StoredGithubConfig,
) -> Result<(), CliError> {
    sync_private_config_directory(parent)?;
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

fn sync_private_config_directory(parent: &Utf8Path) -> Result<(), CliError> {
    #[cfg(unix)]
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

fn git_output(
    program: &Utf8Path,
    arguments: &[OsString],
    directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
    output_limit: usize,
    input: Option<&[u8]>,
) -> Result<std::process::Output, CliError> {
    let mut fixed = vec![
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("-c"),
        OsString::from("credential.interactive=never"),
        OsString::from("-c"),
        OsString::from("protocol.file.allow=never"),
    ];
    fixed.extend_from_slice(arguments);
    run_captured_bounded_isolated(
        program,
        &fixed,
        directory,
        stage,
        reporter,
        output_limit,
        input,
    )
}

fn checked_git_output(
    program: &Utf8Path,
    arguments: &[OsString],
    directory: &Utf8Path,
    stage: &'static str,
    reporter: &Reporter,
) -> Result<Vec<u8>, CliError> {
    let output = git_output(
        program,
        arguments,
        directory,
        stage,
        reporter,
        MAX_TOOL_OUTPUT_BYTES,
        None,
    )?;
    if !output.status.success() {
        return Err(CliError::CommandFailed {
            tool: "git".to_owned(),
            stage,
            status: output.status.code(),
            stderr: String::new(),
            log: None,
            help: "Correct the repository state, then rerun with --verbose.".to_owned(),
        });
    }
    Ok(output.stdout)
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
            let actual = read_bounded_file(path, MAX_CONFIG_BYTES.max(expected.len() as u64))?;
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
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    let is_private = private_final && index + 1 == component_count;
                    builder.mode(if is_private { 0o700 } else { 0o755 });
                }
                builder.create(&current).map_err(|source| CliError::Io {
                    action: "create generated directory",
                    path: current.clone(),
                    source,
                })?;
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
    Ok(())
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
    #[cfg(any(test, not(unix)))]
    use super::parse_git_index_executable_paths;
    use super::{
        ArtifactDownloadRollback, CONFIG_SCHEMA_VERSION, CanonicalBase64SigningBlob,
        ConfigCommitError, ExistingFile, GithubPaths, ImmediateProviderResult,
        MAX_ENVIRONMENT_SECRET_BYTES, ManualGithubSecretValues, ManualGithubSigningAssets,
        ManualGithubSigningSession, ManualSigningRemote, PROTECTED_ENVIRONMENT, RawSigningPassword,
        SigningSecretUpload, StoredGithubConfig, TEMPORARY_NAMESPACE, WORKFLOW_FILE,
        acquire_provider_config_lock, downloaded_manifest, encode_stored_config,
        ensure_config_snapshot_unchanged, ensure_doctor_ready, ensure_provider_directories,
        ensure_workflow_directory, expected_artifact_downloads, generate_workflow, load_config,
        load_signing_project_state, parse_repository_spec, preflight_file,
        prepare_artifact_destination, provider_config_lock_for_signing,
        read_private_config_snapshot, remote_error, replace_private_config,
        required_build_features, required_signing_secret_names, retry_artifact_listing,
        select_requested_artifacts, signing_config_commit_uncertain, source_manifest_digest,
        unsigned_signing_plan, validate_git_remote_name, validate_manual_assets_match_plan,
        validate_stored_config, workflow_from_stored, write_create_only,
    };
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::executable_entrypoint;
    use crate::cli::BuildArtifactSelection;
    use crate::error::CliError;
    use crate::output::Reporter;
    use rustferry_github::transport::{
        EnvironmentSecretWriteRequest, GhExecutionError, Repository, TransportError,
    };
    use rustferry_github::{ProtectedEnvironment, SigningSecretNames};
    use rustferry_remote::{
        ArtifactKind, ArtifactManifest, BundleIdentifier, CURRENT_PROTOCOL_VERSION,
        DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet,
        IosArtifactType, ProviderCapabilities, ProviderCheck, ProviderCheckStatus,
        ProviderDoctorReport, ProviderFeature, ProvisioningPlan, ProvisioningPlatform,
        ProvisioningProfile, ProvisioningProfileType, RemoteBuildError, SecretBytes,
        SecretReference, SecretReferenceKind, SigningCertificate, SigningIdentity, SigningMode,
        SigningPlan, SigningPrivateKeyReference, SigningReference, SigningTarget,
        SigningTargetKind, SourceBundleRequest, plan_source_bundle,
    };

    fn unsigned_stored_config() -> StoredGithubConfig {
        StoredGithubConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            repository: "example/private-builds".to_owned(),
            source_repository: "https://github.com/example/public-app".to_owned(),
            source_remote_name: "public".to_owned(),
            execution_remote_name: "signing".to_owned(),
            trusted_source_ref: "refs/heads/main".to_owned(),
            workflow_file: WORKFLOW_FILE.to_owned(),
            protected_environment: PROTECTED_ENVIRONMENT.to_owned(),
            temporary_namespace: TEMPORARY_NAMESPACE.to_owned(),
            worker_repository: "https://github.com/example/rustferry".to_owned(),
            worker_revision: "a".repeat(40),
            worker_version: "0.1.0".to_owned(),
            signing_targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle ID"),
                kind: SigningTargetKind::Application,
            }],
            signing: None,
        }
    }

    fn provider_config_fixture() -> (
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
            "[package]\nname = \"App\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("Cargo manifest");
        let paths = GithubPaths::new(&root, &root);
        ensure_provider_directories(&root, &paths).expect("private provider directories");
        let config = unsigned_stored_config();
        let bytes = encode_stored_config(&config).expect("config bytes");
        write_create_only(&paths.config, &bytes, true).expect("provider config");
        (temporary, root, paths, config)
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
            original_config_identity,
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
        std::fs::write(&session.paths.config, stored_bytes).expect("replace config fixture");
        let (identity, bytes) = read_private_config_snapshot(&session.root, &session.paths.config)
            .expect("multi config snapshot");
        session.original_config_identity = identity;
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

    #[test]
    fn stored_target_map_renders_static_secrets_and_schema_two_remains_legacy_readable() {
        let mut stored = unsigned_stored_config();
        stored.signing_targets.push(SigningTarget {
            name: "Widget".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app.widget")
                .expect("widget bundle ID"),
            kind: SigningTargetKind::Extension,
        });
        validate_stored_config(&stored).expect("schema three target map");
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

        let mut legacy = unsigned_stored_config();
        legacy.schema_version = super::LEGACY_CONFIG_SCHEMA_VERSION;
        legacy.signing_targets.clear();
        let encoded = serde_json::to_vec(&legacy).expect("legacy config JSON");
        let decoded = serde_json::from_slice::<StoredGithubConfig>(&encoded)
            .expect("new client reads schema two config");
        validate_stored_config(&decoded).expect("legacy single-profile config remains valid");
        let legacy_workflow = generate_workflow(&workflow_from_stored(&decoded).expect("legacy"));
        assert!(
            legacy_workflow
                .yaml()
                .contains("secrets.RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE")
        );
        assert!(!legacy_workflow.yaml().contains("RFSIGNV2"));

        let mut malformed = unsigned_stored_config();
        malformed.signing_targets.clear();
        assert_eq!(
            validate_stored_config(&malformed)
                .expect_err("schema three requires exact targets")
                .code(),
            "invalid_provider_config"
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
            &identity,
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
            &identity,
            &original_bytes,
            &installed,
            || {
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
            &identity,
            &original_bytes,
            &installed,
            || {},
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
    }

    #[test]
    fn handshake_and_manifest_require_every_selected_artifact_type() {
        let requested = select_requested_artifacts(
            SigningMode::ManualDevelopment,
            Some(BuildArtifactSelection::All),
            true,
        )
        .expect("all signed artifacts");
        let features = required_build_features(SigningMode::ManualDevelopment, &requested);
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
    fn create_only_setup_is_idempotent_and_refuses_different_bytes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
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
}
