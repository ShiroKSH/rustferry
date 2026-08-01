use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_github::provider::{
    GitProcessRunner, GitTemporaryRefPublisher, GithubBuildProvider, GithubMutationAuthorization,
    GithubPollingPolicy, GithubProviderConfig, SystemProviderClock, WorkflowFingerprint,
};
use rustferry_github::transport::{
    GhAuthentication, GhProcessRunner, GithubTransport, Repository, TokenEnvironmentVariable,
    TransportLimits,
};
use rustferry_github::{
    GithubVerifiedArtifactStore, ProtectedEnvironment, SigningSecretNames,
    TemporaryBranchNamespace, TrustedSourceRef, WorkerDistribution, WorkflowConfig,
    WorkflowFileName, generate_workflow,
};
use rustferry_remote::{
    ArtifactDownloadRequest, ArtifactKind, ArtifactListRequest, BuildProfile, BuildProvider,
    BundleIdentifier, CURRENT_PROTOCOL_VERSION, CancellationRequest, CancellationToken,
    CleanupConfirmation, CleanupRequest, DiagnosticSeverity, EventRequest, HandshakeRequest,
    IosArtifactType, IosDeviceBuildRequest, JobState, ProtocolPath, ProtocolPathSemantics,
    ProviderDoctorRequest, ProviderFeature, ProviderFuture, RemoteBuildEvent, RemoteBuildEventKind,
    SigningMode, SigningPlan, SigningTarget, SigningTargetKind, SourceBundleRequest, SourceLimits,
    SourceManifest, SourceManifestEntry, SourceMode, UnsignedNestedBundleKind, ValidationLevel,
    plan_source_bundle, validate_source_manifest,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cli::{
    RemoteArgs, RemoteCommand, RemoteDoctorArgs, RemoteProviderChoice, RemoteSetupArgs,
    RemoteStatusArgs,
};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{
    find_in_path, find_project_root, run_captured_bounded, run_captured_bounded_isolated,
};

const CONFIG_SCHEMA_VERSION: u32 = 1;
const CONFIG_RELATIVE_PATH: &str = "target/ferry/github/provider.json";
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
struct StoredGithubConfig {
    schema_version: u32,
    repository: String,
    source_repository: String,
    remote_name: String,
    trusted_source_ref: String,
    workflow_file: String,
    protected_environment: String,
    temporary_namespace: String,
    worker_repository: String,
    worker_revision: String,
    worker_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing: Option<SigningPlan>,
}

#[derive(Debug)]
struct GithubPaths {
    config: Utf8PathBuf,
    cache: Utf8PathBuf,
    git_isolation: Utf8PathBuf,
    workflow: Utf8PathBuf,
}

impl GithubPaths {
    fn new(project_root: &Utf8Path, repository_root: &Utf8Path) -> Self {
        Self {
            config: project_root.join(CONFIG_RELATIVE_PATH),
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

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    manifest_path: Utf8PathBuf,
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct SetupOutput {
    repository: String,
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
    repository: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
    #[cfg(not(any(unix, windows)))]
    length: u64,
    #[cfg(not(any(unix, windows)))]
    created: std::time::SystemTime,
    #[cfg(not(any(unix, windows)))]
    modified: std::time::SystemTime,
}

impl ArtifactFileIdentity {
    fn capture(path: &Utf8Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "downloaded artifact is not a regular file",
            ));
        }

        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;

            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        };
        #[cfg(windows)]
        let identity = {
            use std::os::windows::fs::MetadataExt as _;

            Self {
                volume_serial_number: metadata.volume_serial_number().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "artifact volume identity is unavailable",
                    )
                })?,
                file_index: metadata.file_index().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "artifact file identity is unavailable",
                    )
                })?,
            }
        };
        #[cfg(not(any(unix, windows)))]
        let identity = Self {
            length: metadata.len(),
            created: metadata.created()?,
            modified: metadata.modified()?,
        };

        Ok(identity)
    }
}

#[derive(Debug)]
struct CreatedArtifact {
    path: Utf8PathBuf,
    identity: ArtifactFileIdentity,
}

#[derive(Default)]
struct ArtifactDownloadRollback {
    created: Vec<CreatedArtifact>,
    committed: bool,
}

impl ArtifactDownloadRollback {
    fn record(&mut self, path: &Utf8Path) -> std::io::Result<()> {
        self.created.push(CreatedArtifact {
            path: path.to_owned(),
            identity: ArtifactFileIdentity::capture(path)?,
        });
        Ok(())
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ArtifactDownloadRollback {
    fn drop(&mut self) {
        if !self.committed {
            for artifact in self.created.iter().rev() {
                if ArtifactFileIdentity::capture(&artifact.path).ok() == Some(artifact.identity) {
                    let _ = fs::remove_file(&artifact.path);
                }
            }
        }
    }
}

pub fn run(arguments: RemoteArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        RemoteCommand::Setup(arguments) => setup(arguments, dry_run, reporter),
        RemoteCommand::Doctor(arguments) => doctor(&arguments, reporter),
        RemoteCommand::Status(arguments) => status(&arguments, reporter),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn build_iphone(
    root: &Utf8Path,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    provider: RemoteProviderChoice,
    expected_team: Option<&str>,
    release: bool,
    unsigned: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = provider;
    let stored = load_config(root)?;
    let signing = select_signing_plan(&stored, ferry_config, binary_name, expected_team, unsigned)?;
    let git = git_context(root, &stored.remote_name, reporter)?;
    ensure_configured_repository(&stored, &git)?;
    ensure_clean(&git, reporter)?;
    let mut source = source_manifest(root, &git, reporter)?;
    bind_manifest_to_revision(&git, &mut source, reporter)?;
    ensure_clean_revision(&git, reporter)?;
    let product =
        rustferry_apple::derive_ios_device_product_expectation(ferry_config, binary_name)?;
    let signing_mode = signing.mode;
    let requested_artifacts = match signing_mode {
        SigningMode::UnsignedCompileOnly => BTreeSet::from([IosArtifactType::Xcarchive]),
        SigningMode::ManualDevelopment => {
            BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport])
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

    let expected_downloads =
        expected_artifact_downloads(root, &request.product_name, release, signing_mode)?;
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
    handshake(&provider, signing_mode)?;
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
        let requested_kinds = if signing_mode == SigningMode::UnsignedCompileOnly {
            vec![ArtifactKind::Xcarchive]
        } else {
            vec![ArtifactKind::Ipa, ArtifactKind::SigningReport]
        };
        for kind in requested_kinds {
            require_one_artifact(manifest, kind)?;
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
    let git = git_context(&root, &arguments.remote_name, reporter)?;
    let repository = match arguments.repository.as_deref() {
        Some(specification) => {
            let (_, slug, source) = parse_repository_spec(specification)?;
            if source != git.source_repository {
                return Err(remote_error(
                    "remote_repository_mismatch",
                    "--repository does not match the selected Git remote",
                    "Use the exact owner/repository from the selected GitHub remote.",
                ));
            }
            slug
        }
        None => git.repository_slug.clone(),
    };
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
    let signing = arguments
        .signing_plan
        .as_deref()
        .map(read_signing_plan)
        .transpose()?;
    if let Some(plan) = &signing {
        validate_github_signing_plan(plan)?;
    }
    let stored = StoredGithubConfig {
        schema_version: CONFIG_SCHEMA_VERSION,
        repository,
        source_repository: git.source_repository.clone(),
        remote_name: arguments.remote_name,
        trusted_source_ref,
        workflow_file: WORKFLOW_FILE.to_owned(),
        protected_environment: PROTECTED_ENVIRONMENT.to_owned(),
        temporary_namespace: TEMPORARY_NAMESPACE.to_owned(),
        worker_repository: arguments.worker_repository,
        worker_revision,
        worker_version: arguments.worker_version,
        signing,
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
    let authenticated = transport.authenticate(&git.repository).map_err(|error| {
        remote_error_with_details(
            "github_authentication_required",
            "GitHub authentication could not be verified",
            "Authenticate GitHub API access with `gh auth login` or GH_TOKEN, configure separate SSH or credential-manager Git authentication for temporary refs, then rerun setup.",
            vec![error.to_string()],
        )
    })?;
    let repository_info = transport.repository(&git.repository).map_err(|error| {
        remote_error_with_details(
            "github_repository_unavailable",
            "the exact GitHub repository could not be inspected",
            "Check repository identity and token access, then rerun setup.",
            vec![error.to_string()],
        )
    })?;
    if repository_info.is_archived() || repository_info.is_disabled() {
        return Err(remote_error(
            "github_repository_read_only",
            "the configured GitHub repository cannot run new builds",
            "Use an active, non-archived GitHub repository.",
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
        write_create_only(&paths.workflow, generated.yaml().as_bytes(), false)?;
        write_create_only(&paths.config, &config_bytes, true)?;
    }

    let output = SetupOutput {
        repository: stored.repository.clone(),
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
                    "GitHub remote setup preview\n\nRepository:\n  {}\n\nWorkflow:\n  {}\n\n{}",
                    output.repository,
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
    let RemoteProviderChoice::Github = arguments.provider;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let stored = load_config(&root)?;
    let git = git_context(&root, &stored.remote_name, reporter)?;
    ensure_configured_repository(&stored, &git)?;
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
    let git = git_context(&root, &stored.remote_name, reporter)?;
    ensure_configured_repository(&stored, &git)?;
    let generated = generate_workflow(&workflow_from_stored(&stored)?);
    let paths = GithubPaths::new(&root, &git.root);
    reject_linked_components(&git.root, Utf8Path::new(".github/workflows"), true)?;
    let workflow_matches = existing_file_matches(&paths.workflow, generated.yaml().as_bytes())?;
    let output = StatusOutput {
        repository: stored.repository.clone(),
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
                "GitHub remote configuration\n\nRepository:\n  {}\n\nWorkflow exact:\n  {}\n\nTrusted ref:\n  {}\n\nSigning:\n  {}",
                output.repository,
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
            "Rerun `cargo ferry remote setup github --signing-plan <public-plan.json> ...`, or pass `--unsigned` for a non-installable smoke build.",
        )
    })?;
    validate_github_signing_plan(&plan)?;
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

fn unsigned_signing_plan(
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
    let names = SigningSecretNames::goal3_defaults();
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
        && !plan.provisioning.is_empty()
        && plan.provisioning.iter().all(|provisioning| {
            provisioning.profile.kind() == rustferry_remote::SecretReferenceKind::GithubActions
                && provisioning.profile.name() == names.provisioning_profile().as_str()
        });
    if !references_match {
        return Err(remote_error(
            "signing_secret_reference_mismatch",
            "the signing plan does not use the configured protected GitHub secret names",
            "Use RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12, RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD, and RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE references.",
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
    let remote_url = utf8_line(
        &checked_git_output(
            &git,
            &[
                OsString::from("remote"),
                OsString::from("get-url"),
                OsString::from("--push"),
                OsString::from(remote_name),
            ],
            &root,
            "inspect Git remote",
            reporter,
        )?,
        "Git remote URL",
    )?;
    let (repository, repository_slug, source_repository) = parse_repository_spec(&remote_url)?;
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
        repository,
        repository_slug,
        source_repository,
        revision,
    })
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
    let repository = Repository::new(owner, name).map_err(|error| {
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
    let (repository, _, source_repository) = parse_repository_spec(&stored.repository)?;
    if source_repository != stored.source_repository {
        return Err(remote_error(
            "invalid_provider_config",
            "the provider repository and source repository differ",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
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
        stored.remote_name.clone(),
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

fn handshake(provider: &GithubProvider, signing_mode: SigningMode) -> Result<(), CliError> {
    let artifact = if signing_mode == SigningMode::UnsignedCompileOnly {
        IosArtifactType::Xcarchive
    } else {
        IosArtifactType::Ipa
    };
    let mut required_features = vec![
        ProviderFeature::SourceMode(SourceMode::Git),
        ProviderFeature::IosDeviceBuild,
        ProviderFeature::SigningMode(signing_mode),
        ProviderFeature::LiveEvents,
        ProviderFeature::Cancellation,
        ProviderFeature::ArtifactType(artifact),
        ProviderFeature::ArtifactListing,
        ProviderFeature::ArtifactDownload,
        ProviderFeature::Cleanup,
    ];
    if signing_mode.is_signed() {
        required_features.push(ProviderFeature::ArtifactType(
            IosArtifactType::SigningReport,
        ));
    }
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

fn event_detail(event: &RemoteBuildEvent) -> String {
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
    let trusted = TrustedSourceRef::new(stored.trusted_source_ref.clone());
    let namespace = TemporaryBranchNamespace::new(stored.temporary_namespace.clone());
    let (Ok(filename), Ok(environment), Ok(worker), Ok(trusted), Ok(namespace)) =
        (filename, environment, worker, trusted, namespace)
    else {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub workflow configuration is invalid",
            "Remove the generated provider config and rerun GitHub setup with exact safe values.",
        ));
    };
    WorkflowConfig::new(
        filename,
        environment,
        SigningSecretNames::goal3_defaults(),
        worker,
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
    let (_, slug, source) = parse_repository_spec(&stored.repository)?;
    if slug != stored.repository || source != stored.source_repository {
        return Err(remote_error(
            "invalid_provider_config",
            "the stored GitHub repository identity is inconsistent",
            "Remove the generated provider config and rerun GitHub setup.",
        ));
    }
    workflow_from_stored(stored)?;
    if let Some(signing) = &stored.signing {
        validate_github_signing_plan(signing)?;
    }
    Ok(())
}

fn load_config(root: &Utf8Path) -> Result<StoredGithubConfig, CliError> {
    let path = root.join(CONFIG_RELATIVE_PATH);
    reject_linked_components(root, Utf8Path::new(CONFIG_RELATIVE_PATH), true)?;
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            remote_error(
                "remote_not_configured",
                "the GitHub remote provider is not configured for this project",
                "Run `cargo ferry remote setup github --worker-revision <exact-commit>` first.",
            )
        } else {
            CliError::Io {
                action: "inspect GitHub provider config",
                path: path.clone(),
                source,
            }
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(remote_error(
            "invalid_provider_config",
            "the GitHub provider config is not a bounded regular file",
            "Remove the generated config and rerun GitHub setup.",
        ));
    }
    require_private_mode(&path, &metadata)?;
    let bytes = read_bounded_file(&path, MAX_CONFIG_BYTES)?;
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

fn read_signing_plan(path: &Utf8Path) -> Result<SigningPlan, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect public signing plan",
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(remote_error(
            "invalid_signing_plan",
            "the public signing plan is not a bounded regular file",
            "Use a regular JSON file containing public metadata and opaque secret references only.",
        ));
    }
    let bytes = read_bounded_file(path, MAX_CONFIG_BYTES)?;
    let plan = serde_json::from_slice::<SigningPlan>(&bytes).map_err(|_| {
        remote_error(
            "invalid_signing_plan",
            "the public signing plan is malformed or contains unknown fields",
            "Use the strict SigningPlan JSON schema; raw device UDIDs and secret values are not accepted.",
        )
    })?;
    validate_github_signing_plan(&plan)?;
    Ok(plan)
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

fn ensure_directory_chain(
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

fn prepare_artifact_destination(root: &Utf8Path, artifact: &Utf8Path) -> Result<(), CliError> {
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
        vec![
            ExpectedDownload {
                kind: ArtifactKind::Ipa,
                path: directory.join(format!("{product_name}-development.ipa")),
            },
            ExpectedDownload {
                kind: ArtifactKind::Manifest,
                path: directory.join("artifact-manifest.json"),
            },
            ExpectedDownload {
                kind: ArtifactKind::ValidationReport,
                path: directory.join("validation-report.json"),
            },
        ]
    };
    downloads.push(ExpectedDownload {
        kind: ArtifactKind::SanitizedLog,
        path: directory.join("sanitized-build-log.txt"),
    });
    Ok(downloads)
}

fn validate_artifact_product_name(product_name: &str) -> Result<(), CliError> {
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

fn ensure_configured_repository(
    stored: &StoredGithubConfig,
    git: &GitContext,
) -> Result<(), CliError> {
    if git.source_repository == stored.source_repository && git.repository_slug == stored.repository
    {
        Ok(())
    } else {
        Err(remote_error(
            "remote_repository_changed",
            "the configured GitHub repository no longer matches the selected Git remote",
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
    use super::{
        ArtifactDownloadRollback, ExistingFile, GithubPaths, ImmediateProviderResult,
        downloaded_manifest, ensure_doctor_ready, executable_entrypoint,
        expected_artifact_downloads, parse_repository_spec, preflight_file,
        prepare_artifact_destination, retry_artifact_listing, source_manifest_digest,
        unsigned_signing_plan, write_create_only,
    };
    use std::time::{Duration, Instant};

    use crate::output::Reporter;
    use rustferry_remote::{
        ArtifactKind, ArtifactManifest, CURRENT_PROTOCOL_VERSION, ProviderCapabilities,
        ProviderCheck, ProviderCheckStatus, ProviderDoctorReport, RemoteBuildError, SigningMode,
        SigningTargetKind, SourceBundleRequest, plan_source_bundle,
    };

    #[test]
    fn parses_credential_free_github_remote_forms() {
        for remote in [
            "ShiroKSH/rustferry",
            "https://github.com/ShiroKSH/rustferry.git",
            "git@github.com:ShiroKSH/rustferry.git",
            "ssh://git@github.com/ShiroKSH/rustferry.git",
        ] {
            let (_, slug, source) = parse_repository_spec(remote).expect("valid remote");
            assert_eq!(slug, "ShiroKSH/rustferry");
            assert_eq!(source, "https://github.com/ShiroKSH/rustferry");
        }
        assert!(parse_repository_spec("https://token@github.com/owner/repo").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn executable_entrypoint_preserves_multicall_symlink_basename() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = camino::Utf8Path::from_path(temporary.path()).expect("UTF-8 temp path");
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
        let downloads =
            expected_artifact_downloads(root, "Weather", false, SigningMode::ManualDevelopment)
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
    fn every_download_accepts_only_the_client_verified_manifest_state() {
        let listed = ArtifactManifest::new("operation", "job");
        let downloaded = downloaded_manifest(&listed);
        assert_ne!(downloaded, listed);
        assert!(
            downloaded
                .validation_levels
                .contains(&rustferry_remote::ValidationLevel::DownloadedToClient)
        );
        for _ in expected_artifact_downloads(
            camino::Utf8Path::new("/project"),
            "Weather",
            false,
            SigningMode::ManualDevelopment,
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
        let downloads =
            expected_artifact_downloads(root, "Weather", false, SigningMode::ManualDevelopment)
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
