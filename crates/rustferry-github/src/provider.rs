//! GitHub Actions build-provider orchestration and isolated temporary-ref publication.
//!
//! Submission publishes one create-only temporary branch based on the exact requested source
//! revision. The branch changes only the approved workflow and strict request manifest. Git
//! plumbing never switches branches or mutates the caller's index or working tree.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use rustferry_remote::{
    ArtifactDownloadRequest, ArtifactDownloadResult, ArtifactListRequest, ArtifactManifest,
    BuildProvider, CURRENT_PROTOCOL_VERSION, CancellationAck, CancellationRequest,
    CancellationToken, CleanupConfirmation, CleanupRequest, EventPage, EventRequest,
    HandshakeRequest, HandshakeResponse, IosArtifactType, IosDeviceBuildRequest,
    IosDeviceBuildResult, JobHandle, JobState, ProviderCapabilities, ProviderCheck,
    ProviderCheckStatus, ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature,
    ProviderFuture, RemoteBuildError, RemoteBuildEvent, RemoteBuildEventKind, RemoteBuildResult,
    RemoteErrorInfo, SecretReference, SecretReferenceKind, SigningMode, SourceMode,
    canonical_request_sha256,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    transport::{
        BranchName, CommitSha, GhExecutionError, GhRunner, GithubTransport, PollPolicy, Repository,
        RunConclusion, RunEvent, RunHandle, RunSnapshot, RunStatus, TemporaryGitRef,
        TransportError,
    },
    workflow::{
        GeneratedWorkflow, MAX_SIGNING_PROFILES, TrustedSourceRef, WorkflowConfig,
        generate_workflow,
    },
};

/// Stable provider identifier exposed through the remote-build protocol.
pub const GITHUB_PROVIDER_ID: &str = "github-actions";
/// Strict request file consumed by the generated workflow.
pub const DISPATCH_MANIFEST_PATH: &str = ".rustferry/goal3/request.json";

const DISPATCH_MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAX_JOB_RECORDS: usize = 1_024;
const MAX_JOB_EVENTS: usize = 64;
const MAX_DISPATCH_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;
const MAX_GIT_TIMEOUT: Duration = Duration::from_mins(10);
const GIT_AMBIENT_ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "GH_CONFIG_DIR",
    "PATH",
    "PATHEXT",
    "SSH_AUTH_SOCK",
    "SYSTEMROOT",
    "WINDIR",
    "TMPDIR",
    "TMP",
    "TEMP",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// A validated lowercase SHA-256 digest of the exact generated workflow bytes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowFingerprint(String);

impl WorkflowFingerprint {
    /// Validate a lowercase 64-character SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Rejects uppercase, abbreviated, or non-hexadecimal values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubProviderConfigError> {
        let value = value.into();
        if !is_lower_sha256(&value) {
            return Err(GithubProviderConfigError::InvalidWorkflowFingerprint);
        }
        Ok(Self(value))
    }

    /// Digest text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compute the fingerprint for one generated workflow.
    pub fn for_workflow(workflow: &GeneratedWorkflow) -> Self {
        Self(hex_sha256(workflow.yaml().as_bytes()))
    }
}

/// Explicit caller authority for externally mutating GitHub state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubMutationAuthorization {
    /// Permit one create-only push below the configured temporary namespace.
    pub publish_temporary_ref: bool,
    /// Permit cancellation of the exact mapped GitHub Actions run.
    pub cancel_run: bool,
    /// Permit deletion of the exact provider-created temporary branch.
    pub delete_temporary_ref: bool,
}

/// One bounded policy shared by run discovery and terminal-run polling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubPollingPolicy {
    transport: PollPolicy,
    discovery_attempts: u16,
    discovery_window_ms: u64,
}

impl GithubPollingPolicy {
    /// Construct a policy using the same attempt count and interval for discovery and polling.
    ///
    /// # Errors
    ///
    /// Returns the transport's typed configuration error for attempts outside 1–2000 or an
    /// interval outside 250 milliseconds through 60 seconds.
    pub fn new(
        attempts: u16,
        interval: Duration,
    ) -> Result<Self, crate::transport::TransportConfigError> {
        let transport = PollPolicy::new(attempts, interval)?;
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let discovery_window_ms = interval_ms.saturating_mul(u64::from(attempts));
        Ok(Self {
            transport,
            discovery_attempts: attempts,
            discovery_window_ms,
        })
    }

    /// Five-second checks bounded to 1,440 attempts and two hours.
    ///
    /// # Panics
    ///
    /// Panics only if these compile-time constants stop satisfying `PollPolicy` invariants.
    pub fn secure_defaults() -> Self {
        Self::new(1_440, Duration::from_secs(5)).expect("constant polling policy is valid")
    }

    /// Transport policy used after exact run mapping.
    pub const fn transport(self) -> PollPolicy {
        self.transport
    }

    /// Maximum exact run-discovery attempts.
    pub const fn discovery_attempts(self) -> u16 {
        self.discovery_attempts
    }

    /// Maximum wall-clock run-discovery window.
    pub const fn discovery_window_ms(self) -> u64 {
        self.discovery_window_ms
    }
}

/// Invalid security-sensitive GitHub provider configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubProviderConfigError {
    /// Expected workflow fingerprint was malformed.
    InvalidWorkflowFingerprint,
    /// Generated workflow bytes did not match the approved fingerprint.
    WorkflowFingerprintMismatch,
    /// The configured source repository was not the workflow's canonical public source URL.
    InvalidSourceRepository,
    /// The in-memory job bound was outside 1–1024.
    InvalidJobLimit,
    /// Worker distribution version was not semantic-version syntax.
    InvalidWorkerVersion,
    /// Handshake worker version differed from the hash-pinned workflow worker.
    WorkerVersionMismatch,
}

impl fmt::Display for GithubProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWorkflowFingerprint => {
                formatter.write_str("workflow fingerprint must be lowercase SHA-256")
            }
            Self::WorkflowFingerprintMismatch => {
                formatter.write_str("generated workflow does not match its approved fingerprint")
            }
            Self::InvalidSourceRepository => {
                formatter.write_str("source repository does not match the workflow public source")
            }
            Self::InvalidJobLimit => formatter.write_str("job limit must be between 1 and 1024"),
            Self::InvalidWorkerVersion => {
                formatter.write_str("workflow worker version must be semantic-version syntax")
            }
            Self::WorkerVersionMismatch => {
                formatter.write_str("handshake worker version does not match workflow distribution")
            }
        }
    }
}

impl Error for GithubProviderConfigError {}

/// Fully validated GitHub orchestration policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderConfig {
    repository: Repository,
    source_repository: String,
    workflow: WorkflowConfig,
    workflow_fingerprint: WorkflowFingerprint,
    poll_policy: GithubPollingPolicy,
    mutation_authorization: GithubMutationAuthorization,
    worker_version: Version,
    max_jobs: usize,
}

impl GithubProviderConfig {
    /// Bind repository, workflow identity, immutable content, and mutation policy.
    ///
    /// # Errors
    ///
    /// Rejects a source identity mismatch, fingerprint mismatch, worker-version mismatch, or
    /// invalid job bound. The GitHub repository is the execution repository; the source URL may
    /// identify a distinct repository.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: Repository,
        source_repository: impl Into<String>,
        workflow: WorkflowConfig,
        workflow_fingerprint: WorkflowFingerprint,
        poll_policy: GithubPollingPolicy,
        mutation_authorization: GithubMutationAuthorization,
        worker_version: &Version,
        max_jobs: usize,
    ) -> Result<Self, GithubProviderConfigError> {
        if !(1..=MAX_JOB_RECORDS).contains(&max_jobs) {
            return Err(GithubProviderConfigError::InvalidJobLimit);
        }
        let source_repository = source_repository.into();
        if source_repository != workflow.public_source_repository().url() {
            return Err(GithubProviderConfigError::InvalidSourceRepository);
        }
        let generated = generate_workflow(&workflow);
        if WorkflowFingerprint::for_workflow(&generated) != workflow_fingerprint {
            return Err(GithubProviderConfigError::WorkflowFingerprintMismatch);
        }
        let distribution_worker_version = Version::parse(workflow.worker().version())
            .map_err(|_| GithubProviderConfigError::InvalidWorkerVersion)?;
        if *worker_version != distribution_worker_version {
            return Err(GithubProviderConfigError::WorkerVersionMismatch);
        }
        Ok(Self {
            repository,
            source_repository,
            workflow,
            workflow_fingerprint,
            poll_policy,
            mutation_authorization,
            worker_version: distribution_worker_version,
            max_jobs,
        })
    }

    /// Exact GitHub Actions execution repository.
    pub fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Normalized source repository URL accepted in Git requests.
    pub fn source_repository(&self) -> &str {
        &self.source_repository
    }

    /// Approved workflow configuration.
    pub fn workflow(&self) -> &WorkflowConfig {
        &self.workflow
    }

    /// Approved exact workflow digest.
    pub fn workflow_fingerprint(&self) -> &WorkflowFingerprint {
        &self.workflow_fingerprint
    }

    /// Bounded run polling policy retained for explicit terminal waits.
    pub const fn poll_policy(&self) -> PollPolicy {
        self.poll_policy.transport()
    }

    /// External mutation authority captured from the caller.
    pub const fn mutation_authorization(&self) -> GithubMutationAuthorization {
        self.mutation_authorization
    }
}

/// Strict immutable request committed to the temporary dispatch ref.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubDispatchManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Stable provider identifier.
    pub provider: String,
    /// Exact GitHub Actions execution repository.
    pub execution_repository: String,
    /// Exact normalized GitHub source repository.
    pub source_repository: String,
    /// Exact trusted branch or tag containing the source revision.
    pub trusted_source_ref: String,
    /// Exact provider-created full temporary branch ref.
    pub temporary_ref: String,
    /// Repository-relative generated workflow path.
    pub workflow_path: String,
    /// Approved SHA-256 of the generated workflow bytes.
    pub workflow_sha256: String,
    /// Complete declarative physical-iPhone build request.
    pub request: IosDeviceBuildRequest,
}

impl GithubDispatchManifest {
    fn new(
        config: &GithubProviderConfig,
        temporary_ref: &TemporaryGitRef,
        request: IosDeviceBuildRequest,
    ) -> Self {
        Self {
            schema_version: DISPATCH_MANIFEST_SCHEMA_VERSION,
            provider: GITHUB_PROVIDER_ID.to_owned(),
            execution_repository: repository_url(&config.repository),
            source_repository: config.source_repository.clone(),
            trusted_source_ref: config.workflow.trusted_source_ref().as_str().to_owned(),
            temporary_ref: format!("refs/heads/{}", temporary_ref.branch().as_str()),
            workflow_path: config.workflow.filename().repository_path(),
            workflow_sha256: config.workflow_fingerprint.as_str().to_owned(),
            request,
        }
    }

    /// Validate all duplicated identity fields and the nested build request.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol failure when any identity binding differs.
    pub fn validate_for(&self, config: &GithubProviderConfig) -> RemoteBuildResult<()> {
        if self.schema_version != DISPATCH_MANIFEST_SCHEMA_VERSION
            || self.provider != GITHUB_PROVIDER_ID
            || !github_remote_matches(
                &self.execution_repository,
                &repository_url(&config.repository),
            )
            || self.source_repository != config.source_repository
            || self.trusted_source_ref != config.workflow.trusted_source_ref().as_str()
            || self.workflow_path != config.workflow.filename().repository_path()
            || self.workflow_sha256 != config.workflow_fingerprint.as_str()
            || self.temporary_ref
                != format!(
                    "refs/heads/{}/{}",
                    config.workflow.temporary_branch_namespace().as_str(),
                    self.request.operation_id
                )
        {
            return Err(provider_failure(
                "dispatch_manifest_identity_mismatch",
                "dispatch manifest identity does not match provider configuration",
                false,
            ));
        }
        self.request.validate()?;
        if self.request.source_mode != SourceMode::Git
            || self.request.source_repository.as_deref() != Some(config.source_repository())
        {
            return Err(provider_failure(
                "unsupported_source_request",
                "GitHub provider requires its exact configured Git source repository",
                false,
            ));
        }
        Ok(())
    }

    fn encode(&self) -> RemoteBuildResult<Vec<u8>> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| RemoteBuildError::Serialization {
                message: bounded_message(&error.to_string()),
            })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_DISPATCH_FILE_BYTES {
            return Err(provider_failure(
                "dispatch_manifest_too_large",
                "dispatch manifest exceeds provider size policy",
                false,
            ));
        }
        Ok(bytes)
    }
}

/// Read-only inputs supplied to one temporary-ref publication.
pub struct TemporaryRefPublishRequest<'a> {
    /// Exact GitHub repository.
    pub repository: &'a Repository,
    /// Normalized HTTPS repository URL.
    pub source_repository: &'a str,
    /// Trusted branch or tag containing the source revision.
    pub trusted_source_ref: &'a TrustedSourceRef,
    /// Exact source commit selected by the caller.
    pub source_revision: &'a CommitSha,
    /// Create-only target below the configured temporary namespace.
    pub temporary_ref: &'a TemporaryGitRef,
    /// Repository-relative approved workflow path.
    pub workflow_path: &'a str,
    /// Approved workflow bytes.
    pub workflow_bytes: &'a [u8],
    /// Approved workflow digest.
    pub workflow_fingerprint: &'a WorkflowFingerprint,
    /// Strict request-manifest bytes.
    pub manifest_bytes: &'a [u8],
    /// Safe operation identifier used for local isolation.
    pub operation_id: &'a str,
    /// Milliseconds since Unix epoch, used for deterministic commit metadata.
    pub created_at_ms: u64,
    /// Explicit caller authorization for this push.
    pub authorized: bool,
}

/// Verified publisher readiness for the exact configured remote and trusted ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryRefPublisherReadiness {
    /// Remote tip currently advertised for the trusted ref.
    pub trusted_ref_tip: CommitSha,
}

/// Exact immutable inputs for local trusted-workflow bootstrap verification.
pub struct TemporaryRefDoctorRequest<'a> {
    /// Exact GitHub repository.
    pub repository: &'a Repository,
    /// Normalized HTTPS repository URL.
    pub source_repository: &'a str,
    /// Trusted source branch or tag.
    pub trusted_source_ref: &'a TrustedSourceRef,
    /// Repository-relative approved workflow path.
    pub workflow_path: &'a str,
    /// Approved workflow SHA-256.
    pub workflow_fingerprint: &'a WorkflowFingerprint,
}

/// Exact inputs for one lease-protected temporary-ref deletion.
pub struct TemporaryRefDeleteRequest<'a> {
    /// Exact GitHub repository.
    pub repository: &'a Repository,
    /// Normalized HTTPS repository URL.
    pub source_repository: &'a str,
    /// Provider-created full temporary branch.
    pub temporary_ref: &'a TemporaryGitRef,
    /// Only remote tip permitted to be deleted.
    pub expected_commit: &'a CommitSha,
    /// Explicit caller authorization for this deletion.
    pub authorized: bool,
}

/// Result of one create-only temporary-ref publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedTemporaryRef {
    temporary_ref: TemporaryGitRef,
    commit: CommitSha,
}

impl PublishedTemporaryRef {
    /// Construct publication evidence returned by an alternate publisher.
    pub fn new(temporary_ref: TemporaryGitRef, commit: CommitSha) -> Self {
        Self {
            temporary_ref,
            commit,
        }
    }

    /// Exact temporary branch.
    pub fn temporary_ref(&self) -> &TemporaryGitRef {
        &self.temporary_ref
    }

    /// Exact published dispatch commit.
    pub fn commit(&self) -> &CommitSha {
        &self.commit
    }
}

/// Redacted temporary-ref publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporaryRefPublishError {
    /// Caller did not explicitly authorize a temporary-ref mutation.
    Unauthorized,
    /// Local repository remote differs from the configured GitHub repository.
    RemoteMismatch,
    /// Trusted source ref was absent or malformed.
    TrustedRefUnavailable,
    /// Requested source commit was not reachable from the trusted ref.
    SourceRevisionNotTrusted,
    /// Exact temporary branch already existed remotely.
    TemporaryRefExists,
    /// Workflow bytes differed from the approved fingerprint.
    WorkflowFingerprintMismatch,
    /// A bounded local isolation file could not be reserved or removed.
    LocalIsolationFailed,
    /// Git failed without exposing its output.
    Git(GitExecutionError),
    /// Git returned malformed object or ref metadata.
    MalformedGitOutput,
    /// Push completed without exact remote-ref confirmation.
    PublicationVerificationFailed,
    /// Atomic deletion lease was rejected because the remote ref changed.
    TemporaryRefLeaseRejected,
    /// Lease-protected deletion completed without exact absence confirmation.
    DeletionVerificationFailed,
}

impl fmt::Display for TemporaryRefPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("temporary-ref mutation is not authorized"),
            Self::RemoteMismatch => formatter.write_str("Git remote does not match configuration"),
            Self::TrustedRefUnavailable => formatter.write_str("trusted source ref is unavailable"),
            Self::SourceRevisionNotTrusted => {
                formatter.write_str("source revision is not reachable from trusted source ref")
            }
            Self::TemporaryRefExists => formatter.write_str("temporary ref already exists"),
            Self::WorkflowFingerprintMismatch => {
                formatter.write_str("workflow bytes do not match approved fingerprint")
            }
            Self::LocalIsolationFailed => formatter.write_str("local Git isolation failed"),
            Self::Git(error) => error.fmt(formatter),
            Self::MalformedGitOutput => formatter.write_str("Git returned malformed metadata"),
            Self::PublicationVerificationFailed => {
                formatter.write_str("published ref failed exact verification")
            }
            Self::TemporaryRefLeaseRejected => {
                formatter.write_str("temporary ref changed before lease-protected deletion")
            }
            Self::DeletionVerificationFailed => {
                formatter.write_str("deleted ref failed exact absence verification")
            }
        }
    }
}

impl Error for TemporaryRefPublishError {}

impl From<GitExecutionError> for TemporaryRefPublishError {
    fn from(value: GitExecutionError) -> Self {
        Self::Git(value)
    }
}

/// Publication error plus exact cleanup ownership when a push may have succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryRefPublishFailure {
    error: TemporaryRefPublishError,
    possible_publication: Option<PublishedTemporaryRef>,
}

impl TemporaryRefPublishFailure {
    fn uncertain(error: TemporaryRefPublishError, publication: PublishedTemporaryRef) -> Self {
        Self {
            error,
            possible_publication: Some(publication),
        }
    }

    /// Redacted failure category.
    pub const fn error(&self) -> TemporaryRefPublishError {
        self.error
    }

    /// Exact ref and commit that may now exist remotely.
    pub fn possible_publication(&self) -> Option<&PublishedTemporaryRef> {
        self.possible_publication.as_ref()
    }
}

impl From<TemporaryRefPublishError> for TemporaryRefPublishFailure {
    fn from(error: TemporaryRefPublishError) -> Self {
        Self {
            error,
            possible_publication: None,
        }
    }
}

/// Injectable publication boundary used by the provider.
pub trait TemporaryRefPublisher: Send {
    /// Verify local Git and exact remote/trusted-ref readiness without mutation.
    ///
    /// # Errors
    ///
    /// Returns a redacted readiness error when remote identity, trusted-ref availability, or
    /// approved workflow bytes cannot be verified exactly.
    fn doctor(
        &mut self,
        request: &TemporaryRefDoctorRequest<'_>,
    ) -> Result<TemporaryRefPublisherReadiness, TemporaryRefPublishError>;

    /// Create and push one exact temporary dispatch ref.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure and, after a possibly mutating push, exact cleanup ownership.
    fn publish(
        &mut self,
        request: &TemporaryRefPublishRequest<'_>,
    ) -> Result<PublishedTemporaryRef, TemporaryRefPublishFailure>;

    /// Delete one provider-owned temporary ref with an exact expected-tip lease.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure when the lease is rejected or exact deletion cannot be verified.
    fn delete_temporary_ref(
        &mut self,
        request: &TemporaryRefDeleteRequest<'_>,
    ) -> Result<(), TemporaryRefPublishError>;
}

/// Fixed Git argument vector plus optional bounded stdin.
pub struct GitInvocation {
    arguments: Vec<OsString>,
    stdin: Vec<u8>,
    environment: Vec<(OsString, OsString)>,
    timeout: Duration,
}

impl GitInvocation {
    fn new(arguments: impl IntoIterator<Item = impl Into<OsString>>, timeout: Duration) -> Self {
        Self {
            arguments: arguments.into_iter().map(Into::into).collect(),
            stdin: Vec::new(),
            environment: Vec::new(),
            timeout,
        }
    }

    fn with_stdin(mut self, stdin: &[u8]) -> Self {
        self.stdin.extend_from_slice(stdin);
        self
    }

    fn with_environment(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }

    /// Exact arguments after the `git` executable.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Number of stdin bytes, without exposing their content.
    pub const fn stdin_len(&self) -> usize {
        self.stdin.len()
    }

    /// Explicit non-secret environment overrides.
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    /// Process deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Debug for GitInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitInvocation")
            .field("arguments", &self.arguments)
            .field("stdin_len", &self.stdin.len())
            .field(
                "environment_names",
                &self
                    .environment
                    .iter()
                    .map(|pair| &pair.0)
                    .collect::<Vec<_>>(),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Redacted fixed-argv Git execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitExecutionError {
    /// Git process could not be started.
    SpawnFailed,
    /// Git process exceeded its deadline and was terminated.
    TimedOut,
    /// Process pipes or waiting failed.
    ProcessIo,
    /// Captured output exceeded its bound.
    OutputLimitExceeded,
    /// Git exited unsuccessfully; output is deliberately discarded.
    CommandFailed {
        /// Exit code when available.
        exit_code: Option<i32>,
    },
}

impl fmt::Display for GitExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpawnFailed => formatter.write_str("failed to start Git"),
            Self::TimedOut => formatter.write_str("Git operation timed out"),
            Self::ProcessIo => formatter.write_str("Git process I/O failed"),
            Self::OutputLimitExceeded => formatter.write_str("Git output exceeded its limit"),
            Self::CommandFailed {
                exit_code: Some(code),
            } => {
                write!(formatter, "Git operation failed with status {code}")
            }
            Self::CommandFailed { exit_code: None } => formatter.write_str("Git operation failed"),
        }
    }
}

impl Error for GitExecutionError {}

/// Injectable fixed-argv Git executor.
pub trait GitRunner: Send {
    /// Execute one bounded invocation.
    ///
    /// # Errors
    ///
    /// Returns a redacted process, I/O, timeout, output-limit, or exit-status failure.
    fn execute(&mut self, invocation: &GitInvocation) -> Result<Vec<u8>, GitExecutionError>;
}

/// Production Git executor rooted at one canonical repository checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitProcessRunner {
    executable: PathBuf,
    repository_root: PathBuf,
}

impl GitProcessRunner {
    /// Validate the Git executable and repository root paths.
    ///
    /// # Errors
    ///
    /// Rejects relative, missing, or unsuitable paths.
    pub fn new(
        executable: impl AsRef<Path>,
        repository_root: impl AsRef<Path>,
    ) -> Result<Self, GitPublisherConfigError> {
        let executable = canonical_file(executable.as_ref())?;
        if !executable_basename_matches(&executable, "git") {
            return Err(GitPublisherConfigError::InvalidGitExecutable);
        }
        let repository_root = canonical_directory(repository_root.as_ref())?;
        Ok(Self {
            executable,
            repository_root,
        })
    }
}

impl GitRunner for GitProcessRunner {
    fn execute(&mut self, invocation: &GitInvocation) -> Result<Vec<u8>, GitExecutionError> {
        let mut command = Command::new(&self.executable);
        apply_allowlisted_git_environment(&mut command);
        command
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("protocol.file.allow=never")
            .arg("-c")
            .arg("credential.interactive=never")
            .args(&invocation.arguments)
            .current_dir(&self.repository_root)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &invocation.environment {
            command.env(name, value);
        }
        run_git_process(command, &invocation.stdin, invocation.timeout)
    }
}

/// Invalid local Git publisher configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitPublisherConfigError {
    /// Git executable was not a canonical executable file named `git`.
    InvalidGitExecutable,
    /// Repository or isolation directory was not canonical and usable.
    InvalidDirectory,
    /// Remote name contained option, ref, or path syntax.
    InvalidRemoteName,
    /// Timeout was zero or exceeded ten minutes.
    InvalidTimeout,
}

impl fmt::Display for GitPublisherConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGitExecutable => formatter.write_str("Git executable is invalid"),
            Self::InvalidDirectory => formatter.write_str("Git publisher directory is invalid"),
            Self::InvalidRemoteName => formatter.write_str("Git remote name is invalid"),
            Self::InvalidTimeout => formatter.write_str("Git operation timeout is invalid"),
        }
    }
}

impl Error for GitPublisherConfigError {}

/// Git-plumbing implementation that publishes without checkout or branch mutation.
#[derive(Debug)]
pub struct GitTemporaryRefPublisher<R> {
    runner: R,
    isolation_directory: PathBuf,
    source_remote_name: String,
    execution_remote_name: String,
    timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedGitRemote {
    fetch_url: String,
    push_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPublisherRemotes {
    source: VerifiedGitRemote,
    execution: VerifiedGitRemote,
}

impl<R> GitTemporaryRefPublisher<R> {
    /// Bind a runner to a canonical isolation directory and conservative source/execution remotes.
    ///
    /// # Errors
    ///
    /// Rejects symlink-final/non-canonical directories, unsafe remote names, and invalid timeouts.
    pub fn new(
        runner: R,
        isolation_directory: impl AsRef<Path>,
        source_remote_name: impl Into<String>,
        execution_remote_name: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, GitPublisherConfigError> {
        let isolation_directory = canonical_directory(isolation_directory.as_ref())?;
        let source_remote_name = source_remote_name.into();
        let execution_remote_name = execution_remote_name.into();
        if !is_safe_remote_name(&source_remote_name) || !is_safe_remote_name(&execution_remote_name)
        {
            return Err(GitPublisherConfigError::InvalidRemoteName);
        }
        if timeout.is_zero() || timeout > MAX_GIT_TIMEOUT {
            return Err(GitPublisherConfigError::InvalidTimeout);
        }
        Ok(Self {
            runner,
            isolation_directory,
            source_remote_name,
            execution_remote_name,
            timeout,
        })
    }

    /// Recover the runner, including captured invocations in tests.
    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: GitRunner> GitTemporaryRefPublisher<R> {
    fn execute(
        &mut self,
        arguments: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Result<Vec<u8>, TemporaryRefPublishError> {
        self.runner
            .execute(&GitInvocation::new(arguments, self.timeout))
            .map_err(Into::into)
    }

    fn execute_invocation(
        &mut self,
        invocation: &GitInvocation,
    ) -> Result<Vec<u8>, TemporaryRefPublishError> {
        self.runner.execute(invocation).map_err(Into::into)
    }

    fn verify_remote(
        &mut self,
        remote_name: &str,
        expected_repository: &str,
    ) -> Result<VerifiedGitRemote, TemporaryRefPublishError> {
        let fetch_output = self.execute(["remote", "get-url", remote_name])?;
        let fetch_url = parse_single_line(&fetch_output)?.to_owned();
        let push_output = self.execute(["remote", "get-url", "--push", remote_name])?;
        let push_url = parse_single_line(&push_output)?.to_owned();
        if !github_remote_matches(&fetch_url, expected_repository)
            || !github_remote_matches(&push_url, expected_repository)
        {
            return Err(TemporaryRefPublishError::RemoteMismatch);
        }
        Ok(VerifiedGitRemote {
            fetch_url,
            push_url,
        })
    }

    fn remote_ref(
        &mut self,
        remote_url: &str,
        full_ref: &str,
    ) -> Result<Option<CommitSha>, TemporaryRefPublishError> {
        let output = self.execute(["ls-remote", "--refs", remote_url, full_ref])?;
        parse_ls_remote(&output, full_ref)
    }

    fn doctor_with_remote(
        &mut self,
        request: &TemporaryRefDoctorRequest<'_>,
    ) -> Result<(TemporaryRefPublisherReadiness, VerifiedPublisherRemotes), TemporaryRefPublishError>
    {
        validate_repository_path(request.workflow_path)
            .map_err(|()| TemporaryRefPublishError::MalformedGitOutput)?;
        let source_remote_name = self.source_remote_name.clone();
        let execution_remote_name = self.execution_remote_name.clone();
        let source = self.verify_remote(&source_remote_name, request.source_repository)?;
        let execution_repository = repository_url(request.repository);
        let execution = if source_remote_name == execution_remote_name
            && github_remote_matches(request.source_repository, &execution_repository)
        {
            source.clone()
        } else {
            self.verify_remote(&execution_remote_name, &execution_repository)?
        };
        let tip = self
            .remote_ref(&source.fetch_url, request.trusted_source_ref.as_str())?
            .ok_or(TemporaryRefPublishError::TrustedRefUnavailable)?;
        self.execute([
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-write-fetch-head",
            &source.fetch_url,
            request.trusted_source_ref.as_str(),
        ])?;
        let trusted_workflow = self
            .execute([
                "show",
                &format!("{}:{}", tip.as_str(), request.workflow_path),
            ])
            .map_err(|_| TemporaryRefPublishError::WorkflowFingerprintMismatch)?;
        if WorkflowFingerprint::for_workflow_bytes(&trusted_workflow)
            != *request.workflow_fingerprint
        {
            return Err(TemporaryRefPublishError::WorkflowFingerprintMismatch);
        }
        Ok((
            TemporaryRefPublisherReadiness {
                trusted_ref_tip: tip,
            },
            VerifiedPublisherRemotes { source, execution },
        ))
    }

    fn index_invocation(
        &self,
        arguments: impl IntoIterator<Item = impl Into<OsString>>,
        index_path: &Path,
    ) -> GitInvocation {
        GitInvocation::new(arguments, self.timeout)
            .with_environment("GIT_INDEX_FILE", index_path.as_os_str())
    }

    fn hash_blob(&mut self, bytes: &[u8]) -> Result<String, TemporaryRefPublishError> {
        let invocation =
            GitInvocation::new(["hash-object", "-w", "--stdin"], self.timeout).with_stdin(bytes);
        parse_object_id(&self.execute_invocation(&invocation)?)
    }
}

impl<R: GitRunner> TemporaryRefPublisher for GitTemporaryRefPublisher<R> {
    fn doctor(
        &mut self,
        request: &TemporaryRefDoctorRequest<'_>,
    ) -> Result<TemporaryRefPublisherReadiness, TemporaryRefPublishError> {
        self.doctor_with_remote(request)
            .map(|(readiness, _)| readiness)
    }

    #[allow(clippy::too_many_lines)]
    fn publish(
        &mut self,
        request: &TemporaryRefPublishRequest<'_>,
    ) -> Result<PublishedTemporaryRef, TemporaryRefPublishFailure> {
        if !request.authorized {
            return Err(TemporaryRefPublishError::Unauthorized.into());
        }
        if request.workflow_bytes.len() > MAX_DISPATCH_FILE_BYTES
            || request.manifest_bytes.len() > MAX_DISPATCH_FILE_BYTES
            || WorkflowFingerprint::for_workflow_bytes(request.workflow_bytes)
                != *request.workflow_fingerprint
        {
            return Err(TemporaryRefPublishError::WorkflowFingerprintMismatch.into());
        }
        validate_repository_path(request.workflow_path)
            .map_err(|()| TemporaryRefPublishError::MalformedGitOutput)?;
        let (readiness, remotes) = self.doctor_with_remote(&TemporaryRefDoctorRequest {
            repository: request.repository,
            source_repository: request.source_repository,
            trusted_source_ref: request.trusted_source_ref,
            workflow_path: request.workflow_path,
            workflow_fingerprint: request.workflow_fingerprint,
        })?;
        self.execute([
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", request.source_revision.as_str()),
        ])
        .map_err(|_| TemporaryRefPublishError::SourceRevisionNotTrusted)?;
        self.execute([
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", readiness.trusted_ref_tip.as_str()),
        ])
        .map_err(|_| TemporaryRefPublishError::TrustedRefUnavailable)?;
        self.execute([
            "merge-base",
            "--is-ancestor",
            request.source_revision.as_str(),
            readiness.trusted_ref_tip.as_str(),
        ])
        .map_err(|_| TemporaryRefPublishError::SourceRevisionNotTrusted)?;

        let full_temporary_ref = format!("refs/heads/{}", request.temporary_ref.branch().as_str());
        if self
            .remote_ref(&remotes.execution.fetch_url, &full_temporary_ref)?
            .is_some()
        {
            return Err(TemporaryRefPublishError::TemporaryRefExists.into());
        }

        let mut reservation =
            IndexReservation::create(&self.isolation_directory, request.operation_id)?;
        let index_path = reservation.index_path().to_path_buf();
        let workflow_blob = self.hash_blob(request.workflow_bytes)?;
        let manifest_blob = self.hash_blob(request.manifest_bytes)?;
        self.execute_invocation(&self.index_invocation(
            [
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &workflow_blob,
                request.workflow_path,
            ],
            &index_path,
        ))?;
        self.execute_invocation(&self.index_invocation(
            [
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &manifest_blob,
                DISPATCH_MANIFEST_PATH,
            ],
            &index_path,
        ))?;
        let tree = parse_object_id(
            &self.execute_invocation(&self.index_invocation(["write-tree"], &index_path))?,
        )?;
        let commit_message = format!(
            "RustFerry temporary iPhone build {}\n",
            request.operation_id
        );
        let git_date = format!("@{} +0000", request.created_at_ms / 1_000);
        let commit_invocation = GitInvocation::new(["commit-tree", &tree], self.timeout)
            .with_stdin(commit_message.as_bytes())
            .with_environment("GIT_AUTHOR_NAME", "ShiroKSH")
            .with_environment("GIT_AUTHOR_EMAIL", "kushidashiro@gmail.com")
            .with_environment("GIT_COMMITTER_NAME", "ShiroKSH")
            .with_environment("GIT_COMMITTER_EMAIL", "kushidashiro@gmail.com")
            .with_environment("GIT_AUTHOR_DATE", &git_date)
            .with_environment("GIT_COMMITTER_DATE", &git_date);
        let commit = CommitSha::new(parse_object_id(
            &self.execute_invocation(&commit_invocation)?,
        )?)
        .map_err(|_| TemporaryRefPublishError::MalformedGitOutput)?;
        reservation.finish()?;

        let lease = format!("--force-with-lease={full_temporary_ref}:");
        let refspec = format!("{}:{full_temporary_ref}", commit.as_str());
        let publication = PublishedTemporaryRef::new(request.temporary_ref.clone(), commit.clone());
        if let Err(error) = self.execute([
            "push",
            "--porcelain",
            "--no-verify",
            "--atomic",
            &lease,
            &remotes.execution.push_url,
            &refspec,
        ]) {
            return Err(TemporaryRefPublishFailure::uncertain(error, publication));
        }
        let confirmed = self
            .remote_ref(&remotes.execution.fetch_url, &full_temporary_ref)
            .map_err(|error| TemporaryRefPublishFailure::uncertain(error, publication.clone()))?;
        if confirmed.as_ref() != Some(&commit) {
            return Err(TemporaryRefPublishFailure::uncertain(
                TemporaryRefPublishError::PublicationVerificationFailed,
                publication,
            ));
        }
        Ok(publication)
    }

    fn delete_temporary_ref(
        &mut self,
        request: &TemporaryRefDeleteRequest<'_>,
    ) -> Result<(), TemporaryRefPublishError> {
        if !request.authorized {
            return Err(TemporaryRefPublishError::Unauthorized);
        }
        let execution_remote_name = self.execution_remote_name.clone();
        let remote =
            self.verify_remote(&execution_remote_name, &repository_url(request.repository))?;
        let full_ref = format!("refs/heads/{}", request.temporary_ref.branch().as_str());
        let lease = format!(
            "--force-with-lease={full_ref}:{}",
            request.expected_commit.as_str()
        );
        let delete_refspec = format!(":{full_ref}");
        let deletion = self.execute([
            "push",
            "--porcelain",
            "--no-verify",
            "--atomic",
            &lease,
            &remote.push_url,
            &delete_refspec,
        ]);
        match deletion {
            Ok(_) => match self.remote_ref(&remote.fetch_url, &full_ref)? {
                None => Ok(()),
                Some(_) => Err(TemporaryRefPublishError::DeletionVerificationFailed),
            },
            Err(push_error) => match self.remote_ref(&remote.fetch_url, &full_ref) {
                Ok(None) => Ok(()),
                Ok(Some(current)) if current != *request.expected_commit => {
                    Err(TemporaryRefPublishError::TemporaryRefLeaseRejected)
                }
                Ok(Some(_)) | Err(_) => Err(push_error),
            },
        }
    }
}

impl WorkflowFingerprint {
    fn for_workflow_bytes(bytes: &[u8]) -> Self {
        Self(hex_sha256(bytes))
    }
}

struct IndexReservation {
    lock_path: PathBuf,
    index_path: PathBuf,
    finished: bool,
}

impl IndexReservation {
    fn create(directory: &Path, operation_id: &str) -> Result<Self, TemporaryRefPublishError> {
        validate_ref_segment(operation_id)
            .map_err(|()| TemporaryRefPublishError::LocalIsolationFailed)?;
        let lock_path = directory.join(format!("{operation_id}.lock"));
        let index_path = directory.join(format!("{operation_id}.index"));
        if index_path.exists() {
            return Err(TemporaryRefPublishError::LocalIsolationFailed);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(&lock_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| TemporaryRefPublishError::LocalIsolationFailed)?;
        Ok(Self {
            lock_path,
            index_path,
            finished: false,
        })
    }

    fn index_path(&self) -> &Path {
        &self.index_path
    }

    fn finish(&mut self) -> Result<(), TemporaryRefPublishError> {
        self.cleanup()?;
        self.finished = true;
        Ok(())
    }

    fn cleanup(&self) -> Result<(), TemporaryRefPublishError> {
        remove_exact_file_if_present(&self.index_path)?;
        remove_exact_file_if_present(&self.lock_path)
    }
}

impl Drop for IndexReservation {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}

/// Exact provider/run identity exposed to an independent artifact verifier.
#[derive(Clone, Debug, PartialEq)]
pub struct GithubArtifactContext {
    /// Provider job identifier.
    pub job_id: String,
    /// Caller operation identifier.
    pub operation_id: String,
    /// Exact GitHub Actions execution repository used for run and artifact APIs.
    pub repository: Repository,
    /// Exact mapped run.
    pub run: RunSnapshot,
    /// Exact configured source repository URL bound to the request provenance.
    pub source_repository: String,
    /// Exact source revision.
    pub source_revision: CommitSha,
    /// Exact temporary-ref commit dispatched to GitHub Actions.
    pub dispatch_revision: CommitSha,
    /// Canonical declarative request submitted for this job.
    pub request: IosDeviceBuildRequest,
    /// Lowercase SHA-256 of canonical compact request JSON.
    pub request_sha256: String,
}

/// Injectable independent artifact ingestion and verification seam.
pub trait VerifiedArtifactStore: Send {
    /// Whether verified manifest enumeration is implemented.
    fn supports_listing(&self) -> bool;
    /// Whether verified no-clobber download is implemented.
    fn supports_download(&self) -> bool;
    /// Whether exact retained-artifact deletion is implemented.
    fn supports_removal(&self) -> bool;

    /// Return only independently verified manifests, or an empty vector while pending.
    ///
    /// # Errors
    ///
    /// Returns a typed verification or provider failure; unverified manifests must not be returned.
    fn list_verified(
        &mut self,
        context: &GithubArtifactContext,
    ) -> RemoteBuildResult<Vec<ArtifactManifest>>;

    /// Download and independently verify one exact manifest artifact.
    ///
    /// # Errors
    ///
    /// Returns a typed download, identity, or integrity failure.
    fn download_verified(
        &mut self,
        context: &GithubArtifactContext,
        request: &ArtifactDownloadRequest,
    ) -> RemoteBuildResult<ArtifactDownloadResult>;

    /// Delete only artifacts owned by the exact mapped run.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when exact ownership cannot be established or deletion fails.
    fn remove_artifacts(&mut self, context: &GithubArtifactContext) -> RemoteBuildResult<()>;
}

/// Artifact store used when verified ingestion is not configured.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoVerifiedArtifactStore;

impl VerifiedArtifactStore for NoVerifiedArtifactStore {
    fn supports_listing(&self) -> bool {
        false
    }

    fn supports_download(&self) -> bool {
        false
    }

    fn supports_removal(&self) -> bool {
        false
    }

    fn list_verified(
        &mut self,
        _context: &GithubArtifactContext,
    ) -> RemoteBuildResult<Vec<ArtifactManifest>> {
        Err(unsupported(ProviderFeature::ArtifactListing))
    }

    fn download_verified(
        &mut self,
        _context: &GithubArtifactContext,
        _request: &ArtifactDownloadRequest,
    ) -> RemoteBuildResult<ArtifactDownloadResult> {
        Err(unsupported(ProviderFeature::ArtifactDownload))
    }

    fn remove_artifacts(&mut self, _context: &GithubArtifactContext) -> RemoteBuildResult<()> {
        Err(provider_failure(
            "artifact_removal_unsupported",
            "verified artifact removal is not configured",
            false,
        ))
    }
}

/// Injectable UTC clock for deterministic protocol events.
pub trait ProviderClock: Send + Sync {
    /// Milliseconds since Unix epoch.
    fn now_ms(&self) -> u64;
}

/// Production wall clock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemProviderClock;

impl ProviderClock for SystemProviderClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
struct JobRecord {
    operation_id: String,
    job_id: String,
    source_revision: CommitSha,
    request: IosDeviceBuildRequest,
    request_sha256: String,
    temporary_ref: TemporaryGitRef,
    dispatch_commit: Option<CommitSha>,
    created_at_ms: u64,
    state: JobState,
    run: Option<RunHandle>,
    run_snapshot: Option<RunSnapshot>,
    cancellation_requested: bool,
    cancellation_dispatched: bool,
    temporary_ref_deleted: bool,
    verification_pending_event: bool,
    publication_uncertain: bool,
    run_discovery_attempts: u16,
    run_discovery_deadline_ms: u64,
    manifests: Vec<ArtifactManifest>,
    events: Vec<RemoteBuildEvent>,
}

#[derive(Debug, Default)]
struct ProviderState {
    jobs: BTreeMap<String, JobRecord>,
    reservations: BTreeSet<String>,
}

struct JobReservation<'a> {
    state: &'a Mutex<ProviderState>,
    job_id: String,
    active: bool,
}

impl<'a> JobReservation<'a> {
    fn acquire(
        state: &'a Mutex<ProviderState>,
        job_id: String,
        maximum: usize,
    ) -> RemoteBuildResult<Self> {
        let mut locked = lock_provider_state(state)?;
        if locked.reservations.contains(&job_id)
            || locked
                .jobs
                .get(&job_id)
                .is_some_and(|record| !record.state.is_terminal())
        {
            return Err(provider_failure(
                "duplicate_job_id",
                "operation already has a GitHub provider job",
                false,
            ));
        }
        if locked
            .jobs
            .get(&job_id)
            .is_some_and(|record| record.state.is_terminal())
        {
            locked.jobs.remove(&job_id);
        }
        if locked.jobs.len() + locked.reservations.len() >= maximum {
            let recyclable = locked
                .jobs
                .iter()
                .filter(|(_, record)| record.state.is_terminal())
                .min_by(|(left_id, left), (right_id, right)| {
                    left.created_at_ms
                        .cmp(&right.created_at_ms)
                        .then_with(|| left_id.cmp(right_id))
                })
                .map(|(candidate_id, _)| candidate_id.clone());
            if let Some(recyclable) = recyclable {
                locked.jobs.remove(&recyclable);
            } else {
                return Err(provider_failure(
                    "job_capacity_reached",
                    "GitHub provider reached its bounded in-memory job capacity",
                    true,
                ));
            }
        }
        locked.reservations.insert(job_id.clone());
        drop(locked);
        Ok(Self {
            state,
            job_id,
            active: true,
        })
    }

    fn insert_pending(mut self, record: JobRecord) -> RemoteBuildResult<PendingJobRecord<'a>> {
        let mut state = lock_provider_state(self.state)?;
        state.reservations.remove(&self.job_id);
        state.jobs.insert(self.job_id.clone(), record);
        self.active = false;
        drop(state);
        Ok(PendingJobRecord {
            state: self.state,
            job_id: self.job_id.clone(),
            retain: false,
        })
    }
}

impl Drop for JobReservation<'_> {
    fn drop(&mut self) {
        if self.active
            && let Ok(mut state) = self.state.lock()
        {
            state.reservations.remove(&self.job_id);
        }
    }
}

struct PendingJobRecord<'a> {
    state: &'a Mutex<ProviderState>,
    job_id: String,
    retain: bool,
}

impl PendingJobRecord<'_> {
    fn retain(mut self) {
        self.retain = true;
    }
}

impl Drop for PendingJobRecord<'_> {
    fn drop(&mut self) {
        if !self.retain
            && let Ok(mut state) = self.state.lock()
        {
            state.jobs.remove(&self.job_id);
        }
    }
}

/// Concrete GitHub Actions implementation of the runtime-neutral build-provider contract.
pub struct GithubBuildProvider<R, P, A = NoVerifiedArtifactStore, C = SystemProviderClock> {
    config: GithubProviderConfig,
    capabilities: ProviderCapabilities,
    transport: Mutex<GithubTransport<R>>,
    publisher: Mutex<P>,
    artifacts: Mutex<A>,
    clock: C,
    state: Mutex<ProviderState>,
}

impl<R, P> GithubBuildProvider<R, P, NoVerifiedArtifactStore, SystemProviderClock> {
    /// Construct the provider without artifact ingestion.
    ///
    /// Artifact listing/download capabilities remain false and GitHub success is reported as
    /// verification-pending, never as protocol success.
    pub fn new(config: GithubProviderConfig, transport: GithubTransport<R>, publisher: P) -> Self {
        Self::with_artifact_store_and_clock(
            config,
            transport,
            publisher,
            NoVerifiedArtifactStore,
            SystemProviderClock,
        )
    }
}

impl<R, P, A, C> GithubBuildProvider<R, P, A, C>
where
    A: VerifiedArtifactStore,
    C: ProviderClock,
{
    /// Construct with explicit verified artifact ingestion and clock.
    pub fn with_artifact_store_and_clock(
        config: GithubProviderConfig,
        transport: GithubTransport<R>,
        publisher: P,
        artifacts: A,
        clock: C,
    ) -> Self {
        let capabilities = provider_capabilities(&config, &artifacts);
        Self {
            config,
            capabilities,
            transport: Mutex::new(transport),
            publisher: Mutex::new(publisher),
            artifacts: Mutex::new(artifacts),
            clock,
            state: Mutex::new(ProviderState::default()),
        }
    }

    /// Explicitly poll one mapped run to terminal using the configured bounded policy.
    ///
    /// This does not synthesize protocol success; a later `events` call still requires verified
    /// artifact manifests. Cancellation is checked before and after the bounded transport poll.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure for an unknown/unmapped job or transport failure.
    pub fn wait_for_github_run(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> RemoteBuildResult<RunSnapshot>
    where
        R: GhRunner,
    {
        cancellation.check()?;
        let handle = {
            let state = self.lock_state()?;
            state
                .jobs
                .get(job_id)
                .and_then(|record| record.run.clone())
                .ok_or_else(|| job_not_mapped(job_id))?
        };
        let snapshot = self
            .lock_transport()?
            .wait_for_run(
                &self.config.repository,
                &handle,
                self.config.poll_policy.transport(),
            )
            .map_err(transport_failure)?;
        cancellation.check()?;
        Ok(snapshot)
    }

    fn lock_state(&self) -> RemoteBuildResult<std::sync::MutexGuard<'_, ProviderState>> {
        lock_provider_state(&self.state)
    }

    fn lock_transport(&self) -> RemoteBuildResult<std::sync::MutexGuard<'_, GithubTransport<R>>> {
        self.transport.lock().map_err(|_| {
            provider_failure(
                "transport_unavailable",
                "GitHub transport is unavailable",
                true,
            )
        })
    }

    fn lock_publisher(&self) -> RemoteBuildResult<std::sync::MutexGuard<'_, P>> {
        self.publisher.lock().map_err(|_| {
            provider_failure(
                "publisher_unavailable",
                "temporary-ref publisher is unavailable",
                true,
            )
        })
    }

    fn lock_artifacts(&self) -> RemoteBuildResult<std::sync::MutexGuard<'_, A>> {
        self.artifacts.lock().map_err(|_| {
            provider_failure(
                "artifact_store_unavailable",
                "verified artifact store is unavailable",
                true,
            )
        })
    }

    fn artifact_context(
        record: &JobRecord,
        config: &GithubProviderConfig,
    ) -> Option<GithubArtifactContext> {
        Some(GithubArtifactContext {
            job_id: record.job_id.clone(),
            operation_id: record.operation_id.clone(),
            repository: config.repository.clone(),
            run: record.run_snapshot.clone()?,
            source_repository: config.source_repository.clone(),
            source_revision: record.source_revision.clone(),
            dispatch_revision: record.dispatch_commit.clone()?,
            request: record.request.clone(),
            request_sha256: record.request_sha256.clone(),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn sync_job(&self, job_id: &str, cancellation: &CancellationToken) -> RemoteBuildResult<()>
    where
        R: GhRunner,
    {
        cancellation.check()?;
        let mut state = self.lock_state()?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| job_not_found(job_id))?;
        if record.state.is_build_terminal() || record.state.is_terminal() {
            return Ok(());
        }

        if record.run.is_none() {
            let Some(dispatch_commit) = record.dispatch_commit.as_ref() else {
                return Ok(());
            };
            let result = self.lock_transport()?.find_run(
                &self.config.repository,
                &self.config.workflow.filename().repository_path(),
                dispatch_commit,
                record.temporary_ref.branch(),
                RunEvent::Push,
            );
            match result {
                Ok(handle) => {
                    record.run = Some(handle);
                    append_event(
                        record,
                        self.clock.now_ms(),
                        "queue",
                        RemoteBuildEventKind::Progress {
                            message: "Exact GitHub Actions run mapped to this job".to_owned(),
                            current: None,
                            total: None,
                        },
                    )?;
                }
                Err(TransportError::RunNotFound) => {
                    record.run_discovery_attempts = record.run_discovery_attempts.saturating_add(1);
                    if record.run_discovery_attempts >= self.config.poll_policy.discovery_attempts()
                        || self.clock.now_ms() >= record.run_discovery_deadline_ms
                    {
                        ensure_running_or_cancelling(record)?;
                        transition_record(record, JobState::Failed)?;
                        append_event(
                            record,
                            self.clock.now_ms(),
                            "cleanup",
                            RemoteBuildEventKind::Warning {
                                code: "github.cleanup_required".to_owned(),
                                message: "Temporary Git ref cleanup is required after run discovery expired"
                                    .to_owned(),
                                help: Some(
                                    "Run provider cleanup for this exact job before retrying"
                                        .to_owned(),
                                ),
                            },
                        )?;
                        append_failed(
                            record,
                            self.clock.now_ms(),
                            "run_discovery_exhausted",
                            "Exact GitHub Actions run was not found within the bounded discovery policy",
                            true,
                        )?;
                    }
                    return Ok(());
                }
                Err(error) => return Err(transport_failure(error)),
            }
        }

        let handle = record.run.clone().ok_or_else(|| {
            provider_failure(
                "run_identity_unavailable",
                "GitHub run identity was unavailable after lookup",
                true,
            )
        })?;
        let snapshot = self
            .lock_transport()?
            .run(&self.config.repository, &handle)
            .map_err(transport_failure)?;
        record.run_snapshot = Some(snapshot.clone());

        if record.cancellation_requested
            && !record.cancellation_dispatched
            && !snapshot.status().is_terminal()
        {
            if !self.config.mutation_authorization.cancel_run {
                return Err(unsupported(ProviderFeature::Cancellation));
            }
            self.lock_transport()?
                .cancel_run(&self.config.repository, handle.id())
                .map_err(transport_failure)?;
            record.cancellation_dispatched = true;
        }

        match snapshot.status() {
            RunStatus::Requested | RunStatus::Queued | RunStatus::Pending | RunStatus::Waiting => {}
            RunStatus::InProgress => {
                if record.state == JobState::Queued {
                    transition_record(record, JobState::Running)?;
                    append_event(
                        record,
                        self.clock.now_ms(),
                        "remote-build",
                        RemoteBuildEventKind::PhaseStarted {
                            message: Some("GitHub macOS worker started".to_owned()),
                        },
                    )?;
                }
            }
            RunStatus::Completed => self.finish_from_snapshot(record, &snapshot)?,
        }
        cancellation.check()
    }

    fn finish_from_snapshot(
        &self,
        record: &mut JobRecord,
        snapshot: &RunSnapshot,
    ) -> RemoteBuildResult<()> {
        match snapshot.conclusion() {
            Some(RunConclusion::Cancelled) => {
                ensure_running_or_cancelling(record)?;
                transition_record(record, JobState::Cancelled)?;
                append_event(
                    record,
                    self.clock.now_ms(),
                    "finished",
                    RemoteBuildEventKind::OperationCancelled {
                        reason: "github_run_cancelled".to_owned(),
                        duration_ms: self.clock.now_ms().saturating_sub(record.created_at_ms),
                    },
                )
            }
            Some(RunConclusion::Success) if record.cancellation_requested => {
                ensure_running_or_cancelling(record)?;
                transition_record(record, JobState::Failed)?;
                append_failed(
                    record,
                    self.clock.now_ms(),
                    "cancel_race",
                    "GitHub run completed after cancellation was requested",
                    false,
                )
            }
            Some(RunConclusion::Success) => self.finish_success(record),
            Some(conclusion) => {
                ensure_running_or_cancelling(record)?;
                transition_record(record, JobState::Failed)?;
                append_failed(
                    record,
                    self.clock.now_ms(),
                    conclusion_code(conclusion),
                    "GitHub Actions build did not succeed",
                    conclusion_retryable(conclusion),
                )
            }
            None => Err(provider_failure(
                "missing_run_conclusion",
                "completed GitHub Actions run has no conclusion",
                false,
            )),
        }
    }

    fn finish_success(&self, record: &mut JobRecord) -> RemoteBuildResult<()> {
        if record.state == JobState::Queued {
            transition_record(record, JobState::Running)?;
        }
        let supports_listing = self.lock_artifacts()?.supports_listing();
        if !supports_listing {
            if !record.verification_pending_event {
                append_event(
                    record,
                    self.clock.now_ms(),
                    "artifact-verification",
                    RemoteBuildEventKind::Warning {
                        code: "github.artifact_verification_pending".to_owned(),
                        message: "GitHub run succeeded; independent artifact ingestion is not configured"
                            .to_owned(),
                        help: Some(
                            "Configure a verified artifact store before treating this build as successful"
                                .to_owned(),
                        ),
                    },
                )?;
                record.verification_pending_event = true;
            }
            return Ok(());
        }
        let context = Self::artifact_context(record, &self.config).ok_or_else(|| {
            provider_failure(
                "run_identity_unavailable",
                "artifact verification requires a terminal run snapshot",
                true,
            )
        })?;
        let manifests = self.lock_artifacts()?.list_verified(&context)?;
        if manifests.is_empty() {
            return Ok(());
        }
        validate_manifests(record, &self.config, &manifests)?;
        for manifest in &manifests {
            append_event(
                record,
                self.clock.now_ms(),
                "artifact-verification",
                RemoteBuildEventKind::ArtifactValidated {
                    artifact: manifest.clone(),
                },
            )?;
        }
        record.manifests.clone_from(&manifests);
        transition_record(record, JobState::Succeeded)?;
        let result = IosDeviceBuildResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: record.operation_id.clone(),
            job_id: record.job_id.clone(),
            state: JobState::Succeeded,
            artifacts: manifests,
            cleanup: None,
        };
        result.validate()?;
        append_event(
            record,
            self.clock.now_ms(),
            "finished",
            RemoteBuildEventKind::OperationFinished {
                success: true,
                duration_ms: self.clock.now_ms().saturating_sub(record.created_at_ms),
                result: Some(result),
                error: None,
            },
        )
    }
}

impl<R, P, A, C> BuildProvider for GithubBuildProvider<R, P, A, C>
where
    R: GhRunner + Send,
    P: TemporaryRefPublisher + Send,
    A: VerifiedArtifactStore + Send,
    C: ProviderClock,
{
    fn id(&self) -> &str {
        GITHUB_PROVIDER_ID
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn handshake(
        &self,
        request: HandshakeRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, HandshakeResponse> {
        let result = cancellation.check().and_then(|()| {
            HandshakeResponse::negotiate(
                &request,
                GITHUB_PROVIDER_ID,
                "github-hosted-macos",
                self.config.worker_version.clone(),
                self.capabilities.clone(),
            )
        });
        Box::pin(async move { result })
    }

    #[allow(clippy::too_many_lines)]
    fn doctor(
        &self,
        request: ProviderDoctorRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ProviderDoctorReport> {
        let result = (|| {
            cancellation.check()?;
            CURRENT_PROTOCOL_VERSION.negotiate(request.protocol_version)?;
            validate_provider_identifier("operation_id", &request.operation_id)?;

            let mut checks = Vec::new();
            match self.lock_transport()?.authenticate(&self.config.repository) {
                Ok(principal) => checks.push(ProviderCheck {
                    code: "github.authentication".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: principal.user_login().map_or_else(
                        || "Repository-scoped GitHub credential is available".to_owned(),
                        |login| format!("Authenticated GitHub account `{login}` is available"),
                    ),
                    help: None,
                }),
                Err(error) => checks.push(ProviderCheck {
                    code: "github.authentication".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: transport_public_message(error),
                    help: Some("Authenticate the configured GitHub transport and retry".to_owned()),
                }),
            }
            cancellation.check()?;

            let execution_private = match self.lock_transport()?.repository(&self.config.repository)
            {
                Ok(repository) if repository.is_archived() || repository.is_disabled() => {
                    checks.push(ProviderCheck {
                        code: "github.repository".to_owned(),
                        status: ProviderCheckStatus::Error,
                        message: "Configured GitHub repository cannot run new builds".to_owned(),
                        help: Some("Use an active, non-archived repository".to_owned()),
                    });
                    Some(repository.is_private())
                }
                Ok(repository) if request.require_signing && !repository.is_private() => {
                    checks.push(ProviderCheck {
                        code: "github.signing_repository_visibility".to_owned(),
                        status: ProviderCheckStatus::Error,
                        message: "Signed artifacts require a private GitHub execution repository"
                            .to_owned(),
                        help: Some(
                            "Configure a private signing repository so embedded provisioning metadata is not published to public readers"
                            .to_owned(),
                        ),
                    });
                    Some(false)
                }
                Ok(repository) => {
                    let private = repository.is_private();
                    checks.push(ProviderCheck {
                        code: "github.repository".to_owned(),
                        status: ProviderCheckStatus::Ready,
                        message: "Exact configured GitHub execution repository is available"
                            .to_owned(),
                        help: None,
                    });
                    Some(private)
                }
                Err(error) => {
                    checks.push(ProviderCheck {
                        code: "github.repository".to_owned(),
                        status: ProviderCheckStatus::Error,
                        message: transport_public_message(error),
                        help: Some(
                            "Check execution repository identity and token access".to_owned(),
                        ),
                    });
                    None
                }
            };
            let execution_repository_url = repository_url(&self.config.repository);
            let source_private =
                if github_remote_matches(&self.config.source_repository, &execution_repository_url)
                {
                    execution_private
                } else {
                    let source_repository = repository_from_url(&self.config.source_repository)
                        .ok_or_else(|| {
                            provider_failure(
                                "source_repository_invalid",
                                "configured source repository identity is invalid",
                                false,
                            )
                        })?;
                    match self.lock_transport()?.repository(&source_repository) {
                        Ok(repository) => Some(repository.is_private()),
                        Err(error) => {
                            checks.push(ProviderCheck {
                                code: "github.source_repository".to_owned(),
                                status: ProviderCheckStatus::Error,
                                message: transport_public_message(error),
                                help: Some(
                                    "Check public source repository identity and token access"
                                        .to_owned(),
                                ),
                            });
                            None
                        }
                    }
                };
            match source_private {
                Some(false) => checks.push(ProviderCheck {
                    code: "github.source_repository_visibility".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "Exact configured source repository is public".to_owned(),
                    help: None,
                }),
                Some(true) => checks.push(ProviderCheck {
                    code: "github.source_repository_visibility".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: "Trusted project source must be in a public GitHub repository"
                        .to_owned(),
                    help: Some(
                        "Keep public source separate from the private signing execution repository"
                            .to_owned(),
                    ),
                }),
                None => {}
            }
            cancellation.check()?;

            match self.lock_publisher()?.doctor(&TemporaryRefDoctorRequest {
                repository: &self.config.repository,
                source_repository: &self.config.source_repository,
                trusted_source_ref: self.config.workflow.trusted_source_ref(),
                workflow_path: &self.config.workflow.filename().repository_path(),
                workflow_fingerprint: &self.config.workflow_fingerprint,
            }) {
                Ok(_) => checks.push(ProviderCheck {
                    code: "github.trusted_source".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "Trusted ref contains the exact approved workflow bytes".to_owned(),
                    help: None,
                }),
                Err(error) => checks.push(ProviderCheck {
                    code: "github.trusted_source".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: publisher_public_message(error),
                    help: Some("Check the configured Git remote and trusted source ref".to_owned()),
                }),
            }

            checks.push(
                if self.config.mutation_authorization.publish_temporary_ref {
                    ProviderCheck {
                        code: "github.temporary_ref_authorization".to_owned(),
                        status: ProviderCheckStatus::Ready,
                        message: "Caller authorized create-only temporary build refs".to_owned(),
                        help: None,
                    }
                } else {
                    ProviderCheck {
                        code: "github.temporary_ref_authorization".to_owned(),
                        status: ProviderCheckStatus::Error,
                        message: "Temporary build ref publication is not authorized".to_owned(),
                        help: Some("Confirm the exact temporary ref before submission".to_owned()),
                    }
                },
            );
            if request.require_signing {
                let mut transport = self.lock_transport()?;
                append_signing_environment_checks(&mut checks, &mut transport, &self.config);
                cancellation.check()?;
            }
            if !self
                .artifacts
                .lock()
                .map_err(|_| {
                    provider_failure(
                        "artifact_store_unavailable",
                        "verified artifact store is unavailable",
                        true,
                    )
                })?
                .supports_download()
            {
                checks.push(ProviderCheck {
                    code: "github.artifact_ingestion".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: "Independent artifact download and verification are not configured"
                        .to_owned(),
                    help: Some("Configure a verified GitHub artifact store".to_owned()),
                });
            }
            let ready = checks
                .iter()
                .all(|check| check.status != ProviderCheckStatus::Error);
            Ok(ProviderDoctorReport {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                provider: GITHUB_PROVIDER_ID.to_owned(),
                ready,
                checks,
                capabilities: self.capabilities.clone(),
            })
        })();
        Box::pin(async move { result })
    }

    #[allow(clippy::too_many_lines)]
    fn submit(
        &self,
        request: IosDeviceBuildRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, JobHandle> {
        let result = (|| {
            cancellation.check()?;
            validate_submission(&self.config, &request)?;
            let branch = BranchName::new(format!(
                "{}/{}",
                self.config.workflow.temporary_branch_namespace().as_str(),
                request.operation_id
            ))
            .map_err(|_| {
                provider_failure(
                    "operation_id_not_ref_safe",
                    "operation ID cannot form a safe temporary Git ref",
                    false,
                )
            })?;
            let temporary_ref =
                TemporaryGitRef::new(self.config.workflow.temporary_branch_namespace(), branch)
                    .map_err(|_| {
                        provider_failure(
                            "operation_id_not_ref_safe",
                            "operation ID cannot form a safe temporary Git ref",
                            false,
                        )
                    })?;
            let source_revision =
                CommitSha::new(request.source_revision.clone().ok_or_else(|| {
                    provider_failure(
                        "invalid_source_revision",
                        "source revision is not an exact commit SHA",
                        false,
                    )
                })?)
                .map_err(|_| {
                    provider_failure(
                        "invalid_source_revision",
                        "source revision is not an exact commit SHA",
                        false,
                    )
                })?;
            let job_id = request.operation_id.clone();
            let reservation =
                JobReservation::acquire(&self.state, job_id.clone(), self.config.max_jobs)?;
            let created_at_ms = self.clock.now_ms();
            let workflow = generate_workflow(&self.config.workflow);
            let manifest =
                GithubDispatchManifest::new(&self.config, &temporary_ref, request.clone());
            manifest.validate_for(&self.config)?;
            let manifest_bytes = manifest.encode()?;
            let request_sha256 = canonical_request_sha256(&request)?;
            let discovery_deadline_ms =
                created_at_ms.saturating_add(self.config.poll_policy.discovery_window_ms());
            let mut record = JobRecord {
                operation_id: request.operation_id.clone(),
                job_id: job_id.clone(),
                source_revision: source_revision.clone(),
                request: request.clone(),
                request_sha256,
                temporary_ref: temporary_ref.clone(),
                dispatch_commit: None,
                created_at_ms,
                state: JobState::Created,
                run: None,
                run_snapshot: None,
                cancellation_requested: false,
                cancellation_dispatched: false,
                temporary_ref_deleted: false,
                verification_pending_event: false,
                publication_uncertain: false,
                run_discovery_attempts: 0,
                run_discovery_deadline_ms: discovery_deadline_ms,
                manifests: Vec::new(),
                events: Vec::new(),
            };
            append_event(
                &mut record,
                created_at_ms,
                "submit",
                RemoteBuildEventKind::OperationStarted {
                    command: "build-iphone".to_owned(),
                },
            )?;
            append_event(
                &mut record,
                created_at_ms,
                "submit",
                RemoteBuildEventKind::JobCreated {
                    state: JobState::Created,
                },
            )?;
            let pending = reservation.insert_pending(record)?;
            if request.signing.mode == SigningMode::ManualDevelopment {
                let source_repository = repository_from_url(&self.config.source_repository)
                    .ok_or_else(|| {
                        provider_failure(
                            "source_repository_invalid",
                            "configured source repository identity is invalid",
                            false,
                        )
                    })?;
                let source = self
                    .lock_transport()?
                    .repository(&source_repository)
                    .map_err(|error| {
                        provider_failure(
                            "source_repository_visibility_unavailable",
                            transport_public_message(error),
                            true,
                        )
                    })?;
                if source.is_private() {
                    return Err(provider_failure(
                        "private_source_repository",
                        "signed builds require a public GitHub source repository",
                        false,
                    ));
                }
                let repository = self
                    .lock_transport()?
                    .repository(&self.config.repository)
                    .map_err(|error| {
                        provider_failure(
                            "signing_repository_visibility_unavailable",
                            transport_public_message(error),
                            true,
                        )
                    })?;
                if !repository.is_private() {
                    return Err(provider_failure(
                        "public_signing_repository",
                        "signed artifacts require a private GitHub execution repository",
                        false,
                    ));
                }
                if repository.is_archived() || repository.is_disabled() {
                    return Err(provider_failure(
                        "signing_repository_read_only",
                        "the private GitHub signing repository cannot run new builds",
                        false,
                    ));
                }
                let mut signing_checks = Vec::new();
                let mut transport = self.lock_transport()?;
                append_signing_environment_checks(
                    &mut signing_checks,
                    &mut transport,
                    &self.config,
                );
                if signing_checks
                    .iter()
                    .any(|check| check.status != ProviderCheckStatus::Ready)
                {
                    return Err(provider_failure(
                        "signing_environment_not_ready",
                        "protected signing environment policy or secret metadata is not ready",
                        false,
                    ));
                }
                cancellation.check()?;
            }
            let publish_result = self.lock_publisher()?.publish(&TemporaryRefPublishRequest {
                repository: &self.config.repository,
                source_repository: &self.config.source_repository,
                trusted_source_ref: self.config.workflow.trusted_source_ref(),
                source_revision: &source_revision,
                temporary_ref: &temporary_ref,
                workflow_path: workflow.path(),
                workflow_bytes: workflow.yaml().as_bytes(),
                workflow_fingerprint: &self.config.workflow_fingerprint,
                manifest_bytes: &manifest_bytes,
                operation_id: &request.operation_id,
                created_at_ms,
                authorized: self.config.mutation_authorization.publish_temporary_ref,
            });
            let (published, publication_uncertain) = match publish_result {
                Ok(published) => (published, false),
                Err(failure) => match failure.possible_publication().cloned() {
                    Some(publication) => (publication, true),
                    None => return Err(publisher_failure(failure.error())),
                },
            };
            pending.retain();
            let publisher_identity_mismatch = published.temporary_ref() != &temporary_ref;
            let mut state = self.lock_state()?;
            let record = state.jobs.get_mut(&job_id).ok_or_else(|| {
                provider_failure(
                    "pending_job_lost",
                    "pending GitHub job disappeared during publication",
                    false,
                )
            })?;
            record.dispatch_commit = Some(published.commit().clone());
            record.publication_uncertain = publication_uncertain || publisher_identity_mismatch;
            if publisher_identity_mismatch {
                transition_record(record, JobState::Failed)?;
                append_event(
                    record,
                    self.clock.now_ms(),
                    "cleanup",
                    RemoteBuildEventKind::Warning {
                        code: "github.cleanup_required".to_owned(),
                        message: "Temporary-ref publisher returned a different ref; exact cleanup ownership was retained"
                            .to_owned(),
                        help: Some("Run provider cleanup for this exact failed job".to_owned()),
                    },
                )?;
                append_failed(
                    record,
                    self.clock.now_ms(),
                    "publisher_identity_mismatch",
                    "Temporary-ref publisher returned a different ref after possible mutation",
                    false,
                )?;
                return Ok(JobHandle {
                    job_id,
                    state: JobState::Failed,
                    created_at_ms,
                });
            }
            if publication_uncertain {
                append_event(
                    record,
                    self.clock.now_ms(),
                    "submit",
                    RemoteBuildEventKind::Warning {
                        code: "github.temporary_ref_publication_uncertain".to_owned(),
                        message: "Temporary ref push may have succeeded; cleanup ownership was retained"
                            .to_owned(),
                        help: Some(
                            "Continue polling this job or run exact-ref cleanup after it becomes terminal"
                                .to_owned(),
                        ),
                    },
                )?;
            }
            if record.state == JobState::Created {
                transition_record(record, JobState::Queued)?;
            }
            append_event(
                record,
                created_at_ms,
                "queue",
                RemoteBuildEventKind::JobQueued { position: None },
            )?;
            record.cancellation_requested |= cancellation.is_cancelled();
            if record.cancellation_requested && record.state != JobState::Cancelling {
                transition_record(record, JobState::Cancelling)?;
            }
            let returned_state = record.state;
            Ok(JobHandle {
                job_id,
                state: returned_state,
                created_at_ms,
            })
        })();
        Box::pin(async move { result })
    }

    fn events(
        &self,
        request: EventRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, EventPage> {
        let result = (|| {
            request.validate()?;
            cancellation.check()?;
            self.sync_job(&request.job_id, &cancellation)?;
            let state = self.lock_state()?;
            let record = state
                .jobs
                .get(&request.job_id)
                .ok_or_else(|| job_not_found(&request.job_id))?;
            let after = request.after_sequence.unwrap_or(0);
            let mut matching = record
                .events
                .iter()
                .filter(|event| event.sequence > after)
                .cloned();
            let events = matching
                .by_ref()
                .take(request.limit as usize)
                .collect::<Vec<_>>();
            let truncated = matching.next().is_some();
            let next_sequence = events.last().map(|event| event.sequence);
            Ok(EventPage {
                job_id: record.job_id.clone(),
                state: record.state,
                events,
                next_sequence,
                complete: record.state.is_terminal() && !truncated,
            })
        })();
        Box::pin(async move { result })
    }

    fn cancel(
        &self,
        request: CancellationRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, CancellationAck> {
        let result = (|| {
            cancellation.check()?;
            validate_provider_identifier("job_id", &request.job_id)?;
            validate_provider_identifier("cancellation_reason", &request.reason)?;
            if !self.config.mutation_authorization.cancel_run {
                return Err(unsupported(ProviderFeature::Cancellation));
            }
            let mut state = self.lock_state()?;
            let record = state
                .jobs
                .get_mut(&request.job_id)
                .ok_or_else(|| job_not_found(&request.job_id))?;
            if record.state.is_build_terminal() || record.state.is_terminal() {
                return Ok(CancellationAck {
                    job_id: record.job_id.clone(),
                    accepted: false,
                    state: record.state,
                });
            }
            let accepted = !record.cancellation_requested;
            record.cancellation_requested = true;
            if record.state != JobState::Cancelling {
                transition_record(record, JobState::Cancelling)?;
            }
            if let Some(handle) = &record.run
                && !record.cancellation_dispatched
            {
                self.lock_transport()?
                    .cancel_run(&self.config.repository, handle.id())
                    .map_err(transport_failure)?;
                record.cancellation_dispatched = true;
            }
            Ok(CancellationAck {
                job_id: record.job_id.clone(),
                accepted,
                state: record.state,
            })
        })();
        Box::pin(async move { result })
    }

    fn list_artifacts(
        &self,
        request: ArtifactListRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, Vec<ArtifactManifest>> {
        let result = (|| {
            cancellation.check()?;
            validate_provider_identifier("job_id", &request.job_id)?;
            if !self.capabilities.artifact_listing {
                return Err(unsupported(ProviderFeature::ArtifactListing));
            }
            self.sync_job(&request.job_id, &cancellation)?;
            let state = self.lock_state()?;
            let record = state
                .jobs
                .get(&request.job_id)
                .ok_or_else(|| job_not_found(&request.job_id))?;
            if !record.manifests.is_empty() {
                return Ok(record.manifests.clone());
            }
            let context = Self::artifact_context(record, &self.config).ok_or_else(|| {
                provider_failure(
                    "artifacts_pending",
                    "GitHub run has not completed artifact production",
                    true,
                )
            })?;
            drop(state);
            let manifests = self.lock_artifacts()?.list_verified(&context)?;
            validate_manifests_for_context(&context, &manifests)?;
            Ok(manifests)
        })();
        Box::pin(async move { result })
    }

    fn download_artifact(
        &self,
        request: ArtifactDownloadRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ArtifactDownloadResult> {
        let result = (|| {
            request.validate()?;
            cancellation.check()?;
            if !self.capabilities.artifact_download {
                return Err(unsupported(ProviderFeature::ArtifactDownload));
            }
            self.sync_job(&request.job_id, &cancellation)?;
            let state = self.lock_state()?;
            let record = state
                .jobs
                .get(&request.job_id)
                .ok_or_else(|| job_not_found(&request.job_id))?;
            let context = Self::artifact_context(record, &self.config).ok_or_else(|| {
                provider_failure(
                    "artifact_pending",
                    "GitHub run has not completed artifact production",
                    true,
                )
            })?;
            drop(state);
            let result = self
                .lock_artifacts()?
                .download_verified(&context, &request)?;
            if result.manifest.operation_id != context.operation_id
                || result.manifest.job_id != context.job_id
                || result.local_path != request.destination
            {
                return Err(provider_failure(
                    "artifact_identity_mismatch",
                    "verified artifact result does not match the exact request",
                    false,
                ));
            }
            Ok(result)
        })();
        Box::pin(async move { result })
    }

    #[allow(clippy::too_many_lines)]
    fn cleanup(
        &self,
        request: CleanupRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, CleanupConfirmation> {
        let result = (|| {
            cancellation.check()?;
            validate_provider_identifier("job_id", &request.job_id)?;
            if !self.config.mutation_authorization.delete_temporary_ref {
                return Err(unsupported(ProviderFeature::Cleanup));
            }
            let mut state = self.lock_state()?;
            let record = state
                .jobs
                .get_mut(&request.job_id)
                .ok_or_else(|| job_not_found(&request.job_id))?;
            let terminal_run = record
                .run_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.status().is_terminal());
            if !record.state.is_build_terminal() && terminal_run {
                ensure_running_or_cancelling(record)?;
                transition_record(record, JobState::Failed)?;
                append_failed(
                    record,
                    self.clock.now_ms(),
                    "artifact_verification_failed",
                    "GitHub Actions completed, but independent artifact verification did not complete",
                    false,
                )?;
            }
            if !record.state.is_build_terminal()
                && !matches!(record.state, JobState::Cleaned | JobState::CleanupFailed)
            {
                return Err(provider_failure(
                    "cleanup_before_terminal",
                    "GitHub job must reach a terminal run state before cleanup",
                    true,
                ));
            }
            if matches!(record.state, JobState::Cleaned | JobState::CleanupFailed) {
                return Err(provider_failure(
                    "cleanup_already_attempted",
                    "GitHub job cleanup was already attempted",
                    false,
                ));
            }
            let context = Self::artifact_context(record, &self.config);
            if request.remove_artifacts {
                let context = context.as_ref().ok_or_else(|| {
                    provider_failure(
                        "artifact_identity_unavailable",
                        "exact run identity is unavailable for artifact removal",
                        false,
                    )
                })?;
                if !self.lock_artifacts()?.supports_removal() {
                    return Err(provider_failure(
                        "artifact_removal_unsupported",
                        "verified artifact removal is not configured",
                        false,
                    ));
                }
                self.lock_artifacts()?.remove_artifacts(context)?;
            }
            if !record.temporary_ref_deleted {
                let expected_commit = record.dispatch_commit.as_ref().ok_or_else(|| {
                    provider_failure(
                        "dispatch_commit_unavailable",
                        "exact dispatch commit is unavailable for safe ref cleanup",
                        false,
                    )
                })?;
                self.lock_publisher()?
                    .delete_temporary_ref(&TemporaryRefDeleteRequest {
                        repository: &self.config.repository,
                        source_repository: &self.config.source_repository,
                        temporary_ref: &record.temporary_ref,
                        expected_commit,
                        authorized: self.config.mutation_authorization.delete_temporary_ref,
                    })
                    .map_err(publisher_failure)?;
                record.temporary_ref_deleted = true;
            }
            transition_record(record, JobState::Cleaning)?;
            append_event(
                record,
                self.clock.now_ms(),
                "cleanup",
                RemoteBuildEventKind::CleanupStarted,
            )?;

            let run_completed = record
                .run_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.status().is_terminal());
            let signing_material_removed = record
                .run_snapshot
                .as_ref()
                .and_then(RunSnapshot::conclusion)
                == Some(RunConclusion::Success);
            let confirmation = CleanupConfirmation {
                job_id: record.job_id.clone(),
                completed_at_ms: self.clock.now_ms(),
                workspace_removed: run_completed,
                signing_material_removed,
                artifacts_retained: !request.remove_artifacts,
            };
            let cleanup_state = if run_completed && signing_material_removed {
                JobState::Cleaned
            } else {
                JobState::CleanupFailed
            };
            transition_record(record, cleanup_state)?;
            append_event(
                record,
                self.clock.now_ms(),
                "cleanup",
                RemoteBuildEventKind::CleanupFinished {
                    confirmation: confirmation.clone(),
                },
            )?;
            Ok(confirmation)
        })();
        Box::pin(async move { result })
    }
}

fn provider_capabilities(
    config: &GithubProviderConfig,
    artifacts: &impl VerifiedArtifactStore,
) -> ProviderCapabilities {
    ProviderCapabilities {
        source_modes: BTreeSet::from([SourceMode::Git]),
        ios_device_build: true,
        ios_simulator_build: false,
        signing_modes: BTreeSet::from([
            SigningMode::ManualDevelopment,
            SigningMode::UnsignedCompileOnly,
        ]),
        personal_team: false,
        live_events: true,
        live_logs: false,
        cancellation: config.mutation_authorization.cancel_run,
        artifact_types: BTreeSet::from([
            IosArtifactType::Ipa,
            IosArtifactType::AppBundle,
            IosArtifactType::Dsym,
            IosArtifactType::SigningReport,
            IosArtifactType::Xcarchive,
        ]),
        cache: true,
        max_source_bytes: None,
        retention_seconds: Some(
            u64::from(config.workflow.limits().retention_days()) * 24 * 60 * 60,
        ),
        artifact_listing: artifacts.supports_listing(),
        artifact_download: artifacts.supports_download(),
        cleanup: config.mutation_authorization.delete_temporary_ref,
        physical_device_access: false,
    }
}

fn lock_provider_state(
    state: &Mutex<ProviderState>,
) -> RemoteBuildResult<std::sync::MutexGuard<'_, ProviderState>> {
    state.lock().map_err(|_| {
        provider_failure(
            "state_unavailable",
            "GitHub provider state is unavailable",
            true,
        )
    })
}

fn append_signing_environment_checks<R: GhRunner>(
    checks: &mut Vec<ProviderCheck>,
    transport: &mut GithubTransport<R>,
    config: &GithubProviderConfig,
) {
    append_signing_environment_policy_checks(checks, transport, config);
    append_signing_branch_policy_check(checks, transport, config);
    append_signing_secret_check(checks, transport, config);
}

fn append_signing_environment_policy_checks<R: GhRunner>(
    checks: &mut Vec<ProviderCheck>,
    transport: &mut GithubTransport<R>,
    config: &GithubProviderConfig,
) {
    match transport.environment(
        config.repository(),
        config.workflow().protected_environment(),
    ) {
        Ok(info) => {
            checks.push(if !info.protected_branches() && info.custom_branch_policies() {
                ProviderCheck {
                    code: "github.signing_environment".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "Signing environment requires custom deployment branch policies"
                        .to_owned(),
                    help: None,
                }
            } else {
                ProviderCheck {
                    code: "github.signing_environment".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: "Signing environment does not exclusively use custom deployment branch policies"
                        .to_owned(),
                    help: Some(
                        "Disable protected-branch selection and enable custom branch policies"
                            .to_owned(),
                    ),
                }
            });
            checks.push(if info.has_required_reviewers() {
                ProviderCheck {
                    code: "github.signing_environment.reviewers".to_owned(),
                    status: ProviderCheckStatus::Ready,
                    message: "Signing environment requires a deployment reviewer".to_owned(),
                    help: None,
                }
            } else {
                ProviderCheck {
                    code: "github.signing_environment.reviewers".to_owned(),
                    status: ProviderCheckStatus::Error,
                    message: "Signing environment has no required deployment reviewer".to_owned(),
                    help: Some(
                        "Require server-side deployment approval until signing uses a trusted SHA-pinned reusable workflow"
                            .to_owned(),
                    ),
                }
            });
        }
        Err(error) => checks.push(ProviderCheck {
            code: "github.signing_environment".to_owned(),
            status: ProviderCheckStatus::Error,
            message: transport_public_message(error),
            help: Some("Create the exact configured GitHub signing environment".to_owned()),
        }),
    }
}

fn append_signing_branch_policy_check<R: GhRunner>(
    checks: &mut Vec<ProviderCheck>,
    transport: &mut GithubTransport<R>,
    config: &GithubProviderConfig,
) {
    let workflow = config.workflow();
    let expected_policy = format!("{}/*", workflow.temporary_branch_namespace().as_str());
    match transport.list_deployment_branch_policies(
        config.repository(),
        workflow.protected_environment(),
    ) {
        Ok(policies) if policies.len() == 1 && policies[0].name() == expected_policy.as_str() => {
            checks.push(ProviderCheck {
                code: "github.signing_branch_policy".to_owned(),
                status: ProviderCheckStatus::Ready,
                message: "Signing environment allows only the temporary build namespace"
                    .to_owned(),
                help: None,
            });
        }
        Ok(_) => checks.push(ProviderCheck {
            code: "github.signing_branch_policy".to_owned(),
            status: ProviderCheckStatus::Error,
            message: "Signing environment deployment branch policies do not exactly match the temporary build namespace"
                .to_owned(),
            help: Some(format!("Configure the single deployment branch policy `{expected_policy}`")),
        }),
        Err(error) => checks.push(ProviderCheck {
            code: "github.signing_branch_policy".to_owned(),
            status: ProviderCheckStatus::Error,
            message: transport_public_message(error),
            help: Some(format!("Configure the single deployment branch policy `{expected_policy}`")),
        }),
    }
}

fn append_signing_secret_check<R: GhRunner>(
    checks: &mut Vec<ProviderCheck>,
    transport: &mut GithubTransport<R>,
    config: &GithubProviderConfig,
) {
    let workflow = config.workflow();
    let secret_names = workflow.secret_names();
    let expected_secrets = secret_names.all_names().cloned().collect::<BTreeSet<_>>();
    match transport.list_environment_secrets(config.repository(), workflow.protected_environment())
    {
        Ok(secrets)
            if secrets
                .iter()
                .map(|secret| secret.name().clone())
                .collect::<BTreeSet<_>>()
                == expected_secrets =>
        {
            checks.push(ProviderCheck {
                code: "github.signing_secrets".to_owned(),
                status: ProviderCheckStatus::Ready,
                message: "Signing environment contains exactly the configured signing secret names"
                    .to_owned(),
                help: None,
            });
        }
        Ok(_) => checks.push(ProviderCheck {
            code: "github.signing_secrets".to_owned(),
            status: ProviderCheckStatus::Error,
            message:
                "Signing environment secret metadata does not match the configured signing roles"
                    .to_owned(),
            help: Some(
                "Configure the certificate, password, and provisioning-profile environment secrets"
                    .to_owned(),
            ),
        }),
        Err(error) => checks.push(ProviderCheck {
            code: "github.signing_secrets".to_owned(),
            status: ProviderCheckStatus::Error,
            message: transport_public_message(error),
            help: Some(
                "Grant environment-secret metadata access and configure all signing roles"
                    .to_owned(),
            ),
        }),
    }
}

fn validate_submission(
    config: &GithubProviderConfig,
    request: &IosDeviceBuildRequest,
) -> RemoteBuildResult<()> {
    if request.signing.mode == SigningMode::ManualDevelopment
        && !(1..=MAX_SIGNING_PROFILES).contains(&request.signing.provisioning.len())
    {
        return Err(provider_failure(
            "profile_mapping_unsupported",
            "GitHub provider accepts one application profile and at most two extension profiles",
            false,
        ));
    }
    request.validate()?;
    if request.source_mode != SourceMode::Git
        || request.source_repository.as_deref() != Some(config.source_repository())
        || request.source_revision.is_none()
    {
        return Err(provider_failure(
            "unsupported_source_request",
            "GitHub provider requires its exact configured Git source repository and commit",
            false,
        ));
    }
    match request.signing.mode {
        SigningMode::ManualDevelopment => {
            if github_remote_matches(
                config.source_repository(),
                &repository_url(config.repository()),
            ) {
                return Err(provider_failure(
                    "separate_signing_repository_required",
                    "signed builds require a separate private execution repository",
                    false,
                ));
            }
            validate_signing_secret_references(config, request)?;
            validate_signed_artifact_request(request)?;
        }
        SigningMode::UnsignedCompileOnly => {
            validate_exact_artifact_request(
                request,
                &BTreeSet::from([IosArtifactType::Xcarchive]),
            )?;
        }
        mode => return Err(unsupported(ProviderFeature::SigningMode(mode))),
    }
    validate_ref_segment(&request.operation_id).map_err(|()| {
        provider_failure(
            "operation_id_not_ref_safe",
            "operation ID cannot form a safe temporary Git ref",
            false,
        )
    })
}

fn validate_signing_secret_references(
    config: &GithubProviderConfig,
    request: &IosDeviceBuildRequest,
) -> RemoteBuildResult<()> {
    let names = config.workflow.secret_names();
    let identity_references_match = request.signing.signing.as_ref().is_some_and(|signing| {
        exact_github_secret(
            &signing.identity.private_key.reference,
            names.certificate_p12().as_str(),
        ) && signing.password.as_ref().is_some_and(|password| {
            exact_github_secret(password, names.certificate_password().as_str())
        })
    });
    let profiles_match = if names.uses_legacy_profile_binding() {
        request.signing.provisioning.len() == 1
            && request.signing.provisioning.first().is_some_and(|profile| {
                exact_github_secret(&profile.profile, names.provisioning_profile().as_str())
            })
    } else {
        names.matches_target_graph(&request.signing.targets)
            && request.signing.provisioning.len() == names.profile_names().count()
            && request.signing.provisioning.iter().all(|profile| {
                names
                    .profile_for_target(&profile.target)
                    .is_some_and(|expected| {
                        exact_github_secret(&profile.profile, expected.as_str())
                    })
            })
    };
    if !identity_references_match || !profiles_match {
        return Err(provider_failure(
            "signing_secret_reference_mismatch",
            "signed GitHub builds require the exact configured GitHub Actions secret roles",
            false,
        ));
    }
    Ok(())
}

fn exact_github_secret(reference: &SecretReference, expected_name: &str) -> bool {
    reference.kind() == SecretReferenceKind::GithubActions && reference.name() == expected_name
}

fn validate_exact_artifact_request(
    request: &IosDeviceBuildRequest,
    expected: &BTreeSet<IosArtifactType>,
) -> RemoteBuildResult<()> {
    if request.requested_artifacts == *expected {
        return Ok(());
    }
    if let Some(extra) = request.requested_artifacts.difference(expected).next() {
        return Err(unsupported(ProviderFeature::ArtifactType(*extra)));
    }
    Err(provider_failure(
        "artifact_request_mismatch",
        "requested artifacts do not exactly match the selected signing mode",
        false,
    ))
}

fn validate_signed_artifact_request(request: &IosDeviceBuildRequest) -> RemoteBuildResult<()> {
    let required = BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport]);
    let supported = BTreeSet::from([
        IosArtifactType::Ipa,
        IosArtifactType::AppBundle,
        IosArtifactType::Xcarchive,
        IosArtifactType::Dsym,
        IosArtifactType::SigningReport,
    ]);
    if let Some(extra) = request.requested_artifacts.difference(&supported).next() {
        return Err(unsupported(ProviderFeature::ArtifactType(*extra)));
    }
    if required.is_subset(&request.requested_artifacts) {
        return Ok(());
    }
    Err(provider_failure(
        "artifact_request_mismatch",
        "signed builds require the IPA and signing report artifact set",
        false,
    ))
}

fn validate_manifests(
    record: &JobRecord,
    config: &GithubProviderConfig,
    manifests: &[ArtifactManifest],
) -> RemoteBuildResult<()> {
    let snapshot = record.run_snapshot.clone().ok_or_else(|| {
        provider_failure(
            "run_identity_unavailable",
            "artifact manifests require a terminal run snapshot",
            true,
        )
    })?;
    let dispatch_revision = record.dispatch_commit.clone().ok_or_else(|| {
        provider_failure(
            "dispatch_commit_unavailable",
            "artifact manifests require the exact dispatched commit",
            true,
        )
    })?;
    let context = GithubArtifactContext {
        job_id: record.job_id.clone(),
        operation_id: record.operation_id.clone(),
        repository: config.repository.clone(),
        run: snapshot,
        source_repository: config.source_repository.clone(),
        source_revision: record.source_revision.clone(),
        dispatch_revision,
        request: record.request.clone(),
        request_sha256: record.request_sha256.clone(),
    };
    validate_manifests_for_context(&context, manifests)
}

fn validate_manifests_for_context(
    context: &GithubArtifactContext,
    manifests: &[ArtifactManifest],
) -> RemoteBuildResult<()> {
    if manifests.is_empty() {
        return Err(provider_failure(
            "artifacts_pending",
            "independent artifact verification has not produced a manifest",
            true,
        ));
    }
    for manifest in manifests {
        if manifest.operation_id != context.operation_id
            || manifest.job_id != context.job_id
            || manifest.provider != GITHUB_PROVIDER_ID
            || manifest.source_repository.as_deref() != Some(context.source_repository.as_str())
            || manifest.source_revision.as_deref() != Some(context.source_revision.as_str())
        {
            return Err(provider_failure(
                "artifact_manifest_identity_mismatch",
                "verified artifact manifest does not match the exact GitHub job",
                false,
            ));
        }
    }
    Ok(())
}

fn ensure_running_or_cancelling(record: &mut JobRecord) -> RemoteBuildResult<()> {
    if record.state == JobState::Queued {
        transition_record(record, JobState::Running)?;
    }
    Ok(())
}

fn transition_record(record: &mut JobRecord, next: JobState) -> RemoteBuildResult<()> {
    if record.state == next {
        return Ok(());
    }
    record.state = record.state.transition_to(next)?;
    Ok(())
}

fn append_event(
    record: &mut JobRecord,
    timestamp_ms: u64,
    phase: &'static str,
    kind: RemoteBuildEventKind,
) -> RemoteBuildResult<()> {
    if record.events.len() >= MAX_JOB_EVENTS {
        return Err(provider_failure(
            "event_capacity_reached",
            "GitHub job reached its bounded event capacity",
            false,
        ));
    }
    let sequence = u64::try_from(record.events.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let event = RemoteBuildEvent::new(
        record.operation_id.clone(),
        record.job_id.clone(),
        timestamp_ms,
        GITHUB_PROVIDER_ID,
        phase,
        sequence,
        kind,
    )?;
    record.events.push(event);
    Ok(())
}

fn append_failed(
    record: &mut JobRecord,
    timestamp_ms: u64,
    code: &'static str,
    message: &'static str,
    retryable: bool,
) -> RemoteBuildResult<()> {
    let result = IosDeviceBuildResult {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: record.operation_id.clone(),
        job_id: record.job_id.clone(),
        state: JobState::Failed,
        artifacts: Vec::new(),
        cleanup: None,
    };
    result.validate()?;
    append_event(
        record,
        timestamp_ms,
        "finished",
        RemoteBuildEventKind::OperationFinished {
            success: false,
            duration_ms: timestamp_ms.saturating_sub(record.created_at_ms),
            result: Some(result),
            error: Some(RemoteErrorInfo {
                code: format!("github.{code}"),
                message: message.to_owned(),
                help: Some(
                    "Inspect sanitized GitHub Actions diagnostics and retry if appropriate"
                        .to_owned(),
                ),
                retryable,
            }),
        },
    )
}

fn conclusion_code(conclusion: RunConclusion) -> &'static str {
    match conclusion {
        RunConclusion::Success => "success",
        RunConclusion::Failure => "run_failed",
        RunConclusion::Cancelled => "run_cancelled",
        RunConclusion::TimedOut => "run_timed_out",
        RunConclusion::Neutral => "run_neutral",
        RunConclusion::Skipped => "run_skipped",
        RunConclusion::Stale => "run_stale",
        RunConclusion::ActionRequired => "run_action_required",
        RunConclusion::StartupFailure => "run_startup_failure",
    }
}

fn conclusion_retryable(conclusion: RunConclusion) -> bool {
    matches!(
        conclusion,
        RunConclusion::TimedOut | RunConclusion::Stale | RunConclusion::StartupFailure
    )
}

fn publisher_failure(error: TemporaryRefPublishError) -> RemoteBuildError {
    let (code, retryable) = match error {
        TemporaryRefPublishError::Unauthorized => ("temporary_ref_unauthorized", false),
        TemporaryRefPublishError::RemoteMismatch => ("git_remote_mismatch", false),
        TemporaryRefPublishError::TrustedRefUnavailable => ("trusted_ref_unavailable", true),
        TemporaryRefPublishError::SourceRevisionNotTrusted => {
            ("source_revision_not_trusted", false)
        }
        TemporaryRefPublishError::TemporaryRefExists => ("temporary_ref_exists", false),
        TemporaryRefPublishError::WorkflowFingerprintMismatch => {
            ("workflow_fingerprint_mismatch", false)
        }
        TemporaryRefPublishError::LocalIsolationFailed => ("git_isolation_failed", true),
        TemporaryRefPublishError::Git(GitExecutionError::TimedOut) => {
            ("git_operation_timed_out", true)
        }
        TemporaryRefPublishError::Git(_) => ("git_operation_failed", true),
        TemporaryRefPublishError::MalformedGitOutput => ("malformed_git_output", false),
        TemporaryRefPublishError::PublicationVerificationFailed => {
            ("temporary_ref_verification_failed", false)
        }
        TemporaryRefPublishError::TemporaryRefLeaseRejected => ("temporary_ref_tip_changed", false),
        TemporaryRefPublishError::DeletionVerificationFailed => {
            ("temporary_ref_deletion_unverified", true)
        }
    };
    provider_failure(code, "temporary Git ref mutation failed", retryable)
}

fn transport_failure(error: TransportError) -> RemoteBuildError {
    let retryable = matches!(
        error,
        TransportError::Execution(GhExecutionError::TimedOut)
            | TransportError::RunNotFound
            | TransportError::PollLimitReached
    );
    provider_failure(
        "github_transport_failed",
        "GitHub API operation failed",
        retryable,
    )
}

fn transport_public_message(error: TransportError) -> String {
    match error {
        TransportError::Execution(GhExecutionError::AuthenticationUnavailable) => {
            "Configured GitHub authentication is unavailable".to_owned()
        }
        TransportError::RepositoryIdentityMismatch => {
            "GitHub returned a different repository identity".to_owned()
        }
        _ => "GitHub readiness check failed".to_owned(),
    }
}

fn publisher_public_message(error: TemporaryRefPublishError) -> String {
    match error {
        TemporaryRefPublishError::RemoteMismatch => {
            "Local Git remote differs from the configured repository".to_owned()
        }
        TemporaryRefPublishError::TrustedRefUnavailable => {
            "Configured trusted source ref is unavailable".to_owned()
        }
        _ => "Local Git publisher readiness check failed".to_owned(),
    }
}

fn unsupported(feature: ProviderFeature) -> RemoteBuildError {
    RemoteBuildError::UnsupportedCapability {
        provider: GITHUB_PROVIDER_ID.to_owned(),
        feature,
    }
}

fn provider_failure(
    code: impl Into<String>,
    message: impl Into<String>,
    retryable: bool,
) -> RemoteBuildError {
    RemoteBuildError::ProviderFailure {
        provider: GITHUB_PROVIDER_ID.to_owned(),
        code: code.into(),
        message: message.into(),
        retryable,
    }
}

fn job_not_found(_job_id: &str) -> RemoteBuildError {
    provider_failure("job_not_found", "GitHub provider job was not found", false)
}

fn job_not_mapped(_job_id: &str) -> RemoteBuildError {
    provider_failure(
        "run_not_mapped",
        "GitHub Actions run has not been mapped to this job",
        true,
    )
}

fn repository_url(repository: &Repository) -> String {
    format!(
        "https://github.com/{}/{}",
        repository.owner(),
        repository.name()
    )
}

fn repository_from_url(value: &str) -> Option<Repository> {
    let slug = value.strip_prefix("https://github.com/")?;
    let (owner, name) = slug.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    Repository::new(owner, name).ok()
}

fn is_safe_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn github_remote_matches(actual: &str, expected_https: &str) -> bool {
    let actual = actual.trim_end_matches('/').trim_end_matches(".git");
    if actual.eq_ignore_ascii_case(expected_https) {
        return true;
    }
    let Some(slug) = expected_https.strip_prefix("https://github.com/") else {
        return false;
    };
    actual.eq_ignore_ascii_case(&format!("git@github.com:{slug}"))
        || actual.eq_ignore_ascii_case(&format!("ssh://git@github.com/{slug}"))
}

fn validate_provider_identifier(field: &'static str, value: &str) -> RemoteBuildResult<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value is not a safe provider identifier",
        });
    }
    Ok(())
}

fn validate_ref_segment(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 160
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || value.ends_with('.')
        || value
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("lock"))
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_repository_path(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b':')
    {
        Err(())
    } else {
        Ok(())
    }
}

fn parse_single_line(output: &[u8]) -> Result<&str, TemporaryRefPublishError> {
    let text =
        std::str::from_utf8(output).map_err(|_| TemporaryRefPublishError::MalformedGitOutput)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains(['\n', '\r']) {
        return Err(TemporaryRefPublishError::MalformedGitOutput);
    }
    Ok(text)
}

fn parse_object_id(output: &[u8]) -> Result<String, TemporaryRefPublishError> {
    let value = parse_single_line(output)?;
    CommitSha::new(value.to_owned()).map_err(|_| TemporaryRefPublishError::MalformedGitOutput)?;
    Ok(value.to_owned())
}

fn parse_ls_remote(
    output: &[u8],
    expected_ref: &str,
) -> Result<Option<CommitSha>, TemporaryRefPublishError> {
    if output.is_empty() {
        return Ok(None);
    }
    let text =
        std::str::from_utf8(output).map_err(|_| TemporaryRefPublishError::MalformedGitOutput)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains(['\n', '\r']) {
        return Err(TemporaryRefPublishError::MalformedGitOutput);
    }
    let (sha, reference) = text
        .split_once('\t')
        .ok_or(TemporaryRefPublishError::MalformedGitOutput)?;
    if reference != expected_ref {
        return Err(TemporaryRefPublishError::MalformedGitOutput);
    }
    let sha =
        CommitSha::new(sha.to_owned()).map_err(|_| TemporaryRefPublishError::MalformedGitOutput)?;
    Ok(Some(sha))
}

fn remove_exact_file_if_present(path: &Path) -> Result<(), TemporaryRefPublishError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).map_err(|_| TemporaryRefPublishError::LocalIsolationFailed)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(TemporaryRefPublishError::LocalIsolationFailed),
    }
}

fn canonical_file(path: &Path) -> Result<PathBuf, GitPublisherConfigError> {
    if !is_absolute_normal(path) {
        return Err(GitPublisherConfigError::InvalidGitExecutable);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| GitPublisherConfigError::InvalidGitExecutable)?;
    if !canonical.is_file() {
        return Err(GitPublisherConfigError::InvalidGitExecutable);
    }
    Ok(canonical)
}

fn executable_basename_matches(path: &Path, stem: &str) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    #[cfg(windows)]
    {
        name.eq_ignore_ascii_case(&format!("{stem}.exe"))
    }
    #[cfg(not(windows))]
    {
        name == stem
    }
}

fn apply_allowlisted_git_environment(command: &mut Command) {
    command.env_clear();
    for &name in GIT_AMBIENT_ENVIRONMENT_ALLOWLIST {
        if let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            command.env(name, value);
        }
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, GitPublisherConfigError> {
    if !is_absolute_normal(path) {
        return Err(GitPublisherConfigError::InvalidDirectory);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GitPublisherConfigError::InvalidDirectory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GitPublisherConfigError::InvalidDirectory);
    }
    fs::canonicalize(path).map_err(|_| GitPublisherConfigError::InvalidDirectory)
}

fn is_absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn run_git_process(
    mut command: Command,
    stdin_bytes: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, GitExecutionError> {
    let mut child = command
        .spawn()
        .map_err(|_| GitExecutionError::SpawnFailed)?;
    let stdin = child.stdin.take().ok_or_else(|| {
        terminate_child(&mut child);
        GitExecutionError::ProcessIo
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_child(&mut child);
        GitExecutionError::ProcessIo
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_child(&mut child);
        GitExecutionError::ProcessIo
    })?;
    let input = stdin_bytes.to_vec();
    let stdin_writer = thread::spawn(move || -> io::Result<()> {
        let mut stdin = stdin;
        stdin.write_all(&input)?;
        stdin.flush()
    });
    let stdout_reader = thread::spawn(move || read_capped(stdout, MAX_GIT_OUTPUT_BYTES, true));
    let stderr_reader = thread::spawn(move || read_capped(stderr, MAX_GIT_STDERR_BYTES, false));
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        terminate_child(&mut child);
        let (_stdin_result, _stdout, _stderr) =
            join_git_threads(stdin_writer, stdout_reader, stderr_reader)?;
        return Err(GitExecutionError::TimedOut);
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                terminate_child(&mut child);
                let (_stdin_result, _stdout, _stderr) =
                    join_git_threads(stdin_writer, stdout_reader, stderr_reader)?;
                return Err(GitExecutionError::TimedOut);
            }
            Err(_) => {
                terminate_child(&mut child);
                let (_stdin_result, _stdout, _stderr) =
                    join_git_threads(stdin_writer, stdout_reader, stderr_reader)?;
                return Err(GitExecutionError::ProcessIo);
            }
        }
    };
    let (stdin_result, stdout, stderr) =
        join_git_threads(stdin_writer, stdout_reader, stderr_reader)?;
    stdin_result.map_err(|_| GitExecutionError::ProcessIo)?;
    if stdout.truncated || stderr.truncated {
        return Err(GitExecutionError::OutputLimitExceeded);
    }
    if !status.success() {
        return Err(git_command_failed(status));
    }
    Ok(stdout.bytes)
}

type InputThread = thread::JoinHandle<io::Result<()>>;
type OutputThread = thread::JoinHandle<Result<CapturedGitOutput, GitExecutionError>>;

fn join_git_threads(
    stdin_writer: InputThread,
    stdout_reader: OutputThread,
    stderr_reader: OutputThread,
) -> Result<(io::Result<()>, CapturedGitOutput, CapturedGitOutput), GitExecutionError> {
    let stdin = stdin_writer
        .join()
        .map_err(|_| GitExecutionError::ProcessIo)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| GitExecutionError::ProcessIo)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| GitExecutionError::ProcessIo)??;
    Ok((stdin, stdout, stderr))
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

struct CapturedGitOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_capped(
    mut reader: impl Read,
    limit: usize,
    retain: bool,
) -> Result<CapturedGitOutput, GitExecutionError> {
    let mut bytes = if retain {
        Vec::with_capacity(limit.min(16 * 1024))
    } else {
        Vec::new()
    };
    let mut total = 0_usize;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| GitExecutionError::ProcessIo)?;
        if read == 0 {
            break;
        }
        let retained = limit.saturating_sub(total).min(read);
        if retain && retained > 0 {
            bytes.extend_from_slice(&buffer[..retained]);
        }
        total = total.saturating_add(read);
    }
    Ok(CapturedGitOutput {
        bytes,
        truncated: total > limit,
    })
}

fn git_command_failed(status: ExitStatus) -> GitExecutionError {
    GitExecutionError::CommandFailed {
        exit_code: status.code(),
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn bounded_message(message: &str) -> String {
    message.chars().take(256).collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use rustferry_remote::{
        BuildProfile, BundleIdentifier, DevelopmentTeam, DevelopmentTeamPlan, DevicePlan,
        EntitlementPlan, EntitlementSet, IosDeviceProductExpectation, ProvisioningPlan,
        ProvisioningProfileType, SigningCertificate, SigningIdentity, SigningPlan,
        SigningPrivateKeyReference, SigningReference, SigningTarget, SigningTargetKind,
        SourceManifest, UnsignedNestedBundleExpectation, UnsignedNestedBundleKind,
    };
    use tempfile::tempdir;

    use crate::{
        transport::{GhRequest, TransportLimits},
        workflow::{
            ProtectedEnvironment, PublicSourceRepository, SigningSecretNames,
            TemporaryBranchNamespace, WorkerDistribution, WorkflowFileName,
        },
    };

    use super::*;

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const TRUSTED_TIP: &str = "123456789abcdef0123456789abcdef012345678";
    const DISPATCH_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";
    const TREE_SHA: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const WORKFLOW_BLOB: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const MANIFEST_BLOB: &str = "dddddddddddddddddddddddddddddddddddddddd";
    const BRANCH_BASE64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy9vcGVyYXRpb24tMQ==";
    const WORKFLOW_PATH_BASE64: &str =
        "LmdpdGh1Yi93b3JrZmxvd3MvcnVzdGZlcnJ5LWdvYWwzLWlwaG9uZS55bWw=";
    const SIGNING_ENVIRONMENT_BASE64: &str = "cnVzdGZlcnJ5LWdvYWwzLXNpZ25pbmc=";
    const SIGNING_BRANCH_POLICY_BASE64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy8q";
    const CERTIFICATE_P12_BASE64: &str = "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QMTI=";
    const CERTIFICATE_PASSWORD_BASE64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QQVNTV09SRA==";
    const PROVISIONING_PROFILE_BASE64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19QUk9WSVNJT05JTkdfUFJPRklMRQ==";
    const WIDGET_PROFILE_BASE64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19QUk9GSUxFXzI2NEI4RkUyNjhCMDAwOEIzNkYwOUJCNUNEMDA4RUE0";

    #[derive(Clone, Debug)]
    struct FixedClock(u64);

    impl ProviderClock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct DoctorArtifactStore;

    impl VerifiedArtifactStore for DoctorArtifactStore {
        fn supports_listing(&self) -> bool {
            true
        }

        fn supports_download(&self) -> bool {
            true
        }

        fn supports_removal(&self) -> bool {
            false
        }

        fn list_verified(
            &mut self,
            _context: &GithubArtifactContext,
        ) -> RemoteBuildResult<Vec<ArtifactManifest>> {
            Ok(Vec::new())
        }

        fn download_verified(
            &mut self,
            _context: &GithubArtifactContext,
            _request: &ArtifactDownloadRequest,
        ) -> RemoteBuildResult<ArtifactDownloadResult> {
            Err(unsupported(ProviderFeature::ArtifactDownload))
        }

        fn remove_artifacts(&mut self, _context: &GithubArtifactContext) -> RemoteBuildResult<()> {
            Err(unsupported(ProviderFeature::Cleanup))
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct FailingArtifactStore;

    impl VerifiedArtifactStore for FailingArtifactStore {
        fn supports_listing(&self) -> bool {
            true
        }

        fn supports_download(&self) -> bool {
            true
        }

        fn supports_removal(&self) -> bool {
            false
        }

        fn list_verified(
            &mut self,
            _context: &GithubArtifactContext,
        ) -> RemoteBuildResult<Vec<ArtifactManifest>> {
            Err(provider_failure(
                "artifact_fixture_rejected",
                "artifact fixture rejected",
                false,
            ))
        }

        fn download_verified(
            &mut self,
            _context: &GithubArtifactContext,
            _request: &ArtifactDownloadRequest,
        ) -> RemoteBuildResult<ArtifactDownloadResult> {
            Err(unsupported(ProviderFeature::ArtifactDownload))
        }

        fn remove_artifacts(&mut self, _context: &GithubArtifactContext) -> RemoteBuildResult<()> {
            Err(unsupported(ProviderFeature::Cleanup))
        }
    }

    #[derive(Clone, Debug, Default)]
    struct CapturingArtifactStore {
        contexts: Arc<Mutex<Vec<GithubArtifactContext>>>,
    }

    impl VerifiedArtifactStore for CapturingArtifactStore {
        fn supports_listing(&self) -> bool {
            true
        }

        fn supports_download(&self) -> bool {
            false
        }

        fn supports_removal(&self) -> bool {
            false
        }

        fn list_verified(
            &mut self,
            context: &GithubArtifactContext,
        ) -> RemoteBuildResult<Vec<ArtifactManifest>> {
            self.contexts
                .lock()
                .expect("contexts")
                .push(context.clone());
            Ok(Vec::new())
        }

        fn download_verified(
            &mut self,
            _context: &GithubArtifactContext,
            _request: &ArtifactDownloadRequest,
        ) -> RemoteBuildResult<ArtifactDownloadResult> {
            Err(unsupported(ProviderFeature::ArtifactDownload))
        }

        fn remove_artifacts(&mut self, _context: &GithubArtifactContext) -> RemoteBuildResult<()> {
            Err(unsupported(ProviderFeature::Cleanup))
        }
    }

    #[derive(Debug, Default)]
    struct FakePublisher {
        published: Vec<CapturedPublication>,
        deletions: Vec<CapturedDeletion>,
        failure: Option<TemporaryRefPublishFailure>,
        delete_failure: Option<TemporaryRefPublishError>,
        cancel_on_publish: Option<CancellationToken>,
        returned_temporary_ref: Option<TemporaryGitRef>,
    }

    #[derive(Debug)]
    struct CapturedPublication {
        source_revision: String,
        branch: String,
        workflow_path: String,
        workflow_sha256: String,
        manifest: GithubDispatchManifest,
        authorized: bool,
    }

    #[derive(Debug)]
    struct CapturedDeletion {
        branch: String,
        expected_commit: String,
        authorized: bool,
    }

    impl TemporaryRefPublisher for FakePublisher {
        fn doctor(
            &mut self,
            _request: &TemporaryRefDoctorRequest<'_>,
        ) -> Result<TemporaryRefPublisherReadiness, TemporaryRefPublishError> {
            Ok(TemporaryRefPublisherReadiness {
                trusted_ref_tip: CommitSha::new(TRUSTED_TIP).expect("trusted tip"),
            })
        }

        fn publish(
            &mut self,
            request: &TemporaryRefPublishRequest<'_>,
        ) -> Result<PublishedTemporaryRef, TemporaryRefPublishFailure> {
            if let Some(token) = self.cancel_on_publish.take() {
                token.cancel();
            }
            if let Some(failure) = self.failure.take() {
                return Err(failure);
            }
            self.published.push(CapturedPublication {
                source_revision: request.source_revision.as_str().to_owned(),
                branch: request.temporary_ref.branch().as_str().to_owned(),
                workflow_path: request.workflow_path.to_owned(),
                workflow_sha256: hex_sha256(request.workflow_bytes),
                manifest: serde_json::from_slice(request.manifest_bytes)
                    .expect("strict manifest JSON"),
                authorized: request.authorized,
            });
            Ok(PublishedTemporaryRef::new(
                self.returned_temporary_ref
                    .clone()
                    .unwrap_or_else(|| request.temporary_ref.clone()),
                CommitSha::new(DISPATCH_SHA).expect("dispatch SHA"),
            ))
        }

        fn delete_temporary_ref(
            &mut self,
            request: &TemporaryRefDeleteRequest<'_>,
        ) -> Result<(), TemporaryRefPublishError> {
            self.deletions.push(CapturedDeletion {
                branch: request.temporary_ref.branch().as_str().to_owned(),
                expected_commit: request.expected_commit.as_str().to_owned(),
                authorized: request.authorized,
            });
            if let Some(error) = self.delete_failure.take() {
                return Err(error);
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeGhRunner {
        responses: VecDeque<Result<Vec<u8>, GhExecutionError>>,
        requests: Arc<Mutex<Vec<GhRequest>>>,
    }

    impl FakeGhRunner {
        fn with(responses: impl IntoIterator<Item = Result<Vec<u8>, GhExecutionError>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl GhRunner for FakeGhRunner {
        fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
            self.requests
                .lock()
                .expect("request capture")
                .push(request.clone());
            self.responses.pop_front().expect("unexpected gh request")
        }
    }

    #[derive(Clone, Debug)]
    struct CapturedGitInvocation {
        arguments: Vec<OsString>,
        stdin_len: usize,
        environment: Vec<(OsString, OsString)>,
    }

    #[derive(Debug, Default)]
    struct FakeGitRunner {
        responses: VecDeque<Result<Vec<u8>, GitExecutionError>>,
        invocations: Vec<CapturedGitInvocation>,
    }

    impl FakeGitRunner {
        fn with(responses: impl IntoIterator<Item = Result<Vec<u8>, GitExecutionError>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                invocations: Vec::new(),
            }
        }
    }

    impl GitRunner for FakeGitRunner {
        fn execute(&mut self, invocation: &GitInvocation) -> Result<Vec<u8>, GitExecutionError> {
            self.invocations.push(CapturedGitInvocation {
                arguments: invocation.arguments().to_vec(),
                stdin_len: invocation.stdin_len(),
                environment: invocation.environment().to_vec(),
            });
            self.responses
                .pop_front()
                .expect("unexpected git invocation")
        }
    }

    fn workflow_config_with_secret_names(secret_names: SigningSecretNames) -> WorkflowConfig {
        WorkflowConfig::new(
            WorkflowFileName::new("rustferry-goal3-iphone.yml").expect("workflow name"),
            ProtectedEnvironment::new("rustferry-goal3-signing").expect("environment"),
            secret_names,
            WorkerDistribution::new(
                "https://github.com/ShiroKSH/rust-and-iphone/releases/download/v0.1.0/ferry-worker-macos",
                "0".repeat(64),
                "0.1.0",
            )
            .expect("worker"),
            PublicSourceRepository::new("shiroksh/rust-and-iphone")
                .expect("source repository"),
            TrustedSourceRef::new("refs/heads/goal3/macless-iphone-builds")
                .expect("trusted ref"),
            TemporaryBranchNamespace::new("rustferry/goal3/builds").expect("namespace"),
        )
        .expect("workflow config")
    }

    fn workflow_config() -> WorkflowConfig {
        workflow_config_with_secret_names(SigningSecretNames::goal3_defaults())
    }

    fn same_repository_provider_config(
        authorization: GithubMutationAuthorization,
    ) -> GithubProviderConfig {
        let workflow = workflow_config();
        let fingerprint = WorkflowFingerprint::for_workflow(&generate_workflow(&workflow));
        GithubProviderConfig::new(
            Repository::new("ShiroKSH", "rust-and-iphone").expect("repository"),
            "https://github.com/shiroksh/rust-and-iphone",
            workflow,
            fingerprint,
            GithubPollingPolicy::new(3, Duration::from_millis(250)).expect("poll policy"),
            authorization,
            &Version::new(0, 1, 0),
            8,
        )
        .expect("provider config")
    }

    fn provider_config(authorization: GithubMutationAuthorization) -> GithubProviderConfig {
        let workflow = workflow_config();
        let fingerprint = WorkflowFingerprint::for_workflow(&generate_workflow(&workflow));
        GithubProviderConfig::new(
            Repository::new("ShiroKSH", "rustferry-signing").expect("execution repository"),
            "https://github.com/shiroksh/rust-and-iphone",
            workflow,
            fingerprint,
            GithubPollingPolicy::new(3, Duration::from_millis(250)).expect("poll policy"),
            authorization,
            &Version::new(0, 1, 0),
            8,
        )
        .expect("split provider config")
    }

    fn provider_config_with_secret_names(
        authorization: GithubMutationAuthorization,
        secret_names: SigningSecretNames,
    ) -> GithubProviderConfig {
        let workflow = workflow_config_with_secret_names(secret_names);
        let fingerprint = WorkflowFingerprint::for_workflow(&generate_workflow(&workflow));
        GithubProviderConfig::new(
            Repository::new("ShiroKSH", "rustferry-signing").expect("execution repository"),
            "https://github.com/shiroksh/rust-and-iphone",
            workflow,
            fingerprint,
            GithubPollingPolicy::new(3, Duration::from_millis(250)).expect("poll policy"),
            authorization,
            &Version::new(0, 1, 0),
            8,
        )
        .expect("split provider config")
    }

    fn transport(runner: FakeGhRunner) -> GithubTransport<FakeGhRunner> {
        GithubTransport::new(runner, TransportLimits::secure_defaults())
    }

    fn private_repository_row() -> Vec<u8> {
        b"991\tShiroKSH/rustferry-signing\ttrue\tfalse\tfalse\tmain\n".to_vec()
    }

    fn public_source_repository_row() -> Vec<u8> {
        b"992\tShiroKSH/rust-and-iphone\tfalse\tfalse\tfalse\tmain\n".to_vec()
    }

    fn private_source_repository_row() -> Vec<u8> {
        b"992\tShiroKSH/rust-and-iphone\ttrue\tfalse\tfalse\tmain\n".to_vec()
    }

    fn signed_transport(mut runner: FakeGhRunner) -> GithubTransport<FakeGhRunner> {
        runner.responses.push_front(Ok(exact_signing_secret_rows()));
        runner.responses.push_front(Ok(exact_signing_policy_row()));
        runner
            .responses
            .push_front(Ok(signing_environment_row(false, true, true)));
        runner.responses.push_front(Ok(private_repository_row()));
        runner
            .responses
            .push_front(Ok(public_source_repository_row()));
        transport(runner)
    }

    fn valid_request() -> IosDeviceBuildRequest {
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("team");
        let secret =
            |name| SecretReference::new(SecretReferenceKind::GithubActions, name).expect("secret");
        let signing = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: SigningCertificate {
                        common_name: "Apple Development".to_owned(),
                        sha256_fingerprint: "A".repeat(64),
                        team: team.clone(),
                        expires_at_unix_seconds: u64::MAX,
                    },
                    private_key: SigningPrivateKeyReference {
                        reference: secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12"),
                    },
                },
                password: Some(secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD")),
            }),
            team: Some(DevelopmentTeamPlan {
                expected: team.clone(),
            }),
            device: Some(DevicePlan::from_sha256("0".repeat(64), None).expect("device")),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: secret("RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).expect("entitlements"),
            }],
            allow_provisioning_updates: false,
        };
        let request = IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-1".to_owned(),
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
            profile: BuildProfile::Release,
            source_mode: SourceMode::Git,
            source_repository: Some("https://github.com/shiroksh/rust-and-iphone".to_owned()),
            source_revision: Some(SOURCE_SHA.to_owned()),
            source: empty_source_manifest(),
            signing,
            requested_artifacts: BTreeSet::from([
                IosArtifactType::Ipa,
                IosArtifactType::SigningReport,
            ]),
        };
        request.validate().expect("valid Git request");
        request
    }

    fn multi_profile_request() -> (IosDeviceBuildRequest, SigningSecretNames) {
        let mut request = valid_request();
        let targets = vec![
            request.signing.targets[0].clone(),
            SigningTarget {
                name: "Widget".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app.widget")
                    .expect("widget bundle"),
                kind: SigningTargetKind::Extension,
            },
        ];
        let names = SigningSecretNames::for_targets(&targets).expect("profile names");
        let secret = |name: &str| {
            SecretReference::new(SecretReferenceKind::GithubActions, name).expect("secret")
        };
        request.signing.targets = targets;
        request.product.nested_bundles = vec![UnsignedNestedBundleExpectation {
            relative_path: "PlugIns/Widget.appex".to_owned(),
            bundle_identifier: "com.example.app.widget".to_owned(),
            executable: "Widget".to_owned(),
            kind: UnsignedNestedBundleKind::AppExtension,
        }];
        request.signing.provisioning = vec![
            ProvisioningPlan {
                target: "App".to_owned(),
                profile: secret(
                    names
                        .profile_for_target("App")
                        .expect("application profile")
                        .as_str(),
                ),
                profile_type: ProvisioningProfileType::Development,
            },
            ProvisioningPlan {
                target: "Widget".to_owned(),
                profile: secret(
                    names
                        .profile_for_target("Widget")
                        .expect("widget profile")
                        .as_str(),
                ),
                profile_type: ProvisioningProfileType::Development,
            },
        ];
        request.signing.entitlements.push(EntitlementPlan {
            target: "Widget".to_owned(),
            required: EntitlementSet::new(BTreeMap::new()).expect("widget entitlements"),
        });
        request.validate().expect("valid multi-profile request");
        (request, names)
    }

    fn multi_profile_request_with_framework() -> (IosDeviceBuildRequest, SigningSecretNames) {
        let (mut request, _) = multi_profile_request();
        request.signing.targets.push(SigningTarget {
            name: "RuntimeBridge".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app.runtime-bridge")
                .expect("framework bundle"),
            kind: SigningTargetKind::Framework,
        });
        request
            .product
            .nested_bundles
            .push(UnsignedNestedBundleExpectation {
                relative_path: "Frameworks/RuntimeBridge.framework".to_owned(),
                bundle_identifier: "com.example.app.runtime-bridge".to_owned(),
                executable: "RuntimeBridge".to_owned(),
                kind: UnsignedNestedBundleKind::Framework,
            });
        request
            .product
            .nested_bundles
            .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        request
            .validate()
            .expect("valid multi-profile request with framework");
        let names = SigningSecretNames::for_targets(&request.signing.targets)
            .expect("framework-bound profile names");
        (request, names)
    }

    fn assert_signing_reference_mismatch(
        config: &GithubProviderConfig,
        request: &IosDeviceBuildRequest,
    ) {
        let error = validate_submission(config, request)
            .expect_err("configured signing target graph must remain exact");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure {
                code,
                retryable: false,
                ..
            } if code == "signing_secret_reference_mismatch"
        ));
    }

    fn unsigned_request() -> IosDeviceBuildRequest {
        let mut request = valid_request();
        request.signing.mode = SigningMode::UnsignedCompileOnly;
        request.signing.signing = None;
        request.signing.team = None;
        request.signing.device = None;
        request.signing.provisioning.clear();
        request.requested_artifacts = BTreeSet::from([IosArtifactType::Xcarchive]);
        request.validate().expect("valid unsigned Git request");
        request
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
            sha256: hex::encode(digest.finalize()),
        }
    }

    fn poll_ready<T>(mut future: ProviderFuture<'_, T>) -> RemoteBuildResult<T> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("provider future unexpectedly pending"),
        }
    }

    fn all_authorized() -> GithubMutationAuthorization {
        GithubMutationAuthorization {
            publish_temporary_ref: true,
            cancel_run: true,
            delete_temporary_ref: true,
        }
    }

    fn completed_run_row(conclusion: &str) -> Vec<u8> {
        format!(
            "41\t17\t{WORKFLOW_PATH_BASE64}\t9\t1\t{DISPATCH_SHA}\t{BRANCH_BASE64}\tpush\tcompleted\t{conclusion}\n"
        )
        .into_bytes()
    }

    fn signing_environment_row(
        protected_branches: bool,
        custom_branch_policies: bool,
        required_reviewers: bool,
    ) -> Vec<u8> {
        format!(
            "{SIGNING_ENVIRONMENT_BASE64}\t{protected_branches}\t{custom_branch_policies}\t{required_reviewers}\n"
        )
        .into_bytes()
    }

    fn exact_signing_policy_row() -> Vec<u8> {
        format!("361471\t{SIGNING_BRANCH_POLICY_BASE64}\n").into_bytes()
    }

    fn exact_signing_secret_rows() -> Vec<u8> {
        format!(
            "{CERTIFICATE_P12_BASE64}\n{CERTIFICATE_PASSWORD_BASE64}\n{PROVISIONING_PROFILE_BASE64}\n"
        )
        .into_bytes()
    }

    fn signed_doctor_report(
        environment: Result<Vec<u8>, GhExecutionError>,
        policies: Result<Vec<u8>, GhExecutionError>,
        secrets: Result<Vec<u8>, GhExecutionError>,
    ) -> ProviderDoctorReport {
        signed_doctor_report_with_visibility(true, environment, policies, secrets)
    }

    fn signed_doctor_report_with_visibility(
        private: bool,
        environment: Result<Vec<u8>, GhExecutionError>,
        policies: Result<Vec<u8>, GhExecutionError>,
        secrets: Result<Vec<u8>, GhExecutionError>,
    ) -> ProviderDoctorReport {
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(FakeGhRunner::with([
                Ok(b"ShiroKSH\n".to_vec()),
                Ok(
                    format!("991\tShiroKSH/rustferry-signing\t{private}\tfalse\tfalse\tmain\n")
                        .into_bytes(),
                ),
                Ok(b"992\tShiroKSH/rust-and-iphone\tfalse\tfalse\tfalse\tmain\n".to_vec()),
                environment,
                policies,
                secrets,
            ])),
            FakePublisher::default(),
            DoctorArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: "signed-doctor".to_owned(),
                require_signing: true,
            },
            CancellationToken::new(),
        ))
        .expect("doctor report")
    }

    #[test]
    fn workflow_fingerprint_is_exact_lowercase_sha256() {
        let workflow = generate_workflow(&workflow_config());
        let fingerprint = WorkflowFingerprint::for_workflow(&workflow);
        assert!(is_lower_sha256(fingerprint.as_str()));
        assert_eq!(fingerprint, WorkflowFingerprint::for_workflow(&workflow));
        assert!(WorkflowFingerprint::new("A".repeat(64)).is_err());
    }

    #[test]
    fn git_process_environment_excludes_ambient_tokens_and_signing_material() {
        let mut command = Command::new("git");
        command
            .env("GH_TOKEN", "token-canary")
            .env("GITHUB_TOKEN", "token-canary")
            .env("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD", "secret-canary");
        apply_allowlisted_git_environment(&mut command);

        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert!(
            names
                .iter()
                .all(|name| GIT_AMBIENT_ENVIRONMENT_ALLOWLIST.contains(&name.as_str()))
        );
        assert!(!names.contains("GH_TOKEN"));
        assert!(!names.contains("GITHUB_TOKEN"));
        assert!(!names.contains("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD"));
    }

    #[test]
    fn git_executable_basename_is_platform_exact() {
        #[cfg(windows)]
        assert!(executable_basename_matches(
            Path::new(r"C:\Git\git.exe"),
            "git"
        ));
        #[cfg(not(windows))]
        assert!(executable_basename_matches(
            Path::new("/usr/bin/git"),
            "git"
        ));
        assert!(!executable_basename_matches(
            Path::new("/usr/bin/not-git"),
            "git"
        ));
    }

    #[test]
    fn github_remote_identity_accepts_equivalent_https_and_ssh_transports() {
        let expected = "https://github.com/ShiroKSH/rust-and-iphone";
        for actual in [
            expected,
            "https://github.com/ShiroKSH/rust-and-iphone.git",
            "git@github.com:ShiroKSH/rust-and-iphone.git",
            "ssh://git@github.com/ShiroKSH/rust-and-iphone",
        ] {
            assert!(github_remote_matches(actual, expected), "{actual}");
        }
        for actual in [
            "https://github.com/attacker/rust-and-iphone",
            "git@github.com:attacker/rust-and-iphone.git",
            "ssh://git@github.example/ShiroKSH/rust-and-iphone",
            "https://github.com/ShiroKSH/rust-and-iphone/extra",
        ] {
            assert!(!github_remote_matches(actual, expected), "{actual}");
        }
    }

    #[test]
    fn config_accepts_distinct_source_and_rejects_invalid_source_digest_and_worker_version() {
        let workflow = workflow_config();
        let fingerprint = WorkflowFingerprint::for_workflow(&generate_workflow(&workflow));
        let repository = Repository::new("ShiroKSH", "rustferry-signing").expect("repository");
        let split = GithubProviderConfig::new(
            repository.clone(),
            "https://github.com/shiroksh/rust-and-iphone",
            workflow.clone(),
            fingerprint.clone(),
            GithubPollingPolicy::secure_defaults(),
            all_authorized(),
            &Version::new(0, 1, 0),
            8,
        )
        .expect("distinct source and execution repositories");
        assert_eq!(split.repository(), &repository);
        assert_eq!(
            split.source_repository(),
            "https://github.com/shiroksh/rust-and-iphone"
        );
        assert_eq!(
            GithubProviderConfig::new(
                repository.clone(),
                "https://github.com/ShiroKSH/rust-and-iphone",
                workflow.clone(),
                fingerprint.clone(),
                GithubPollingPolicy::secure_defaults(),
                all_authorized(),
                &Version::new(0, 1, 0),
                8,
            ),
            Err(GithubProviderConfigError::InvalidSourceRepository)
        );
        assert_eq!(
            GithubProviderConfig::new(
                repository.clone(),
                "https://github.com/shiroksh/rust-and-iphone",
                workflow.clone(),
                WorkflowFingerprint::new("f".repeat(64)).expect("fingerprint"),
                GithubPollingPolicy::secure_defaults(),
                all_authorized(),
                &Version::new(0, 1, 0),
                8,
            ),
            Err(GithubProviderConfigError::WorkflowFingerprintMismatch)
        );
        assert_eq!(
            GithubProviderConfig::new(
                repository,
                "https://github.com/shiroksh/rust-and-iphone",
                workflow.clone(),
                WorkflowFingerprint::for_workflow(&generate_workflow(&workflow)),
                GithubPollingPolicy::secure_defaults(),
                all_authorized(),
                &Version::new(0, 2, 0),
                8,
            ),
            Err(GithubProviderConfigError::WorkerVersionMismatch)
        );
    }

    #[test]
    fn split_repository_artifact_context_keeps_execution_and_source_identities_separate() {
        let workflow = workflow_config();
        let fingerprint = WorkflowFingerprint::for_workflow(&generate_workflow(&workflow));
        let config = GithubProviderConfig::new(
            Repository::new("ShiroKSH", "rustferry-signing").expect("execution repository"),
            "https://github.com/shiroksh/rust-and-iphone",
            workflow,
            fingerprint,
            GithubPollingPolicy::new(3, Duration::from_millis(250)).expect("poll policy"),
            all_authorized(),
            &Version::new(0, 1, 0),
            8,
        )
        .expect("split repository config");
        let runner = FakeGhRunner::with([
            Ok(completed_run_row("success")),
            Ok(completed_run_row("success")),
        ]);
        let requests = Arc::clone(&runner.requests);
        let artifacts = CapturingArtifactStore::default();
        let contexts = Arc::clone(&artifacts.contexts);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            transport(runner),
            FakePublisher::default(),
            artifacts,
            FixedClock(1_700_000_000_000),
        );

        poll_ready(provider.submit(unsigned_request(), CancellationToken::new())).expect("submit");
        poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("events");

        let captured = contexts.lock().expect("contexts");
        let context = captured.first().expect("artifact context");
        assert_eq!(context.repository.owner(), "ShiroKSH");
        assert_eq!(context.repository.name(), "rustferry-signing");
        assert_eq!(
            context.source_repository,
            "https://github.com/shiroksh/rust-and-iphone"
        );
        assert_eq!(
            context.request.source_repository.as_deref(),
            Some(context.source_repository.as_str())
        );
        assert_eq!(context.run.handle().head_sha(), &context.dispatch_revision);
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            request
                .endpoint()
                .starts_with("/repos/ShiroKSH/rustferry-signing/actions/")
        }));
    }

    #[test]
    fn production_doctor_rejects_trusted_tip_workflow_byte_mismatch() {
        let config = same_repository_provider_config(all_authorized());
        let workflow_path = config.workflow.filename().repository_path();
        let responses = [
            Ok(b"https://github.com/ShiroKSH/rust-and-iphone\n".to_vec()),
            Ok(b"git@github.com:ShiroKSH/rust-and-iphone.git\n".to_vec()),
            Ok(format!(
                "{TRUSTED_TIP}\t{}\n",
                config.workflow.trusted_source_ref().as_str()
            )
            .into_bytes()),
            Ok(Vec::new()),
            Ok(b"name: unapproved\n".to_vec()),
        ];
        let directory = tempdir().expect("isolation directory");
        let mut publisher = GitTemporaryRefPublisher::new(
            FakeGitRunner::with(responses),
            directory.path(),
            "origin",
            "origin",
            Duration::from_secs(5),
        )
        .expect("publisher");
        let error = publisher
            .doctor(&TemporaryRefDoctorRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                trusted_source_ref: config.workflow.trusted_source_ref(),
                workflow_path: &workflow_path,
                workflow_fingerprint: &config.workflow_fingerprint,
            })
            .expect_err("unapproved trusted-tip workflow bytes");
        assert_eq!(error, TemporaryRefPublishError::WorkflowFingerprintMismatch);
    }

    #[test]
    fn git_publisher_rejects_a_mismatched_push_url_before_network_access() {
        let config = same_repository_provider_config(all_authorized());
        let workflow_path = config.workflow.filename().repository_path();
        let runner = FakeGitRunner::with([
            Ok(b"git@github.com:ShiroKSH/rust-and-iphone.git\n".to_vec()),
            Ok(b"git@github.com:attacker/rust-and-iphone.git\n".to_vec()),
        ]);
        let directory = tempdir().expect("isolation directory");
        let mut publisher = GitTemporaryRefPublisher::new(
            runner,
            directory.path(),
            "origin",
            "origin",
            Duration::from_secs(5),
        )
        .expect("publisher");

        let error = publisher
            .doctor(&TemporaryRefDoctorRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                trusted_source_ref: config.workflow.trusted_source_ref(),
                workflow_path: &workflow_path,
                workflow_fingerprint: &config.workflow_fingerprint,
            })
            .expect_err("mismatched push URL");
        assert_eq!(error, TemporaryRefPublishError::RemoteMismatch);
        let runner = publisher.into_runner();
        assert_eq!(runner.invocations.len(), 2);
        assert!(runner.responses.is_empty());
    }

    #[test]
    fn provider_doctor_accepts_approved_branch_only_workflow_without_numeric_registration() {
        let transport_responses = [
            Ok(b"ShiroKSH\n".to_vec()),
            Ok(b"991\tShiroKSH/rust-and-iphone\tfalse\tfalse\tfalse\tmain\n".to_vec()),
        ];
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            same_repository_provider_config(all_authorized()),
            transport(FakeGhRunner::with(transport_responses)),
            FakePublisher::default(),
            DoctorArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let report = poll_ready(provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: "doctor-1".to_owned(),
                require_signing: false,
            },
            CancellationToken::new(),
        ))
        .expect("doctor report");
        assert!(report.ready);
        assert!(report.checks.iter().any(|check| {
            check.code == "github.trusted_source" && check.status == ProviderCheckStatus::Ready
        }));
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.code != "github.workflow_registration")
        );
    }

    #[test]
    fn provider_doctor_rejects_a_private_source_repository() {
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(FakeGhRunner::with([
                Ok(b"ShiroKSH\n".to_vec()),
                Ok(b"991\tShiroKSH/rustferry-signing\ttrue\tfalse\tfalse\tmain\n".to_vec()),
                Ok(b"992\tShiroKSH/rust-and-iphone\ttrue\tfalse\tfalse\tmain\n".to_vec()),
            ])),
            FakePublisher::default(),
            DoctorArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let report = poll_ready(provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: "private-source-doctor".to_owned(),
                require_signing: false,
            },
            CancellationToken::new(),
        ))
        .expect("doctor report");
        assert!(!report.ready);
        assert!(report.checks.iter().any(|check| {
            check.code == "github.source_repository_visibility"
                && check.status == ProviderCheckStatus::Error
        }));
    }

    #[test]
    fn signed_doctor_requires_exact_environment_policy_and_secret_metadata() {
        let report = signed_doctor_report(
            Ok(signing_environment_row(false, true, true)),
            Ok(exact_signing_policy_row()),
            Ok(exact_signing_secret_rows()),
        );

        assert!(report.ready);
        for code in [
            "github.signing_environment",
            "github.signing_branch_policy",
            "github.signing_secrets",
            "github.signing_environment.reviewers",
        ] {
            assert!(
                report.checks.iter().any(|check| {
                    check.code == code && check.status == ProviderCheckStatus::Ready
                })
            );
        }
    }

    #[test]
    fn multi_profile_secret_metadata_requires_the_exact_configured_set() {
        let (_request, names) = multi_profile_request();
        let config = provider_config_with_secret_names(all_authorized(), names);
        let exact_rows = format!(
            "{CERTIFICATE_P12_BASE64}\n{CERTIFICATE_PASSWORD_BASE64}\n{PROVISIONING_PROFILE_BASE64}\n{WIDGET_PROFILE_BASE64}\n"
        )
        .into_bytes();
        let mut checks = Vec::new();
        append_signing_secret_check(
            &mut checks,
            &mut transport(FakeGhRunner::with([Ok(exact_rows)])),
            &config,
        );
        assert!(checks.iter().any(|check| {
            check.code == "github.signing_secrets" && check.status == ProviderCheckStatus::Ready
        }));

        let mut checks = Vec::new();
        append_signing_secret_check(
            &mut checks,
            &mut transport(FakeGhRunner::with([Ok(exact_signing_secret_rows())])),
            &config,
        );
        assert!(checks.iter().any(|check| {
            check.code == "github.signing_secrets" && check.status == ProviderCheckStatus::Error
        }));
    }

    #[test]
    fn signed_doctor_rejects_a_public_execution_repository() {
        let report = signed_doctor_report_with_visibility(
            false,
            Ok(signing_environment_row(false, true, true)),
            Ok(exact_signing_policy_row()),
            Ok(exact_signing_secret_rows()),
        );

        assert!(!report.ready);
        assert!(report.checks.iter().any(|check| {
            check.code == "github.signing_repository_visibility"
                && check.status == ProviderCheckStatus::Error
        }));
    }

    #[test]
    fn signed_doctor_requires_server_side_reviewer_approval() {
        let report = signed_doctor_report(
            Ok(signing_environment_row(false, true, false)),
            Ok(exact_signing_policy_row()),
            Ok(exact_signing_secret_rows()),
        );

        assert!(!report.ready);
        assert!(report.checks.iter().any(|check| {
            check.code == "github.signing_environment.reviewers"
                && check.status == ProviderCheckStatus::Error
        }));
    }

    #[test]
    fn signed_doctor_fails_closed_on_missing_or_mismatched_production_evidence() {
        let cases = [
            (
                "environment API unavailable",
                Err(GhExecutionError::CommandFailed {
                    exit_code: Some(1),
                }),
                Ok(exact_signing_policy_row()),
                Ok(exact_signing_secret_rows()),
                "github.signing_environment",
            ),
            (
                "environment policy flags",
                Ok(signing_environment_row(true, true, true)),
                Ok(exact_signing_policy_row()),
                Ok(exact_signing_secret_rows()),
                "github.signing_environment",
            ),
            (
                "deployment branch policy",
                Ok(signing_environment_row(false, true, true)),
                Ok(b"361471\tbWFpbg==\n".to_vec()),
                Ok(exact_signing_secret_rows()),
                "github.signing_branch_policy",
            ),
            (
                "unexpected deployment branch policy",
                Ok(signing_environment_row(false, true, true)),
                Ok(format!("361471\t{SIGNING_BRANCH_POLICY_BASE64}\n361472\tbWFpbg==\n")
                    .into_bytes()),
                Ok(exact_signing_secret_rows()),
                "github.signing_branch_policy",
            ),
            (
                "missing signing secret",
                Ok(signing_environment_row(false, true, true)),
                Ok(exact_signing_policy_row()),
                Ok(format!("{CERTIFICATE_P12_BASE64}\n{CERTIFICATE_PASSWORD_BASE64}\n")
                    .into_bytes()),
                "github.signing_secrets",
            ),
            (
                "unexpected signing secret",
                Ok(signing_environment_row(false, true, true)),
                Ok(exact_signing_policy_row()),
                Ok(format!(
                    "{CERTIFICATE_P12_BASE64}\n{CERTIFICATE_PASSWORD_BASE64}\n{PROVISIONING_PROFILE_BASE64}\nRVhUUkE=\n"
                )
                .into_bytes()),
                "github.signing_secrets",
            ),
        ];

        for (name, environment, policies, secrets, expected_error) in cases {
            let report = signed_doctor_report(environment, policies, secrets);
            assert!(!report.ready, "accepted {name}");
            assert!(
                report.checks.iter().any(|check| {
                    check.code == expected_error && check.status == ProviderCheckStatus::Error
                }),
                "missing error for {name}"
            );
        }
    }

    #[test]
    fn strict_dispatch_manifest_rejects_unknown_fields() {
        let config = provider_config(all_authorized());
        let temporary_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
        )
        .expect("temporary ref");
        let manifest = GithubDispatchManifest::new(&config, &temporary_ref, valid_request());
        manifest.validate_for(&config).expect("valid manifest");
        assert!(github_remote_matches(
            &manifest.execution_repository,
            &repository_url(&config.repository)
        ));
        let mut wrong_execution = manifest.clone();
        wrong_execution.execution_repository =
            "https://github.com/shiroksh/other-signing".to_owned();
        assert!(wrong_execution.validate_for(&config).is_err());
        let mut value = serde_json::to_value(manifest).expect("manifest value");
        value
            .as_object_mut()
            .expect("object")
            .insert("future_shell".to_owned(), serde_json::json!("cargo build"));
        assert!(serde_json::from_value::<GithubDispatchManifest>(value).is_err());
    }

    #[test]
    fn operation_ids_must_be_single_safe_ref_segments() {
        for invalid in [
            "",
            "-job",
            "job/child",
            "job:child",
            "job..child",
            "job.lock",
        ] {
            assert!(
                validate_ref_segment(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(validate_ref_segment("operation-1.test_case").is_ok());
    }

    #[test]
    fn unauthorized_git_publication_executes_nothing() {
        let directory = tempdir().expect("isolation directory");
        let runner = FakeGitRunner::default();
        let mut publisher = GitTemporaryRefPublisher::new(
            runner,
            directory.path(),
            "origin",
            "origin",
            Duration::from_secs(5),
        )
        .expect("publisher");
        let config = provider_config(all_authorized());
        let workflow = generate_workflow(&config.workflow);
        let temporary_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
        )
        .expect("temporary ref");
        let error = publisher
            .publish(&TemporaryRefPublishRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                trusted_source_ref: config.workflow.trusted_source_ref(),
                source_revision: &CommitSha::new(SOURCE_SHA).expect("source"),
                temporary_ref: &temporary_ref,
                workflow_path: workflow.path(),
                workflow_bytes: workflow.yaml().as_bytes(),
                workflow_fingerprint: &config.workflow_fingerprint,
                manifest_bytes: b"{}\n",
                operation_id: "operation-1",
                created_at_ms: 1_700_000_000_000,
                authorized: false,
            })
            .expect_err("authorization required");
        assert_eq!(error.error(), TemporaryRefPublishError::Unauthorized);
        assert!(publisher.into_runner().invocations.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn git_publisher_creates_an_orphan_two_file_dispatch_commit() {
        let full_trusted_ref = "refs/heads/goal3/macless-iphone-builds";
        let full_temporary_ref = "refs/heads/rustferry/goal3/builds/operation-1";
        let config = provider_config(all_authorized());
        let workflow = generate_workflow(&config.workflow);
        let responses = [
            Ok(b"git@github.com:ShiroKSH/rust-and-iphone.git\n".to_vec()),
            Ok(b"ssh://git@github.com/ShiroKSH/rust-and-iphone\n".to_vec()),
            Ok(b"git@github.com:ShiroKSH/rustferry-signing.git\n".to_vec()),
            Ok(b"ssh://git@github.com/ShiroKSH/rustferry-signing\n".to_vec()),
            Ok(format!("{TRUSTED_TIP}\t{full_trusted_ref}\n").into_bytes()),
            Ok(Vec::new()),
            Ok(workflow.yaml().as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(format!("{WORKFLOW_BLOB}\n").into_bytes()),
            Ok(format!("{MANIFEST_BLOB}\n").into_bytes()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(format!("{TREE_SHA}\n").into_bytes()),
            Ok(format!("{DISPATCH_SHA}\n").into_bytes()),
            Ok(Vec::new()),
            Ok(format!("{DISPATCH_SHA}\t{full_temporary_ref}\n").into_bytes()),
        ];
        let directory = tempdir().expect("isolation directory");
        let runner = FakeGitRunner::with(responses);
        let mut publisher = GitTemporaryRefPublisher::new(
            runner,
            directory.path(),
            "source",
            "execution",
            Duration::from_secs(5),
        )
        .expect("publisher");
        let temporary_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
        )
        .expect("temporary ref");
        let publication = publisher
            .publish(&TemporaryRefPublishRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                trusted_source_ref: config.workflow.trusted_source_ref(),
                source_revision: &CommitSha::new(SOURCE_SHA).expect("source"),
                temporary_ref: &temporary_ref,
                workflow_path: workflow.path(),
                workflow_bytes: workflow.yaml().as_bytes(),
                workflow_fingerprint: &config.workflow_fingerprint,
                manifest_bytes: b"{\"schema_version\":1}\n",
                operation_id: "operation-1",
                created_at_ms: 1_700_000_000_000,
                authorized: true,
            })
            .expect("publication");
        assert_eq!(publication.commit().as_str(), DISPATCH_SHA);
        let runner = publisher.into_runner();
        assert!(runner.responses.is_empty());
        assert!(runner.invocations.iter().all(|invocation| {
            !invocation.arguments.iter().any(|argument| {
                matches!(
                    argument.to_str(),
                    Some("checkout" | "switch" | "branch" | "commit")
                )
            })
        }));
        assert!(runner.invocations.iter().all(|invocation| {
            !matches!(
                invocation
                    .arguments
                    .first()
                    .and_then(|argument| argument.to_str()),
                Some("read-tree" | "ls-files")
            ) && !invocation
                .arguments
                .contains(&OsString::from("--force-remove"))
        }));
        let indexed_paths = runner
            .invocations
            .iter()
            .filter(|invocation| {
                invocation.arguments.first() == Some(&OsString::from("update-index"))
            })
            .filter_map(|invocation| invocation.arguments.last()?.to_str())
            .collect::<Vec<_>>();
        assert_eq!(
            indexed_paths,
            [
                ".github/workflows/rustferry-goal3-iphone.yml",
                DISPATCH_MANIFEST_PATH,
            ]
        );
        let push = runner
            .invocations
            .iter()
            .find(|invocation| invocation.arguments.first() == Some(&OsString::from("push")))
            .expect("push invocation");
        assert!(push.arguments.contains(&OsString::from("--no-verify")));
        assert!(push.arguments.contains(&OsString::from(format!(
            "--force-with-lease={full_temporary_ref}:"
        ))));
        assert!(push.arguments.contains(&OsString::from(format!(
            "{DISPATCH_SHA}:{full_temporary_ref}"
        ))));
        assert!(push.arguments.contains(&OsString::from(
            "ssh://git@github.com/ShiroKSH/rustferry-signing"
        )));
        let fetch = runner
            .invocations
            .iter()
            .find(|invocation| invocation.arguments.first() == Some(&OsString::from("fetch")))
            .expect("trusted-ref fetch");
        assert!(fetch.arguments.contains(&OsString::from(
            "git@github.com:ShiroKSH/rust-and-iphone.git"
        )));
        assert_eq!(
            runner
                .invocations
                .iter()
                .filter(|invocation| invocation.arguments.first()
                    == Some(&OsString::from("hash-object")))
                .count(),
            2
        );
        let commit = runner
            .invocations
            .iter()
            .find(|invocation| invocation.arguments.first() == Some(&OsString::from("commit-tree")))
            .expect("commit-tree invocation");
        assert_eq!(
            commit.arguments,
            [OsString::from("commit-tree"), OsString::from(TREE_SHA)]
        );
        assert!(commit.stdin_len > 0);
        for expected in [
            ("GIT_AUTHOR_NAME", "ShiroKSH"),
            ("GIT_AUTHOR_EMAIL", "kushidashiro@gmail.com"),
            ("GIT_COMMITTER_NAME", "ShiroKSH"),
            ("GIT_COMMITTER_EMAIL", "kushidashiro@gmail.com"),
        ] {
            assert!(
                commit
                    .environment
                    .contains(&(OsString::from(expected.0), OsString::from(expected.1),))
            );
        }
        assert!(
            commit
                .environment
                .iter()
                .any(|(name, _)| name == "GIT_AUTHOR_DATE")
        );
    }

    #[test]
    fn git_publisher_deletes_only_with_exact_expected_tip_lease() {
        let full_ref = "refs/heads/rustferry/goal3/builds/operation-1";
        let config = provider_config(all_authorized());
        let temporary_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
        )
        .expect("temporary ref");
        let responses = [
            Ok(b"git@github.com:ShiroKSH/rustferry-signing.git\n".to_vec()),
            Ok(b"ssh://git@github.com/ShiroKSH/rustferry-signing\n".to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
        ];
        let directory = tempdir().expect("isolation directory");
        let mut publisher = GitTemporaryRefPublisher::new(
            FakeGitRunner::with(responses),
            directory.path(),
            "origin",
            "origin",
            Duration::from_secs(5),
        )
        .expect("publisher");
        publisher
            .delete_temporary_ref(&TemporaryRefDeleteRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                temporary_ref: &temporary_ref,
                expected_commit: &CommitSha::new(DISPATCH_SHA).expect("dispatch commit"),
                authorized: true,
            })
            .expect("lease-protected deletion");
        let runner = publisher.into_runner();
        let push = runner
            .invocations
            .iter()
            .find(|invocation| invocation.arguments.first() == Some(&OsString::from("push")))
            .expect("delete push");
        assert!(push.arguments.contains(&OsString::from(format!(
            "--force-with-lease={full_ref}:{DISPATCH_SHA}"
        ))));
        assert!(
            push.arguments
                .contains(&OsString::from(format!(":{full_ref}")))
        );
        assert!(push.arguments.contains(&OsString::from("--atomic")));
    }

    #[test]
    fn git_publisher_reports_changed_tip_after_delete_lease_rejection() {
        let full_ref = "refs/heads/rustferry/goal3/builds/operation-1";
        let config = provider_config(all_authorized());
        let temporary_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
        )
        .expect("temporary ref");
        let responses = [
            Ok(b"git@github.com:ShiroKSH/rustferry-signing.git\n".to_vec()),
            Ok(b"ssh://git@github.com/ShiroKSH/rustferry-signing\n".to_vec()),
            Err(GitExecutionError::CommandFailed { exit_code: Some(1) }),
            Ok(format!("{TRUSTED_TIP}\t{full_ref}\n").into_bytes()),
        ];
        let directory = tempdir().expect("isolation directory");
        let mut publisher = GitTemporaryRefPublisher::new(
            FakeGitRunner::with(responses),
            directory.path(),
            "origin",
            "origin",
            Duration::from_secs(5),
        )
        .expect("publisher");
        assert_eq!(
            publisher.delete_temporary_ref(&TemporaryRefDeleteRequest {
                repository: &config.repository,
                source_repository: &config.source_repository,
                temporary_ref: &temporary_ref,
                expected_commit: &CommitSha::new(DISPATCH_SHA).expect("dispatch commit"),
                authorized: true,
            }),
            Err(TemporaryRefPublishError::TemporaryRefLeaseRejected)
        );
    }

    #[test]
    fn provider_submit_publishes_exact_request_and_queues_without_fake_success() {
        let config = provider_config(all_authorized());
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config.clone(),
            signed_transport(FakeGhRunner::default()),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let handle =
            poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        assert_eq!(handle.job_id, "operation-1");
        assert_eq!(handle.state, JobState::Queued);
        let publisher = provider.publisher.lock().expect("publisher");
        let captured = publisher.published.first().expect("publication");
        assert_eq!(captured.source_revision, SOURCE_SHA);
        assert_eq!(captured.branch, "rustferry/goal3/builds/operation-1");
        assert_eq!(
            captured.workflow_path,
            ".github/workflows/rustferry-goal3-iphone.yml"
        );
        assert_eq!(
            captured.workflow_sha256,
            config.workflow_fingerprint.as_str()
        );
        assert_eq!(captured.manifest.request, valid_request());
        assert!(captured.authorized);
        assert!(!provider.capabilities().artifact_download);
        let state = provider.state.lock().expect("state");
        let record = state.jobs.get("operation-1").expect("job record");
        assert_eq!(record.request, valid_request());
        assert_eq!(
            record.request_sha256,
            canonical_request_sha256(&record.request).expect("request hash")
        );
    }

    #[test]
    fn signed_submission_rechecks_private_visibility_before_publication() {
        let runner = FakeGhRunner::with([
            Ok(public_source_repository_row()),
            Ok(b"991\tShiroKSH/rustferry-signing\tfalse\tfalse\tfalse\tmain\n".to_vec()),
        ]);
        let captured_requests = Arc::clone(&runner.requests);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(runner),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );

        let error = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect_err("public signing repository must fail closed");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "public_signing_repository"
        ));
        assert_eq!(captured_requests.lock().expect("requests").len(), 2);
        assert!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .published
                .is_empty()
        );
        assert!(provider.state.lock().expect("state").jobs.is_empty());
    }

    #[test]
    fn submission_requires_worker_supported_artifacts_and_bounded_profiles() {
        let config = provider_config(all_authorized());
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config.clone(),
            signed_transport(FakeGhRunner::default()),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        assert_eq!(
            provider.capabilities().artifact_types,
            BTreeSet::from([
                IosArtifactType::Ipa,
                IosArtifactType::AppBundle,
                IosArtifactType::Dsym,
                IosArtifactType::SigningReport,
                IosArtifactType::Xcarchive,
            ])
        );
        assert_eq!(
            provider.capabilities().signing_modes,
            BTreeSet::from([
                SigningMode::ManualDevelopment,
                SigningMode::UnsignedCompileOnly,
            ])
        );

        let mut optional_artifacts = valid_request();
        optional_artifacts.requested_artifacts.extend([
            IosArtifactType::AppBundle,
            IosArtifactType::Dsym,
            IosArtifactType::Xcarchive,
        ]);
        validate_submission(&config, &optional_artifacts)
            .expect("provider accepts supported optional signed artifacts");

        let mut missing_ipa = valid_request();
        missing_ipa
            .requested_artifacts
            .remove(&IosArtifactType::Ipa);
        assert_eq!(
            validate_submission(&config, &missing_ipa).expect_err("signed IPA is mandatory"),
            RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "signed builds must request the installable IPA",
            }
        );

        let mut extra_artifact = valid_request();
        extra_artifact
            .requested_artifacts
            .insert(IosArtifactType::ProvisioningReport);
        assert_eq!(
            poll_ready(provider.submit(extra_artifact, CancellationToken::new()))
                .expect_err("worker does not produce provisioning reports"),
            unsupported(ProviderFeature::ArtifactType(
                IosArtifactType::ProvisioningReport
            ))
        );

        let mut too_many_profiles = valid_request();
        for _ in 0..MAX_SIGNING_PROFILES {
            too_many_profiles
                .signing
                .provisioning
                .push(too_many_profiles.signing.provisioning[0].clone());
        }
        let error = poll_ready(provider.submit(too_many_profiles, CancellationToken::new()))
            .expect_err("more than three profiles must fail closed");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, .. }
                if code == "profile_mapping_unsupported"
        ));
    }

    #[test]
    fn submission_accepts_exact_static_multi_profile_map_and_rejects_role_swaps() {
        let (request, names) = multi_profile_request();
        let config = provider_config_with_secret_names(all_authorized(), names);
        validate_submission(&config, &request).expect("exact multi-profile map");

        let mut swapped = request.clone();
        let first = swapped.signing.provisioning[0].profile.clone();
        swapped.signing.provisioning[0].profile = swapped.signing.provisioning[1].profile.clone();
        swapped.signing.provisioning[1].profile = first;
        let error = validate_submission(&config, &swapped).expect_err("profile roles are bound");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "signing_secret_reference_mismatch"
        ));

        let legacy = provider_config(all_authorized());
        let error = validate_submission(&legacy, &request)
            .expect_err("legacy profile binding must remain single-profile only");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "signing_secret_reference_mismatch"
        ));
    }

    #[test]
    fn submission_rejects_application_and_extension_identity_drift() {
        let (request, names) = multi_profile_request();
        let config = provider_config_with_secret_names(all_authorized(), names);

        let mut app_bundle_drift = request.clone();
        app_bundle_drift.bundle_identifier = "com.example.renamed-app".to_owned();
        app_bundle_drift
            .signing
            .targets
            .iter_mut()
            .find(|target| target.kind == SigningTargetKind::Application)
            .expect("application target")
            .bundle_identifier =
            BundleIdentifier::new("com.example.renamed-app").expect("drifted app bundle");
        app_bundle_drift
            .validate()
            .expect("internally valid app bundle drift");
        assert_signing_reference_mismatch(&config, &app_bundle_drift);

        let mut extension_bundle_drift = request.clone();
        extension_bundle_drift
            .signing
            .targets
            .iter_mut()
            .find(|target| target.kind == SigningTargetKind::Extension)
            .expect("extension target")
            .bundle_identifier = BundleIdentifier::new("com.example.app.renamed-widget")
            .expect("drifted extension bundle");
        extension_bundle_drift
            .product
            .nested_bundles
            .iter_mut()
            .find(|bundle| bundle.kind == UnsignedNestedBundleKind::AppExtension)
            .expect("extension bundle")
            .bundle_identifier = "com.example.app.renamed-widget".to_owned();
        extension_bundle_drift
            .validate()
            .expect("internally valid extension bundle drift");
        assert_signing_reference_mismatch(&config, &extension_bundle_drift);

        let mut extension_name_drift = request.clone();
        extension_name_drift
            .signing
            .targets
            .iter_mut()
            .find(|target| target.kind == SigningTargetKind::Extension)
            .expect("extension target")
            .name = "RenamedWidget".to_owned();
        extension_name_drift
            .signing
            .provisioning
            .iter_mut()
            .find(|profile| profile.target == "Widget")
            .expect("extension profile")
            .target = "RenamedWidget".to_owned();
        extension_name_drift
            .signing
            .entitlements
            .iter_mut()
            .find(|entitlements| entitlements.target == "Widget")
            .expect("extension entitlements")
            .target = "RenamedWidget".to_owned();
        extension_name_drift
            .validate()
            .expect("internally valid extension name drift");
        assert_signing_reference_mismatch(&config, &extension_name_drift);
    }

    #[test]
    fn submission_target_graph_match_is_order_insensitive_and_exact() {
        let (request, names) = multi_profile_request_with_framework();
        let config = provider_config_with_secret_names(all_authorized(), names);
        validate_submission(&config, &request).expect("exact full target graph");

        let mut reordered = request.clone();
        reordered.signing.targets.reverse();
        reordered.validate().expect("valid reordered target graph");
        validate_submission(&config, &reordered).expect("target order is not identity");

        let mut omitted = request.clone();
        omitted
            .signing
            .targets
            .retain(|target| target.name != "RuntimeBridge");
        omitted
            .product
            .nested_bundles
            .retain(|bundle| bundle.executable != "RuntimeBridge");
        omitted.validate().expect("valid omitted framework graph");
        assert_signing_reference_mismatch(&config, &omitted);

        let mut extra = request.clone();
        extra.signing.targets.push(SigningTarget {
            name: "SupportKit".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app.support-kit")
                .expect("extra framework bundle"),
            kind: SigningTargetKind::Framework,
        });
        extra
            .product
            .nested_bundles
            .push(UnsignedNestedBundleExpectation {
                relative_path: "Frameworks/SupportKit.framework".to_owned(),
                bundle_identifier: "com.example.app.support-kit".to_owned(),
                executable: "SupportKit".to_owned(),
                kind: UnsignedNestedBundleKind::Framework,
            });
        extra
            .product
            .nested_bundles
            .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        extra.validate().expect("valid extra framework graph");
        assert_signing_reference_mismatch(&config, &extra);
    }

    #[test]
    fn signed_secrets_are_exact_by_kind_and_role_while_unsigned_xcarchive_is_accepted() {
        let runner = FakeGhRunner::default();
        let captured_requests = Arc::clone(&runner.requests);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(runner),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );

        let mut wrong_kind = valid_request();
        wrong_kind
            .signing
            .signing
            .as_mut()
            .expect("signing")
            .identity
            .private_key
            .reference = SecretReference::new(
            SecretReferenceKind::Environment,
            "RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12",
        )
        .expect("environment reference");
        let error = poll_ready(provider.submit(wrong_kind, CancellationToken::new()))
            .expect_err("wrong secret namespace");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, .. }
                if code == "signing_secret_reference_mismatch"
        ));

        let mut swapped_roles = valid_request();
        let signing = swapped_roles.signing.signing.as_mut().expect("signing");
        signing.identity.private_key.reference = SecretReference::new(
            SecretReferenceKind::GithubActions,
            "RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD",
        )
        .expect("password role");
        signing.password = Some(
            SecretReference::new(
                SecretReferenceKind::GithubActions,
                "RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12",
            )
            .expect("certificate role"),
        );
        let error = poll_ready(provider.submit(swapped_roles, CancellationToken::new()))
            .expect_err("secret roles are not interchangeable");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, .. }
                if code == "signing_secret_reference_mismatch"
        ));

        let unsigned = unsigned_request();
        let handle = poll_ready(provider.submit(unsigned.clone(), CancellationToken::new()))
            .expect("unsigned xcarchive request");
        assert_eq!(handle.state, JobState::Queued);
        assert_eq!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .published
                .first()
                .expect("publication")
                .manifest
                .request,
            unsigned
        );
        assert!(captured_requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn failed_pre_push_submission_releases_job_reservation() {
        let publisher = FakePublisher {
            failure: Some(TemporaryRefPublishError::RemoteMismatch.into()),
            ..FakePublisher::default()
        };
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::with([
                Ok(public_source_repository_row()),
                Ok(private_repository_row()),
                Ok(signing_environment_row(false, true, true)),
                Ok(exact_signing_policy_row()),
                Ok(exact_signing_secret_rows()),
            ])),
            publisher,
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect_err("first publication fails before push");
        let handle = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect("reservation was released");
        assert_eq!(handle.job_id, "operation-1");
    }

    #[test]
    fn cancellation_during_successful_push_returns_visible_handle() {
        let cancellation = CancellationToken::new();
        let publisher = FakePublisher {
            cancel_on_publish: Some(cancellation.clone()),
            ..FakePublisher::default()
        };
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::default()),
            publisher,
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let handle = poll_ready(provider.submit(valid_request(), cancellation))
            .expect("published job remains visible");
        assert_eq!(handle.job_id, "operation-1");
        assert_eq!(handle.state, JobState::Cancelling);
        assert!(
            provider
                .state
                .lock()
                .expect("state")
                .jobs
                .contains_key("operation-1")
        );
    }

    #[test]
    fn signed_submission_rejects_same_source_and_execution_repository() {
        let runner = FakeGhRunner::default();
        let captured_requests = Arc::clone(&runner.requests);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            same_repository_provider_config(all_authorized()),
            transport(runner),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );

        let error = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect_err("same-repository signing must fail closed");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "separate_signing_repository_required"
        ));
        assert!(captured_requests.lock().expect("requests").is_empty());
        assert!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .published
                .is_empty()
        );
    }

    #[test]
    fn signed_submission_rechecks_public_source_visibility_before_publication() {
        let runner = FakeGhRunner::with([Ok(private_source_repository_row())]);
        let captured_requests = Arc::clone(&runner.requests);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(runner),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );

        let error = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect_err("private source repository must fail closed");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "private_source_repository"
        ));
        assert_eq!(captured_requests.lock().expect("requests").len(), 1);
        assert!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .published
                .is_empty()
        );
    }

    #[test]
    fn signed_submission_rechecks_required_environment_reviewers_before_publication() {
        let runner = FakeGhRunner::with([
            Ok(public_source_repository_row()),
            Ok(private_repository_row()),
            Ok(signing_environment_row(false, true, false)),
            Ok(exact_signing_policy_row()),
            Ok(exact_signing_secret_rows()),
        ]);
        let captured_requests = Arc::clone(&runner.requests);
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(runner),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );

        let error = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect_err("missing deployment reviewer must fail closed");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, retryable: false, .. }
                if code == "signing_environment_not_ready"
        ));
        assert_eq!(captured_requests.lock().expect("requests").len(), 5);
        assert!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .published
                .is_empty()
        );
    }

    #[test]
    fn uncertain_push_retains_exact_cleanup_ownership() {
        let publication = PublishedTemporaryRef::new(
            TemporaryGitRef::new(
                provider_config(all_authorized())
                    .workflow
                    .temporary_branch_namespace(),
                BranchName::new("rustferry/goal3/builds/operation-1").expect("branch"),
            )
            .expect("temporary ref"),
            CommitSha::new(DISPATCH_SHA).expect("dispatch SHA"),
        );
        let publisher = FakePublisher {
            failure: Some(TemporaryRefPublishFailure::uncertain(
                TemporaryRefPublishError::Git(GitExecutionError::TimedOut),
                publication,
            )),
            ..FakePublisher::default()
        };
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::default()),
            publisher,
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let handle = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect("uncertain publication returns owned handle");
        assert_eq!(handle.state, JobState::Queued);
        let state = provider.state.lock().expect("state");
        let record = state.jobs.get("operation-1").expect("durable record");
        assert!(record.publication_uncertain);
        assert_eq!(
            record.dispatch_commit.as_ref().map(CommitSha::as_str),
            Some(DISPATCH_SHA)
        );
    }

    #[test]
    fn publisher_identity_mismatch_returns_failed_owned_handle() {
        let config = provider_config(all_authorized());
        let returned_ref = TemporaryGitRef::new(
            config.workflow.temporary_branch_namespace(),
            BranchName::new("rustferry/goal3/builds/unexpected").expect("branch"),
        )
        .expect("temporary ref");
        let publisher = FakePublisher {
            returned_temporary_ref: Some(returned_ref.clone()),
            ..FakePublisher::default()
        };
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            signed_transport(FakeGhRunner::default()),
            publisher,
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let handle = poll_ready(provider.submit(valid_request(), CancellationToken::new()))
            .expect("possibly mutated ref retains a visible handle");
        assert_eq!(handle.state, JobState::Failed);
        let state = provider.state.lock().expect("state");
        let record = state.jobs.get("operation-1").expect("owned record");
        assert_ne!(record.temporary_ref, returned_ref);
        assert_eq!(
            record.temporary_ref.branch().as_str(),
            "rustferry/goal3/builds/operation-1"
        );
        assert_eq!(
            record.dispatch_commit.as_ref().map(CommitSha::as_str),
            Some(DISPATCH_SHA)
        );
        assert!(record.publication_uncertain);
    }

    #[test]
    fn run_discovery_exhaustion_becomes_typed_cleanup_needed_failure() {
        let mut config = provider_config(all_authorized());
        config.poll_policy =
            GithubPollingPolicy::new(2, Duration::from_millis(250)).expect("policy");
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            signed_transport(FakeGhRunner::with([Ok(Vec::new()), Ok(Vec::new())])),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let events = || EventRequest {
            job_id: "operation-1".to_owned(),
            after_sequence: None,
            limit: 100,
        };
        let first = poll_ready(provider.events(events(), CancellationToken::new()))
            .expect("first discovery attempt");
        assert_eq!(first.state, JobState::Queued);
        let second = poll_ready(provider.events(events(), CancellationToken::new()))
            .expect("bounded discovery failure");
        assert_eq!(second.state, JobState::Failed);
        assert!(!second.complete);
        assert!(second.events.iter().any(|event| matches!(
            &event.kind,
            RemoteBuildEventKind::Warning { code, .. } if code == "github.cleanup_required"
        )));
        assert!(second.events.iter().any(|event| matches!(
            &event.kind,
            RemoteBuildEventKind::OperationFinished {
                success: false,
                error: Some(error),
                ..
            } if error.code == "github.run_discovery_exhausted"
        )));
    }

    #[test]
    fn cleanup_uses_one_exact_lease_and_refuses_a_changed_tip() {
        let mut config = provider_config(all_authorized());
        config.poll_policy =
            GithubPollingPolicy::new(1, Duration::from_millis(250)).expect("policy");
        let runner = FakeGhRunner::with([Ok(Vec::new())]);
        let captured_requests = Arc::clone(&runner.requests);
        let publisher = FakePublisher {
            delete_failure: Some(TemporaryRefPublishError::TemporaryRefLeaseRejected),
            ..FakePublisher::default()
        };
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            signed_transport(runner),
            publisher,
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let page = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("bounded discovery failure");
        assert_eq!(page.state, JobState::Failed);
        let request_count_before_cleanup = captured_requests.lock().expect("requests").len();
        let error = poll_ready(provider.cleanup(
            CleanupRequest {
                job_id: "operation-1".to_owned(),
                remove_artifacts: false,
            },
            CancellationToken::new(),
        ))
        .expect_err("changed remote ref must not be deleted");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, .. }
                if code == "temporary_ref_tip_changed"
        ));
        assert_eq!(
            captured_requests.lock().expect("captured requests").len(),
            request_count_before_cleanup,
            "cleanup must not issue a GitHub DELETE after a tip mismatch"
        );
        let publisher = provider.publisher.lock().expect("publisher");
        let deletion = publisher.deletions.first().expect("delete lease");
        assert_eq!(deletion.branch, "rustferry/goal3/builds/operation-1");
        assert_eq!(deletion.expected_commit, DISPATCH_SHA);
        assert!(deletion.authorized);
    }

    #[test]
    fn event_page_completes_only_after_closed_lifecycle_and_untruncated_delivery() {
        let mut config = provider_config(all_authorized());
        config.poll_policy =
            GithubPollingPolicy::new(1, Duration::from_millis(250)).expect("policy");
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            signed_transport(FakeGhRunner::with([Ok(Vec::new())])),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let failed = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("discovery failure");
        assert_eq!(failed.state, JobState::Failed);
        assert!(!failed.complete);
        poll_ready(provider.cleanup(
            CleanupRequest {
                job_id: "operation-1".to_owned(),
                remove_artifacts: false,
            },
            CancellationToken::new(),
        ))
        .expect("cleanup closes lifecycle");
        let truncated = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 1,
            },
            CancellationToken::new(),
        ))
        .expect("truncated events");
        assert!(truncated.state.is_terminal());
        assert!(!truncated.complete);
        let complete = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("complete events");
        assert!(complete.state.is_terminal());
        assert!(complete.complete);
    }

    #[test]
    fn closed_job_records_are_recycled_at_capacity() {
        let mut config = provider_config(all_authorized());
        config.max_jobs = 1;
        config.poll_policy =
            GithubPollingPolicy::new(1, Duration::from_millis(250)).expect("policy");
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            config,
            signed_transport(FakeGhRunner::with([
                Ok(Vec::new()),
                Ok(public_source_repository_row()),
                Ok(private_repository_row()),
                Ok(signing_environment_row(false, true, true)),
                Ok(exact_signing_policy_row()),
                Ok(exact_signing_secret_rows()),
            ])),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("discovery failure");
        poll_ready(provider.cleanup(
            CleanupRequest {
                job_id: "operation-1".to_owned(),
                remove_artifacts: false,
            },
            CancellationToken::new(),
        ))
        .expect("closed old job");

        let mut replacement = valid_request();
        replacement.operation_id = "operation-2".to_owned();
        let handle = poll_ready(provider.submit(replacement, CancellationToken::new()))
            .expect("closed record recycled");
        assert_eq!(handle.job_id, "operation-2");
        let state = provider.state.lock().expect("state");
        assert_eq!(state.jobs.len(), 1);
        assert!(state.jobs.contains_key("operation-2"));
    }

    #[test]
    fn github_success_stays_pending_without_independent_artifact_verifier() {
        let responses = [
            Ok(completed_run_row("success")),
            Ok(completed_run_row("success")),
        ];
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::with(responses)),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let page = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("events");
        assert_eq!(page.state, JobState::Running);
        assert!(!page.complete);
        assert!(page.events.iter().any(|event| matches!(
            &event.kind,
            RemoteBuildEventKind::Warning { code, .. }
                if code == "github.artifact_verification_pending"
        )));
        assert!(!page.events.iter().any(|event| matches!(
            event.kind,
            RemoteBuildEventKind::OperationFinished { success: true, .. }
        )));
    }

    #[test]
    fn terminal_run_can_be_cleaned_after_artifact_verification_error() {
        let responses = [
            Ok(completed_run_row("success")),
            Ok(completed_run_row("success")),
        ];
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::with(responses)),
            FakePublisher::default(),
            FailingArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let error = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect_err("artifact verification fails");
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { code, .. }
                if code == "artifact_fixture_rejected"
        ));

        let confirmation = poll_ready(provider.cleanup(
            CleanupRequest {
                job_id: "operation-1".to_owned(),
                remove_artifacts: false,
            },
            CancellationToken::new(),
        ))
        .expect("terminal run cleanup");
        assert!(confirmation.workspace_removed);
        assert!(confirmation.signing_material_removed);
        let state = provider.state.lock().expect("state");
        assert_eq!(
            state.jobs.get("operation-1").expect("job").state,
            JobState::Cleaned
        );
        drop(state);
        assert_eq!(
            provider
                .publisher
                .lock()
                .expect("publisher")
                .deletions
                .len(),
            1
        );
    }

    #[test]
    fn failed_run_produces_typed_terminal_failure() {
        let responses = [
            Ok(completed_run_row("failure")),
            Ok(completed_run_row("failure")),
        ];
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::with(responses)),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let page = poll_ready(provider.events(
            EventRequest {
                job_id: "operation-1".to_owned(),
                after_sequence: None,
                limit: 100,
            },
            CancellationToken::new(),
        ))
        .expect("events");
        assert_eq!(page.state, JobState::Failed);
        assert!(page.events.iter().any(|event| matches!(
            &event.kind,
            RemoteBuildEventKind::OperationFinished {
                success: false,
                error: Some(error),
                ..
            } if error.code == "github.run_failed"
        )));
    }

    #[test]
    fn cancellation_is_idempotent_before_run_mapping() {
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            signed_transport(FakeGhRunner::default()),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        poll_ready(provider.submit(valid_request(), CancellationToken::new())).expect("submit");
        let request = CancellationRequest {
            job_id: "operation-1".to_owned(),
            reason: "user_requested".to_owned(),
        };
        let first = poll_ready(provider.cancel(request.clone(), CancellationToken::new()))
            .expect("first cancellation");
        let second = poll_ready(provider.cancel(request, CancellationToken::new()))
            .expect("second cancellation");
        assert!(first.accepted);
        assert!(!second.accepted);
        assert_eq!(second.state, JobState::Cancelling);
    }

    #[test]
    fn unconfigured_artifact_download_is_typed_unsupported() {
        let provider = GithubBuildProvider::with_artifact_store_and_clock(
            provider_config(all_authorized()),
            transport(FakeGhRunner::default()),
            FakePublisher::default(),
            NoVerifiedArtifactStore,
            FixedClock(1_700_000_000_000),
        );
        let destination = rustferry_remote::ProtocolPath::new(
            rustferry_remote::ProtocolPathSemantics::ClientAbsolute,
            "/tmp/application.ipa",
        )
        .expect("destination");
        let error = poll_ready(provider.download_artifact(
            ArtifactDownloadRequest {
                job_id: "operation-1".to_owned(),
                artifact_id: "ipa".to_owned(),
                destination,
            },
            CancellationToken::new(),
        ))
        .expect_err("download unsupported");
        assert_eq!(error, unsupported(ProviderFeature::ArtifactDownload));
    }
}
