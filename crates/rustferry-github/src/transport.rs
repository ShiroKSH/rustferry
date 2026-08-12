//! Bounded GitHub REST transport for remote build orchestration.
//!
//! Every request uses an explicit repository endpoint and fixed `gh api`
//! arguments. The process runner clears ambient environment state, supplies
//! exactly one configured authentication source, caps captured output, and
//! never returns command stderr in errors.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(any(not(windows), feature = "secure-job-log-http"))]
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::AsHandle as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use rustferry_core::windows_private_directory::{
    PrivateDirectoryCleanupStatus, PrivateDirectoryError, PrivateDirectoryErrorKind,
    create_private_file as create_windows_private_file,
    remove_private_file_handle as remove_windows_private_file_handle,
    verify_private_file_handle as verify_windows_private_file_handle,
};
use rustferry_remote::SecretBytes;

#[cfg(feature = "secure-job-log-http")]
use crate::job_logs::{
    GithubJobLogAccept, GithubJobLogAuthorization, GithubJobLogHttpBody, GithubJobLogHttpClient,
    GithubJobLogHttpError, GithubJobLogHttpRequest, GithubJobLogHttpResponse,
};
use crate::workflow::{ProtectedEnvironment, SecretName, TemporaryBranchNamespace};

const GITHUB_HOST: &str = "github.com";
const API_ACCEPT: &str = "Accept: application/vnd.github+json";
const API_VERSION: &str = "X-GitHub-Api-Version: 2022-11-28";
const WORKFLOW_DISPATCH_API_VERSION: &str = "2026-03-10";
const WORKFLOW_DISPATCH_API_VERSION_HEADER: &str = "X-GitHub-Api-Version: 2026-03-10";
const WORKFLOW_DISPATCH_ACCEPT: &str = "application/vnd.github+json";
const WORKFLOW_DISPATCH_CONTENT_TYPE: &str = "application/json";
const MAX_WORKFLOW_DISPATCH_BODY_BYTES: usize = 2 * 1024;
const MAX_WORKFLOW_DISPATCH_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_SECRET_SET_OUTPUT_BYTES: usize = 4 * 1024;
#[cfg(feature = "secure-job-log-http")]
const MAX_GITHUB_TOKEN_BYTES: usize = 4 * 1024;
#[cfg(feature = "secure-job-log-http")]
const GH_AUTH_TOKEN_OUTPUT_BYTES: usize = MAX_GITHUB_TOKEN_BYTES + 2;
#[cfg(feature = "secure-job-log-http")]
const GH_AUTH_TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "secure-job-log-http")]
const JOB_LOG_API_ORIGIN: &str = "https://api.github.com";
#[cfg(feature = "secure-job-log-http")]
const JOB_LOG_API_ACCEPT: &str = "application/vnd.github+json";
#[cfg(feature = "secure-job-log-http")]
const JOB_LOG_PLAINTEXT_ACCEPT: &str = "text/plain";
#[cfg(feature = "secure-job-log-http")]
const JOB_LOG_API_VERSION: &str = "2026-03-10";
#[cfg(feature = "secure-job-log-http")]
const MAX_JOB_LOG_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
#[cfg(feature = "secure-job-log-http")]
const MAX_JOB_LOG_HTTP_CHUNK_BYTES: usize = 64 * 1024 + 1;
#[cfg(feature = "secure-job-log-http")]
const MAX_JOB_LOG_HTTP_TIMEOUT: Duration = Duration::from_hours(1);
#[cfg(feature = "secure-job-log-http")]
const _: () = assert!(
    (log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize),
    "secure-job-log-http must compile out URL-bearing ureq TRACE diagnostics"
);
const PROCESS_CLEANUP_GRACE: Duration = Duration::from_secs(1);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_API_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PAGES: u16 = 100;
const MAX_POLL_ATTEMPTS: u16 = 2_000;
const MAX_DEPLOYMENT_POLICY_NAME_BYTES: usize = 255;
const MAX_WORKFLOW_DISPATCH_RUN_NAME_BYTES: usize = 240;
const WORKFLOW_DISPATCH_RUN_NAME_PREFIX: &str = "rustferry-v1|";
const ZIP_END_RECORD_MINIMUM_BYTES: usize = 22;
const ZIP_END_RECORD_SEARCH_BYTES: usize = 65_557;

/// Maximum value accepted by GitHub Actions for one Environment secret.
pub const MAX_ENVIRONMENT_SECRET_BYTES: usize = 48 * 1024;

const USER_QUERY: &str = "[.id,(.login | @base64)] | @tsv";
const INSTALLATION_REPOSITORY_QUERY: &str = ".repositories[] | [.id,(.full_name | @base64)] | @tsv";
const REPOSITORY_QUERY: &str =
    "[.id,.full_name,.private,.archived,.disabled,.default_branch] | @tsv";
const ACTIONS_PERMISSIONS_QUERY: &str = ".enabled";
const WORKFLOW_QUERY: &str = "[.id,(.path | @base64),.state] | @tsv";
const RUN_LIST_QUERY: &str = ".workflow_runs[] | [.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\")] | @tsv";
const RUN_QUERY: &str = "[.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\")] | @tsv";
const WORKFLOW_DISPATCH_RUN_LIST_QUERY: &str = ".workflow_runs[] | [.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\"),(.display_title | @base64)] | @tsv";
const WORKFLOW_DISPATCH_RUN_QUERY: &str = "[.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\"),(.display_title | @base64)] | @tsv";
const ARTIFACT_LIST_QUERY: &str =
    ".artifacts[] | [.id,(.name | @base64),.size_in_bytes,.expired,(.digest // \"\")] | @tsv";
const ENVIRONMENT_QUERY: &str = "[(.name | @base64),.deployment_branch_policy.protected_branches,.deployment_branch_policy.custom_branch_policies,([.protection_rules[]? | select(.type == \"required_reviewers\") | .reviewers[]?] | length > 0)] | @tsv";
const DEPLOYMENT_BRANCH_POLICY_LIST_QUERY: &str =
    ".branch_policies[] | [.id,(.name | @base64)] | @tsv";
const ENVIRONMENT_SECRET_LIST_QUERY: &str = ".secrets[] | [(.name | @base64)] | @tsv";

/// Validation failure for a GitHub identifier or local policy value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportConfigError {
    /// A required field was empty.
    Empty {
        /// Stable field name; rejected input is intentionally omitted.
        field: &'static str,
    },
    /// A field exceeded its byte limit.
    TooLong {
        /// Stable field name.
        field: &'static str,
        /// Maximum accepted byte count.
        maximum: usize,
    },
    /// A byte fell outside the field allowlist.
    InvalidCharacter {
        /// Stable field name.
        field: &'static str,
        /// Byte offset, without the rejected byte.
        index: usize,
    },
    /// A field did not satisfy its structural rules.
    InvalidFormat {
        /// Stable field name.
        field: &'static str,
    },
    /// A numeric value was outside its inclusive range.
    OutOfRange {
        /// Stable field name.
        field: &'static str,
        /// Inclusive minimum.
        minimum: u64,
        /// Inclusive maximum.
        maximum: u64,
    },
    /// A local executable or directory was not a usable absolute path.
    InvalidLocalPath {
        /// Stable path role; the actual path is intentionally omitted.
        field: &'static str,
    },
    /// A branch was outside the configured temporary-ref namespace.
    RefOutsideTemporaryNamespace,
}

impl fmt::Display for TransportConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{field} is empty"),
            Self::TooLong { field, maximum } => {
                write!(formatter, "{field} exceeds {maximum} bytes")
            }
            Self::InvalidCharacter { field, index } => {
                write!(
                    formatter,
                    "{field} contains an unsafe byte at offset {index}"
                )
            }
            Self::InvalidFormat { field } => write!(formatter, "{field} has an invalid format"),
            Self::OutOfRange {
                field,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field} must be between {minimum} and {maximum} inclusive"
            ),
            Self::InvalidLocalPath { field } => {
                write!(formatter, "{field} is not a usable absolute path")
            }
            Self::RefOutsideTemporaryNamespace => {
                formatter.write_str("branch is outside the temporary job namespace")
            }
        }
    }
}

impl Error for TransportConfigError {}

/// Explicit GitHub owner and repository name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Repository {
    owner: String,
    name: String,
}

impl Repository {
    /// Validate a GitHub.com owner and repository name.
    ///
    /// # Errors
    ///
    /// Rejects path syntax, control bytes, option-like names, and values above
    /// GitHub's documented name limits.
    pub fn new(
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, TransportConfigError> {
        let owner = owner.into();
        let name = name.into();
        validate_owner(&owner)?;
        validate_repository_name(&name)?;
        Ok(Self { owner, name })
    }

    /// GitHub owner or organization login.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Repository name without its owner.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn endpoint(&self, suffix: &str) -> String {
        format!("/repos/{}/{}{}", self.owner, self.name, suffix)
    }

    fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// Exact lowercase 40-character Git commit identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommitSha(String);

impl CommitSha {
    /// Validate a full lowercase SHA-1 object identifier.
    ///
    /// # Errors
    ///
    /// Rejects abbreviated, uppercase, or non-hexadecimal values.
    pub fn new(value: impl Into<String>) -> Result<Self, TransportConfigError> {
        let value = value.into();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TransportConfigError::InvalidFormat {
                field: "commit sha",
            });
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(TransportConfigError::InvalidFormat {
                field: "commit sha",
            });
        }
        Ok(Self(value))
    }

    /// Full commit identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact Git branch name without the `refs/heads/` prefix.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BranchName(String);

impl BranchName {
    /// Validate a conservative Git branch name.
    ///
    /// # Errors
    ///
    /// Rejects ref traversal, wildcard syntax, reflog syntax, control bytes,
    /// full refs, and names longer than 244 bytes.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn new(value: impl Into<String>) -> Result<Self, TransportConfigError> {
        let value = value.into();
        validate_nonempty_length("branch", &value, 244)?;
        validate_ascii_allowlist("branch", &value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })?;
        if value.starts_with('-')
            || value.starts_with('/')
            || value.starts_with("refs/")
            || value.ends_with('/')
            || value.ends_with('.')
            || value.ends_with(".lock")
            || value.contains("..")
            || value.contains("//")
            || value.contains("@{")
            || value.split('/').any(|part| part.is_empty() || part == ".")
        {
            return Err(TransportConfigError::InvalidFormat { field: "branch" });
        }
        Ok(Self(value))
    }

    /// Branch name without a ref prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact generated artifact name expected from the workflow.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactName(String);

impl ArtifactName {
    /// Validate an artifact name safe for exact comparison.
    ///
    /// # Errors
    ///
    /// Rejects path separators, expression syntax, control bytes, and values
    /// longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, TransportConfigError> {
        let value = value.into();
        validate_nonempty_length("artifact name", &value, 128)?;
        validate_ascii_allowlist("artifact name", &value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })?;
        if !value.as_bytes()[0].is_ascii_alphanumeric()
            || value.ends_with('.')
            || value.contains("..")
        {
            return Err(TransportConfigError::InvalidFormat {
                field: "artifact name",
            });
        }
        Ok(Self(value))
    }

    /// Validated artifact name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! numeric_identifier {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Non-zero GitHub ", $label, " identifier.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            #[doc = concat!("Validate a GitHub ", $label, " identifier.")]
            ///
            /// # Errors
            ///
            /// Rejects zero, which GitHub never assigns as an identifier.
            pub fn new(value: u64) -> Result<Self, TransportConfigError> {
                if value == 0 {
                    return Err(TransportConfigError::OutOfRange {
                        field: concat!($label, " id"),
                        minimum: 1,
                        maximum: u64::MAX,
                    });
                }
                Ok(Self(value))
            }

            #[doc = concat!("Return the numeric ", $label, " identifier.")]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

numeric_identifier!(WorkflowId, "workflow");
numeric_identifier!(RunId, "run");
numeric_identifier!(ArtifactId, "artifact");

/// Supported workflow event used for an exact run lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunEvent {
    /// A push to the temporary job ref.
    Push,
    /// An explicitly enabled manual dispatch.
    WorkflowDispatch,
}

impl RunEvent {
    /// GitHub REST event spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::WorkflowDispatch => "workflow_dispatch",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "push" => Some(Self::Push),
            "workflow_dispatch" => Some(Self::WorkflowDispatch),
            _ => None,
        }
    }
}

/// A branch proven to be below the configured temporary namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryGitRef(BranchName);

impl TemporaryGitRef {
    /// Bind an exact branch to the generated workflow's temporary namespace.
    ///
    /// # Errors
    ///
    /// Rejects the namespace root itself and any branch outside it.
    pub fn new(
        namespace: &TemporaryBranchNamespace,
        branch: BranchName,
    ) -> Result<Self, TransportConfigError> {
        let prefix = format!("{}/", namespace.as_str());
        let Some(tail) = branch.as_str().strip_prefix(&prefix) else {
            return Err(TransportConfigError::RefOutsideTemporaryNamespace);
        };
        if tail.is_empty() {
            return Err(TransportConfigError::RefOutsideTemporaryNamespace);
        }
        Ok(Self(branch))
    }

    /// Exact branch name without `refs/heads/`.
    pub fn branch(&self) -> &BranchName {
        &self.0
    }
}

/// Bounded metadata, pagination, and artifact-download policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pages: u16,
    per_page: u8,
    api_response_bytes: usize,
    artifact_bytes: u64,
    api_timeout: Duration,
    download_timeout: Duration,
}

impl TransportLimits {
    /// Construct transport limits.
    ///
    /// # Errors
    ///
    /// Rejects zero, GitHub pagination values above 100, response buffers
    /// above 16 MiB, artifact bounds above 2 GiB, and timeouts above one hour.
    pub fn new(
        pages: u16,
        per_page: u8,
        api_response_bytes: usize,
        artifact_bytes: u64,
        api_timeout: Duration,
        download_timeout: Duration,
    ) -> Result<Self, TransportConfigError> {
        validate_range(
            "pagination pages",
            u64::from(pages),
            1,
            u64::from(MAX_PAGES),
        )?;
        validate_range("pagination page size", u64::from(per_page), 1, 100)?;
        validate_range(
            "API response bytes",
            usize_to_u64(api_response_bytes),
            1_024,
            usize_to_u64(MAX_API_RESPONSE_BYTES),
        )?;
        validate_range("artifact bytes", artifact_bytes, 1_024, MAX_ARTIFACT_BYTES)?;
        validate_duration("API timeout", api_timeout, 1, 600)?;
        validate_duration("download timeout", download_timeout, 1, 3_600)?;
        Ok(Self {
            pages,
            per_page,
            api_response_bytes,
            artifact_bytes,
            api_timeout,
            download_timeout,
        })
    }

    /// Conservative defaults: ten 100-item pages, 2 MiB API responses,
    /// 512 MiB artifacts, one-minute API calls, and ten-minute downloads.
    ///
    /// # Panics
    ///
    /// This cannot panic because all constants satisfy the constructor bounds.
    pub fn secure_defaults() -> Self {
        Self::new(
            10,
            100,
            2 * 1024 * 1024,
            512 * 1024 * 1024,
            Duration::from_mins(1),
            Duration::from_mins(10),
        )
        .expect("constant transport limits are valid")
    }

    /// Maximum artifact download size.
    pub const fn artifact_bytes(self) -> u64 {
        self.artifact_bytes
    }
}

/// Bounded polling policy for one known run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollPolicy {
    attempts: u16,
    interval: Duration,
}

impl PollPolicy {
    /// Construct a polling policy.
    ///
    /// # Errors
    ///
    /// Allows 1–2000 attempts and intervals from 250 ms through 60 seconds.
    pub fn new(attempts: u16, interval: Duration) -> Result<Self, TransportConfigError> {
        validate_range(
            "poll attempts",
            u64::from(attempts),
            1,
            u64::from(MAX_POLL_ATTEMPTS),
        )?;
        if !(Duration::from_millis(250)..=Duration::from_mins(1)).contains(&interval) {
            return Err(TransportConfigError::OutOfRange {
                field: "poll interval milliseconds",
                minimum: 250,
                maximum: 60_000,
            });
        }
        Ok(Self { attempts, interval })
    }

    /// Default five-second polling for at most two hours.
    ///
    /// # Panics
    ///
    /// This cannot panic because both constants satisfy the constructor bounds.
    pub fn secure_defaults() -> Self {
        Self::new(1_440, Duration::from_secs(5)).expect("constant polling policy is valid")
    }
}

/// HTTP method used by a planned `gh api` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiMethod {
    /// Read one REST resource.
    Get,
    /// Invoke an idempotence-sensitive REST action such as run cancellation.
    Post,
}

impl ApiMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// Fully planned, non-secret `gh api` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhRequest {
    method: ApiMethod,
    endpoint: String,
    fields: Vec<(String, String)>,
    jq: Option<&'static str>,
    silent: bool,
    output_limit: usize,
    timeout: Duration,
    api_version: &'static str,
}

impl GhRequest {
    /// HTTP method.
    pub const fn method(&self) -> ApiMethod {
        self.method
    }

    /// Explicit GitHub REST endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Maximum accepted stdout bytes.
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Per-process deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Exact `X-GitHub-Api-Version` header planned for this request.
    pub const fn api_version_header(&self) -> &'static str {
        self.api_version
    }

    /// Render fixed argv entries for `gh`; no shell parsing is involved.
    pub fn arguments(&self) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("api"),
            OsString::from("--hostname"),
            OsString::from(GITHUB_HOST),
            OsString::from("--method"),
            OsString::from(self.method.as_str()),
            OsString::from("-H"),
            OsString::from(API_ACCEPT),
            OsString::from("-H"),
            OsString::from(self.api_version),
            OsString::from(&self.endpoint),
        ];
        for (name, value) in &self.fields {
            arguments.push(OsString::from("-f"));
            arguments.push(OsString::from(format!("{name}={value}")));
        }
        if let Some(query) = self.jq {
            arguments.push(OsString::from("--jq"));
            arguments.push(OsString::from(query));
        }
        if self.silent {
            arguments.push(OsString::from("--silent"));
        }
        arguments
    }
}

/// Exact secret role and protected GitHub Environment selected for one write.
///
/// The secret value is deliberately absent. It is supplied separately to the
/// runner so it cannot enter argv, debug output, or serialized request state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSecretWriteRequest {
    repository: Repository,
    environment: ProtectedEnvironment,
    name: SecretName,
}

impl EnvironmentSecretWriteRequest {
    /// Bind one validated secret name to an exact repository and Environment.
    pub const fn new(
        repository: Repository,
        environment: ProtectedEnvironment,
        name: SecretName,
    ) -> Self {
        Self {
            repository,
            environment,
            name,
        }
    }

    /// Exact target repository.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Exact protected Environment.
    pub const fn environment(&self) -> &ProtectedEnvironment {
        &self.environment
    }

    /// Validated secret role name.
    pub const fn name(&self) -> &SecretName {
        &self.name
    }

    /// Render the fixed `gh secret set` argv. The value is read from stdin.
    pub fn arguments(&self) -> Vec<OsString> {
        vec![
            OsString::from("secret"),
            OsString::from("set"),
            OsString::from(self.name.as_str()),
            OsString::from("--repo"),
            OsString::from(self.repository.full_name()),
            OsString::from("--env"),
            OsString::from(self.environment.as_str()),
        ]
    }
}

/// Secret-free confirmation that `gh` accepted one exact Environment write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSecretWriteReceipt {
    repository: Repository,
    environment: ProtectedEnvironment,
    name: SecretName,
}

impl EnvironmentSecretWriteReceipt {
    /// Exact target repository.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Exact protected Environment.
    pub const fn environment(&self) -> &ProtectedEnvironment {
        &self.environment
    }

    /// Secret role accepted by `gh`.
    pub const fn name(&self) -> &SecretName {
        &self.name
    }
}

/// Redacted execution failure from a `gh` runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GhExecutionError {
    /// Authentication was unavailable from the exact configured source.
    AuthenticationUnavailable,
    /// A secret value exceeded GitHub's fixed Environment-secret limit.
    SecretTooLarge,
    /// The child process could not be created.
    SpawnFailed,
    /// The child process exceeded its deadline and was terminated.
    TimedOut,
    /// Waiting for or reading the child process failed.
    ProcessIo,
    /// Stdout or stderr crossed its configured cap.
    OutputLimitExceeded,
    /// `gh` returned a non-zero status. Output is intentionally discarded.
    CommandFailed {
        /// Exit code when the platform supplied one.
        exit_code: Option<i32>,
    },
}

impl fmt::Display for GhExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationUnavailable => {
                formatter.write_str("GitHub authentication is unavailable")
            }
            Self::SecretTooLarge => {
                formatter.write_str("GitHub Environment secret exceeds size limit")
            }
            Self::SpawnFailed => formatter.write_str("failed to start GitHub CLI"),
            Self::TimedOut => formatter.write_str("GitHub API request timed out"),
            Self::ProcessIo => formatter.write_str("GitHub CLI process I/O failed"),
            Self::OutputLimitExceeded => {
                formatter.write_str("GitHub CLI output exceeded its limit")
            }
            Self::CommandFailed { exit_code } => match exit_code {
                Some(code) => write!(formatter, "GitHub API request failed with status {code}"),
                None => formatter.write_str("GitHub API request failed"),
            },
        }
    }
}

impl Error for GhExecutionError {}

/// Injectable executor for planned GitHub API requests.
pub trait GhRunner {
    /// Execute one request and return bounded stdout bytes.
    ///
    /// # Errors
    ///
    /// Returns only redacted process failure categories.
    fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError>;

    /// Clone a lazy, credential-owning factory for one direct workflow dispatch client.
    ///
    /// Implementations must not read credentials or access the network until the returned
    /// factory is consumed. Callers consume it before publishing a temporary ref or committing a
    /// durable dispatch intent, so deterministic credential failures cannot strand that intent.
    ///
    /// # Errors
    ///
    /// Returns a redacted authentication or client-construction failure.
    fn workflow_dispatch_client_factory(
        &self,
    ) -> Result<Box<dyn GithubWorkflowDispatchHttpClientFactory>, GhExecutionError> {
        Err(GhExecutionError::AuthenticationUnavailable)
    }
}

/// Injectable executor for one fixed-argv Environment-secret write.
pub trait GhSecretRunner {
    /// Send the value only through child-process stdin.
    ///
    /// # Errors
    ///
    /// Returns only redacted process failure categories. Implementations must
    /// reject values above [`MAX_ENVIRONMENT_SECRET_BYTES`].
    fn set_environment_secret(
        &mut self,
        request: &EnvironmentSecretWriteRequest,
        value: &SecretBytes,
        timeout: Duration,
    ) -> Result<(), GhExecutionError>;
}

/// Exact environment variable accepted as a GitHub token source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEnvironmentVariable {
    /// GitHub CLI's preferred token variable.
    GhToken,
    /// GitHub Actions' standard token variable.
    GithubToken,
}

impl TokenEnvironmentVariable {
    fn as_str(self) -> &'static str {
        match self {
            Self::GhToken => "GH_TOKEN",
            Self::GithubToken => "GITHUB_TOKEN",
        }
    }
}

/// Explicit GitHub CLI authentication source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GhAuthentication {
    /// Read exactly one named token variable and use an isolated config dir.
    EnvironmentToken {
        /// Allowlisted variable name; never its value.
        variable: TokenEnvironmentVariable,
    },
    /// Use exactly one canonical `gh` configuration directory.
    ConfigDirectory(PathBuf),
}

impl GhAuthentication {
    /// Configure exact environment-token authentication. The token itself is
    /// not read until request execution.
    pub const fn environment_token(variable: TokenEnvironmentVariable) -> Self {
        Self::EnvironmentToken { variable }
    }

    /// Configure authentication through one exact `gh` config directory.
    ///
    /// # Errors
    ///
    /// Rejects a missing, relative, non-directory, or symlink-final path.
    pub fn config_directory(directory: impl AsRef<Path>) -> Result<Self, TransportConfigError> {
        Ok(Self::ConfigDirectory(canonical_directory(
            directory.as_ref(),
            "gh config directory",
        )?))
    }
}

#[derive(Debug)]
struct GhPrivateState {
    _lifetime: tempfile::TempDir,
    root: PathBuf,
}

/// Real fixed-argv GitHub CLI process runner.
#[derive(Clone, Debug)]
pub struct GhProcessRunner {
    executable: PathBuf,
    neutral_working_directory: PathBuf,
    authentication: GhAuthentication,
    configuration_directory: PathBuf,
    private_state: Arc<GhPrivateState>,
    #[cfg(windows)]
    system_root: PathBuf,
}

impl GhProcessRunner {
    /// Validate the executable, neutral working directory, and auth source.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute, missing, or unsuitable local paths.
    pub fn new(
        executable: impl AsRef<Path>,
        neutral_working_directory: impl AsRef<Path>,
        authentication: GhAuthentication,
    ) -> Result<Self, TransportConfigError> {
        let executable = canonical_file(executable.as_ref(), "gh executable")?;
        if !executable_basename_matches(&executable, "gh") {
            return Err(TransportConfigError::InvalidLocalPath {
                field: "gh executable",
            });
        }
        let neutral_working_directory = canonical_directory(
            neutral_working_directory.as_ref(),
            "neutral working directory",
        )?;
        let private_state = Arc::new(create_private_gh_state(&neutral_working_directory)?);
        let configuration_directory = match &authentication {
            GhAuthentication::EnvironmentToken { .. } => private_state.root.clone(),
            GhAuthentication::ConfigDirectory(directory) => directory.clone(),
        };
        #[cfg(windows)]
        let system_root = rustferry_core::windows_system_root().map_err(|_| {
            TransportConfigError::InvalidLocalPath {
                field: "Windows system root",
            }
        })?;
        Ok(Self {
            executable,
            neutral_working_directory,
            authentication,
            configuration_directory,
            private_state,
            #[cfg(windows)]
            system_root,
        })
    }

    fn command(&self, request: &GhRequest) -> Command {
        self.command_with_arguments(request.arguments(), Stdio::null())
    }

    fn environment_secret_command(&self, request: &EnvironmentSecretWriteRequest) -> Command {
        self.command_with_arguments(request.arguments(), Stdio::piped())
    }

    fn command_with_arguments(&self, arguments: Vec<OsString>, stdin: Stdio) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(arguments)
            .current_dir(&self.neutral_working_directory)
            .env_clear()
            .env("GH_CONFIG_DIR", &self.configuration_directory)
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("GH_TELEMETRY", "false")
            .env("DO_NOT_TRACK", "true")
            .env("GH_PAGER", "cat")
            .env("PAGER", "cat")
            .env("NO_COLOR", "1")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("XDG_STATE_HOME", &self.private_state.root)
            .env("HOME", &self.private_state.root)
            .env("USERPROFILE", &self.private_state.root)
            .env("APPDATA", &self.private_state.root)
            .env("LOCALAPPDATA", &self.private_state.root);
        #[cfg(windows)]
        command.env("SystemRoot", &self.system_root);
        command
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_tree(&mut command);
        command
    }

    fn apply_authentication(&self, command: &mut Command) -> Result<(), GhExecutionError> {
        if let GhAuthentication::EnvironmentToken { variable, .. } = &self.authentication {
            let name = variable.as_str();
            let value = std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .ok_or(GhExecutionError::AuthenticationUnavailable)?;
            command.env(name, value);
        }
        Ok(())
    }

    #[cfg(feature = "secure-job-log-http")]
    fn authentication_token_command(&self) -> Command {
        self.command_with_arguments(
            vec![
                OsString::from("auth"),
                OsString::from("token"),
                OsString::from("--hostname"),
                OsString::from(GITHUB_HOST),
            ],
            Stdio::null(),
        )
    }

    /// Acquire the configured credential and construct the bounded direct
    /// GitHub HTTPS client used by API dispatch and attempt-scoped job logs.
    ///
    /// Environment authentication reads only its selected allowlisted variable.
    /// Configuration-directory authentication runs exactly
    /// `gh auth token --hostname github.com` in the isolated process context.
    ///
    /// # Errors
    ///
    /// Returns a redacted authentication or bounded process failure. Token
    /// contents and command output are never included.
    #[cfg(feature = "secure-job-log-http")]
    pub fn github_api_http_client(&self) -> Result<UreqGithubApiHttpClient, GhExecutionError> {
        let token = match &self.authentication {
            GhAuthentication::EnvironmentToken { variable } => {
                let value = std::env::var(variable.as_str())
                    .map_err(|_| GhExecutionError::AuthenticationUnavailable)?;
                validate_github_token(value.into_bytes(), false)?
            }
            GhAuthentication::ConfigDirectory(_) => {
                let output = run_process(
                    self.authentication_token_command(),
                    GH_AUTH_TOKEN_TIMEOUT,
                    GH_AUTH_TOKEN_OUTPUT_BYTES,
                )?;
                validate_github_token(output, true)?
            }
        };
        UreqGithubJobLogHttpClient::new(token)
    }

    /// Backward-compatible job-log-specific name for the same fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a redacted authentication or bounded process failure.
    #[cfg(feature = "secure-job-log-http")]
    pub fn job_log_http_client(&self) -> Result<UreqGithubJobLogHttpClient, GhExecutionError> {
        self.github_api_http_client()
    }
}

#[cfg(feature = "secure-job-log-http")]
fn validate_github_token(
    mut bytes: Vec<u8>,
    strip_process_newline: bool,
) -> Result<SecretBytes, GhExecutionError> {
    if strip_process_newline && bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty()
        || bytes.len() > MAX_GITHUB_TOKEN_BYTES
        || !bytes.iter().all(|byte| (b'!'..=b'~').contains(byte))
    {
        let oversized = bytes.len() > MAX_GITHUB_TOKEN_BYTES;
        bytes.fill(0);
        return Err(if oversized {
            GhExecutionError::OutputLimitExceeded
        } else {
            GhExecutionError::AuthenticationUnavailable
        });
    }
    Ok(SecretBytes::new(bytes))
}

impl GhRunner for GhProcessRunner {
    fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
        let mut command = self.command(request);
        self.apply_authentication(&mut command)?;
        run_process(command, request.timeout, request.output_limit)
    }

    fn workflow_dispatch_client_factory(
        &self,
    ) -> Result<Box<dyn GithubWorkflowDispatchHttpClientFactory>, GhExecutionError> {
        #[cfg(feature = "secure-job-log-http")]
        {
            Ok(Box::new(self.clone()))
        }
        #[cfg(not(feature = "secure-job-log-http"))]
        {
            Err(GhExecutionError::AuthenticationUnavailable)
        }
    }
}

impl GhSecretRunner for GhProcessRunner {
    fn set_environment_secret(
        &mut self,
        request: &EnvironmentSecretWriteRequest,
        value: &SecretBytes,
        timeout: Duration,
    ) -> Result<(), GhExecutionError> {
        if value.len() > MAX_ENVIRONMENT_SECRET_BYTES {
            return Err(GhExecutionError::SecretTooLarge);
        }
        let mut command = self.environment_secret_command(request);
        self.apply_authentication(&mut command)?;
        run_process_with_secret_input(command, timeout, MAX_SECRET_SET_OUTPUT_BYTES, value)
    }
}

/// Production no-auto-redirect HTTPS adapter for attempt-scoped GitHub job logs.
///
/// The adapter owns the authorization value in zeroing [`SecretBytes`]. It
/// ignores ambient proxy variables, permits HTTPS only, returns redirects to
/// the caller without following them, and attaches authorization only to the
/// fixed GitHub API origin.
///
/// Enabling `secure-job-log-http` deliberately enables
/// `log/max_level_debug`. Cargo feature unification therefore compiles out
/// TRACE process-wide for any final binary that opts into this adapter. This
/// prevents ureq TRACE diagnostics from exposing signed redirect targets.
#[cfg(feature = "secure-job-log-http")]
pub struct UreqGithubJobLogHttpClient {
    agent: ureq::Agent,
    authorization: SecretBytes,
}

/// Direct fixed-origin GitHub API client; retained alias for additive dispatch use.
#[cfg(feature = "secure-job-log-http")]
pub type UreqGithubApiHttpClient = UreqGithubJobLogHttpClient;

#[cfg(feature = "secure-job-log-http")]
impl fmt::Debug for UreqGithubJobLogHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqGithubJobLogHttpClient")
            .field("https_only", &self.agent.config().https_only())
            .field("proxy", &"disabled")
            .field("redirects", &"disabled")
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "secure-job-log-http")]
impl UreqGithubJobLogHttpClient {
    /// Construct an adapter from one owned raw GitHub token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or non-ASCII tokens
    /// with a redacted authentication failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the adapter must take ownership and zero the supplied credential"
    )]
    pub fn new(token: SecretBytes) -> Result<Self, GhExecutionError> {
        validate_github_token_bytes(token.expose_secret_bytes())?;
        let mut authorization = Vec::with_capacity("Bearer ".len() + token.len());
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(token.expose_secret_bytes());
        Ok(Self {
            agent: build_job_log_agent(),
            authorization: SecretBytes::new(authorization),
        })
    }

    fn prepare_get(
        &self,
        target: &str,
        api_path: bool,
        authorization: GithubJobLogAuthorization,
        accept: GithubJobLogAccept,
        timeout: Duration,
    ) -> Result<ureq::RequestBuilder<ureq::typestate::WithoutBody>, GithubJobLogHttpError> {
        validate_job_log_request_mode(api_path, authorization, accept, timeout)?;
        let target = resolve_job_log_target(target, api_path)?;
        let mut builder = self.agent.get(target).header(
            "Accept",
            match accept {
                GithubJobLogAccept::Json => JOB_LOG_API_ACCEPT,
                GithubJobLogAccept::PlainText => JOB_LOG_PLAINTEXT_ACCEPT,
            },
        );
        if authorization == GithubJobLogAuthorization::GithubApi {
            let mut value =
                ureq::http::HeaderValue::from_bytes(self.authorization.expose_secret_bytes())
                    .map_err(|_| GithubJobLogHttpError::Protocol)?;
            value.set_sensitive(true);
            builder = builder
                .header("Authorization", value)
                .header("X-GitHub-Api-Version", JOB_LOG_API_VERSION);
        }
        Ok(builder
            .config()
            .timeout_global(Some(timeout))
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .build())
    }

    fn prepare_workflow_dispatch_post(
        &self,
        request: &GithubWorkflowDispatchHttpRequest,
    ) -> Result<ureq::RequestBuilder<ureq::typestate::WithBody>, GithubWorkflowDispatchHttpError>
    {
        let target = resolve_workflow_dispatch_target(request.endpoint())?;
        let mut authorization =
            ureq::http::HeaderValue::from_bytes(self.authorization.expose_secret_bytes())
                .map_err(|_| GithubWorkflowDispatchHttpError::Protocol)?;
        authorization.set_sensitive(true);
        Ok(self
            .agent
            .post(target)
            .header("Accept", request.accept())
            .header("Content-Type", request.content_type())
            .header("X-GitHub-Api-Version", request.api_version())
            .header("Authorization", authorization)
            .config()
            .timeout_global(Some(request.timeout()))
            .timeout_resolve(Some(request.timeout()))
            .timeout_connect(Some(request.timeout()))
            .timeout_send_request(Some(request.timeout()))
            .timeout_recv_response(Some(request.timeout()))
            .timeout_recv_body(Some(request.timeout()))
            .build())
    }
}

#[cfg(feature = "secure-job-log-http")]
fn validate_github_token_bytes(bytes: &[u8]) -> Result<(), GhExecutionError> {
    if bytes.is_empty()
        || bytes.len() > MAX_GITHUB_TOKEN_BYTES
        || !bytes.iter().all(|byte| (b'!'..=b'~').contains(byte))
    {
        return Err(if bytes.len() > MAX_GITHUB_TOKEN_BYTES {
            GhExecutionError::OutputLimitExceeded
        } else {
            GhExecutionError::AuthenticationUnavailable
        });
    }
    Ok(())
}

#[cfg(feature = "secure-job-log-http")]
fn build_job_log_agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .build();
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .https_only(true)
        .tls_config(tls)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .save_redirect_history(false)
        .user_agent(concat!("rustferry/", env!("CARGO_PKG_VERSION")))
        .accept("")
        .accept_encoding("")
        .timeout_global(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .timeout_resolve(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .timeout_connect(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .timeout_send_request(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .timeout_recv_response(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .timeout_recv_body(Some(MAX_JOB_LOG_HTTP_TIMEOUT))
        .max_response_header_size(MAX_JOB_LOG_RESPONSE_HEADER_BYTES)
        .build();
    config.into()
}

#[cfg(feature = "secure-job-log-http")]
fn validate_job_log_request_mode(
    api_path: bool,
    authorization: GithubJobLogAuthorization,
    accept: GithubJobLogAccept,
    timeout: Duration,
) -> Result<(), GithubJobLogHttpError> {
    if timeout.is_zero()
        || timeout > MAX_JOB_LOG_HTTP_TIMEOUT
        || !matches!(
            (api_path, authorization, accept),
            (
                true,
                GithubJobLogAuthorization::GithubApi,
                GithubJobLogAccept::Json
            ) | (
                false,
                GithubJobLogAuthorization::Omit,
                GithubJobLogAccept::PlainText
            )
        )
    {
        return Err(GithubJobLogHttpError::Protocol);
    }
    Ok(())
}

#[cfg(feature = "secure-job-log-http")]
fn resolve_job_log_target(target: &str, api_path: bool) -> Result<String, GithubJobLogHttpError> {
    if api_path {
        if !target.starts_with("/repos/")
            || target.starts_with("//")
            || !target.is_ascii()
            || target.bytes().any(|byte| {
                !byte.is_ascii_alphanumeric()
                    && !matches!(byte, b'/' | b'?' | b'=' | b'&' | b'_' | b'.' | b'-')
            })
        {
            return Err(GithubJobLogHttpError::Protocol);
        }
        return Ok(format!("{JOB_LOG_API_ORIGIN}{target}"));
    }

    let uri = target
        .parse::<ureq::http::Uri>()
        .map_err(|_| GithubJobLogHttpError::Protocol)?;
    if uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(GithubJobLogHttpError::Protocol);
    }
    Ok(target.to_owned())
}

/// Incremental, deadline-bound ureq response body.
#[cfg(feature = "secure-job-log-http")]
pub struct UreqGithubJobLogHttpBody {
    reader: ureq::BodyReader<'static>,
    request_deadline: Instant,
}

#[cfg(feature = "secure-job-log-http")]
impl GithubJobLogHttpBody for UreqGithubJobLogHttpBody {
    fn next_chunk(
        &mut self,
        maximum_bytes: usize,
        cancellation: &rustferry_remote::CancellationToken,
    ) -> Result<Option<Vec<u8>>, GithubJobLogHttpError> {
        read_job_log_body_chunk(
            &mut self.reader,
            maximum_bytes,
            self.request_deadline,
            cancellation,
        )
    }
}

#[cfg(feature = "secure-job-log-http")]
impl GithubJobLogHttpClient for UreqGithubJobLogHttpClient {
    type Body = UreqGithubJobLogHttpBody;

    fn get(
        &mut self,
        request: &GithubJobLogHttpRequest,
        cancellation: &rustferry_remote::CancellationToken,
    ) -> Result<GithubJobLogHttpResponse<Self::Body>, GithubJobLogHttpError> {
        let request_deadline = Instant::now()
            .checked_add(request.timeout())
            .ok_or(GithubJobLogHttpError::TimedOut)?;
        check_job_log_http_active(cancellation, request_deadline)?;
        let response = self
            .prepare_get(
                request.target(),
                request.is_api_path(),
                request.authorization(),
                request.accept(),
                request.timeout(),
            )?
            .call();
        check_job_log_http_active(cancellation, request_deadline)?;
        let response = response.map_err(map_ureq_request_error)?;

        let status = response.status().as_u16();
        let content_type = selected_job_log_header(response.headers(), "content-type")?;
        let location = selected_job_log_header(response.headers(), "location")?;
        let (_, body) = response.into_parts();
        Ok(GithubJobLogHttpResponse::new(
            status,
            content_type,
            location,
            UreqGithubJobLogHttpBody {
                reader: body.into_reader(),
                request_deadline,
            },
        ))
    }
}

#[cfg(feature = "secure-job-log-http")]
impl GithubWorkflowDispatchHttpClient for UreqGithubJobLogHttpClient {
    fn post(
        &mut self,
        request: &GithubWorkflowDispatchHttpRequest,
    ) -> Result<GithubWorkflowDispatchHttpResponse, GithubWorkflowDispatchHttpError> {
        if request.body().is_empty() || request.body().len() > MAX_WORKFLOW_DISPATCH_BODY_BYTES {
            return Err(GithubWorkflowDispatchHttpError::Protocol);
        }
        let response = self
            .prepare_workflow_dispatch_post(request)?
            .send(request.body())
            .map_err(map_ureq_workflow_dispatch_error)?;
        let status = response.status().as_u16();
        let content_type = selected_workflow_dispatch_header(response.headers(), "content-type")?;
        let (_, body) = response.into_parts();
        let mut reader = body
            .into_reader()
            .take(u64::try_from(request.response_limit()).unwrap_or(u64::MAX) + 1);
        let mut bytes = Vec::with_capacity(request.response_limit().saturating_add(1));
        reader
            .read_to_end(&mut bytes)
            .map_err(|error| map_ureq_workflow_dispatch_body_error(&error))?;
        if bytes.len() > request.response_limit() {
            bytes.fill(0);
            return Err(GithubWorkflowDispatchHttpError::ResponseTooLarge);
        }
        Ok(GithubWorkflowDispatchHttpResponse::new(
            status,
            content_type,
            bytes,
        ))
    }
}

#[cfg(feature = "secure-job-log-http")]
fn resolve_workflow_dispatch_target(
    endpoint: &str,
) -> Result<String, GithubWorkflowDispatchHttpError> {
    if !endpoint.starts_with("/repos/")
        || endpoint.starts_with("//")
        || !endpoint.is_ascii()
        || endpoint
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'/' | b'_' | b'.' | b'-'))
        || !endpoint.ends_with("/dispatches")
    {
        return Err(GithubWorkflowDispatchHttpError::Protocol);
    }
    Ok(format!("{JOB_LOG_API_ORIGIN}{endpoint}"))
}

#[cfg(feature = "secure-job-log-http")]
fn selected_workflow_dispatch_header(
    headers: &ureq::http::HeaderMap,
    name: &'static str,
) -> Result<Option<String>, GithubWorkflowDispatchHttpError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(GithubWorkflowDispatchHttpError::Protocol);
    }
    let value = value
        .to_str()
        .map_err(|_| GithubWorkflowDispatchHttpError::Protocol)?;
    if value.len() > MAX_JOB_LOG_RESPONSE_HEADER_BYTES {
        return Err(GithubWorkflowDispatchHttpError::Protocol);
    }
    Ok(Some(value.to_owned()))
}

#[cfg(feature = "secure-job-log-http")]
fn map_ureq_workflow_dispatch_error(error: ureq::Error) -> GithubWorkflowDispatchHttpError {
    match error {
        ureq::Error::Timeout(_) => GithubWorkflowDispatchHttpError::TimedOut,
        ureq::Error::Io(error) if io_error_is_timeout(&error) => {
            GithubWorkflowDispatchHttpError::TimedOut
        }
        ureq::Error::Http(_)
        | ureq::Error::BadUri(_)
        | ureq::Error::Protocol(_)
        | ureq::Error::RedirectFailed
        | ureq::Error::BodyExceedsLimit(_)
        | ureq::Error::TooManyRedirects
        | ureq::Error::RequireHttpsOnly(_)
        | ureq::Error::LargeResponseHeader(_, _)
        | ureq::Error::StatusCode(_) => GithubWorkflowDispatchHttpError::Protocol,
        _ => GithubWorkflowDispatchHttpError::Unavailable,
    }
}

#[cfg(feature = "secure-job-log-http")]
fn map_ureq_workflow_dispatch_body_error(error: &io::Error) -> GithubWorkflowDispatchHttpError {
    if io_error_is_timeout(error) {
        GithubWorkflowDispatchHttpError::TimedOut
    } else {
        GithubWorkflowDispatchHttpError::BodyRead
    }
}

#[cfg(feature = "secure-job-log-http")]
fn check_job_log_http_active(
    cancellation: &rustferry_remote::CancellationToken,
    deadline: Instant,
) -> Result<(), GithubJobLogHttpError> {
    if cancellation.is_cancelled() {
        Err(GithubJobLogHttpError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(GithubJobLogHttpError::TimedOut)
    } else {
        Ok(())
    }
}

#[cfg(feature = "secure-job-log-http")]
fn selected_job_log_header(
    headers: &ureq::http::HeaderMap,
    name: &'static str,
) -> Result<Option<String>, GithubJobLogHttpError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(GithubJobLogHttpError::Protocol);
    }
    let value = value
        .to_str()
        .map_err(|_| GithubJobLogHttpError::Protocol)?;
    if value.len() > MAX_JOB_LOG_RESPONSE_HEADER_BYTES {
        return Err(GithubJobLogHttpError::Protocol);
    }
    Ok(Some(value.to_owned()))
}

#[cfg(feature = "secure-job-log-http")]
fn read_job_log_body_chunk(
    reader: &mut impl Read,
    maximum_bytes: usize,
    request_deadline: Instant,
    cancellation: &rustferry_remote::CancellationToken,
) -> Result<Option<Vec<u8>>, GithubJobLogHttpError> {
    if cancellation.is_cancelled() {
        return Err(GithubJobLogHttpError::Cancelled);
    }
    if maximum_bytes == 0 || maximum_bytes > MAX_JOB_LOG_HTTP_CHUNK_BYTES {
        return Err(GithubJobLogHttpError::Protocol);
    }
    if Instant::now() >= request_deadline {
        return Err(GithubJobLogHttpError::TimedOut);
    }
    let mut bytes = vec![0_u8; maximum_bytes];
    let read = reader.read(&mut bytes);
    if cancellation.is_cancelled() {
        return Err(GithubJobLogHttpError::Cancelled);
    }
    if Instant::now() >= request_deadline {
        return Err(GithubJobLogHttpError::TimedOut);
    }
    let read = read.map_err(|error| map_ureq_body_error(&error))?;
    if read == 0 {
        return Ok(None);
    }
    bytes.truncate(read);
    Ok(Some(bytes))
}

#[cfg(feature = "secure-job-log-http")]
fn map_ureq_request_error(error: ureq::Error) -> GithubJobLogHttpError {
    match error {
        ureq::Error::Timeout(_) => GithubJobLogHttpError::TimedOut,
        ureq::Error::Io(error) if io_error_is_timeout(&error) => GithubJobLogHttpError::TimedOut,
        ureq::Error::Http(_)
        | ureq::Error::BadUri(_)
        | ureq::Error::Protocol(_)
        | ureq::Error::RedirectFailed
        | ureq::Error::BodyExceedsLimit(_)
        | ureq::Error::TooManyRedirects
        | ureq::Error::RequireHttpsOnly(_)
        | ureq::Error::LargeResponseHeader(_, _)
        | ureq::Error::StatusCode(_) => GithubJobLogHttpError::Protocol,
        _ => GithubJobLogHttpError::Unavailable,
    }
}

#[cfg(feature = "secure-job-log-http")]
fn map_ureq_body_error(error: &io::Error) -> GithubJobLogHttpError {
    if io_error_is_timeout(error) {
        GithubJobLogHttpError::TimedOut
    } else {
        GithubJobLogHttpError::BodyRead
    }
}

#[cfg(feature = "secure-job-log-http")]
fn io_error_is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
        .is_some_and(|source| matches!(source, ureq::Error::Timeout(_)))
}

fn create_private_gh_state(
    neutral_working_directory: &Path,
) -> Result<GhPrivateState, TransportConfigError> {
    let directory = tempfile::Builder::new()
        .prefix("rustferry-gh-")
        .tempdir()
        .map_err(|_| TransportConfigError::InvalidLocalPath {
            field: "private gh state directory",
        })?;
    let root = validate_private_gh_state_root(directory.path(), neutral_working_directory)?;
    Ok(GhPrivateState {
        _lifetime: directory,
        root,
    })
}

fn validate_private_gh_state_root(
    root: &Path,
    neutral_working_directory: &Path,
) -> Result<PathBuf, TransportConfigError> {
    let root = canonical_directory(root, "private gh state directory")?;
    let neutral_working_directory =
        canonical_directory(neutral_working_directory, "neutral working directory")?;
    if root.starts_with(neutral_working_directory) {
        return Err(TransportConfigError::InvalidLocalPath {
            field: "private gh state directory",
        });
    }
    Ok(root)
}

/// Parsed authenticated GitHub account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedUser {
    id: u64,
    login: String,
}

/// Validated GitHub API credential principal without overstating identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedPrincipal {
    /// User credential verified through `GET /user`.
    User(AuthenticatedUser),
    /// Installation credential whose accessible-repository list contains the
    /// exact requested repository.
    RepositoryCredential {
        /// Stable database ID returned by the installation repository list.
        repository_id: u64,
    },
}

impl AuthenticatedPrincipal {
    /// Stable human-readable principal label for diagnostics and JSON output.
    pub fn label(&self) -> &str {
        match self {
            Self::User(user) => user.login(),
            Self::RepositoryCredential { .. } => "repository-scoped token",
        }
    }

    /// Human login only when the API proved a user credential.
    pub fn user_login(&self) -> Option<&str> {
        match self {
            Self::User(user) => Some(user.login()),
            Self::RepositoryCredential { .. } => None,
        }
    }

    /// Exact repository ID independently proven by an installation credential.
    pub const fn repository_id(&self) -> Option<u64> {
        match self {
            Self::User(_) => None,
            Self::RepositoryCredential { repository_id } => Some(*repository_id),
        }
    }
}

impl AuthenticatedUser {
    /// Stable GitHub user database identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Authenticated GitHub login.
    pub fn login(&self) -> &str {
        &self.login
    }
}

/// Parsed repository metadata used before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryInfo {
    id: u64,
    full_name: String,
    private: bool,
    archived: bool,
    disabled: bool,
    default_branch: BranchName,
}

impl RepositoryInfo {
    /// Stable repository database identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Canonical owner/name returned by GitHub.
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Whether repository visibility is private.
    pub const fn is_private(&self) -> bool {
        self.private
    }

    /// Whether the repository is archived.
    pub const fn is_archived(&self) -> bool {
        self.archived
    }

    /// Whether GitHub has disabled the repository.
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Canonical default branch reported by GitHub.
    pub fn default_branch(&self) -> &BranchName {
        &self.default_branch
    }
}

/// Repository-scoped GitHub Actions availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionsPermissions {
    enabled: bool,
}

impl ActionsPermissions {
    /// Whether GitHub Actions is enabled for the exact repository.
    pub const fn enabled(self) -> bool {
        self.enabled
    }
}

/// One active workflow registration bound to its exact repository path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRegistration {
    repository: Repository,
    id: WorkflowId,
    path: String,
}

impl WorkflowRegistration {
    pub(crate) fn restore(
        repository: Repository,
        id: WorkflowId,
        path: impl Into<String>,
    ) -> Result<Self, TransportConfigError> {
        let path = path.into();
        validated_workflow_filename(&path).map_err(|_| TransportConfigError::InvalidFormat {
            field: "workflow registration path",
        })?;
        Ok(Self {
            repository,
            id,
            path,
        })
    }

    /// Exact repository whose API registry returned this workflow.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Stable GitHub workflow identifier.
    pub const fn id(&self) -> WorkflowId {
        self.id
    }

    /// Exact repository-relative workflow path returned by GitHub.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Validated public inputs for one no-secret workflow dispatch.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkflowDispatchRequest {
    repository: Repository,
    workflow: WorkflowRegistration,
    temporary_ref: TemporaryGitRef,
    operation_id: String,
    request_sha256: String,
    source_revision: CommitSha,
    dispatch_revision: CommitSha,
    run_name: String,
    body_sha256: String,
    body: Vec<u8>,
}

impl fmt::Debug for WorkflowDispatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowDispatchRequest")
            .field("repository", &self.repository)
            .field("workflow", &self.workflow)
            .field("temporary_ref", &self.temporary_ref)
            .field("operation_id", &self.operation_id)
            .field("request_sha256", &"<redacted>")
            .field("source_revision", &self.source_revision)
            .field("dispatch_revision", &self.dispatch_revision)
            .field("run_name", &"<redacted>")
            .field("body_sha256", &"<redacted>")
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl WorkflowDispatchRequest {
    /// Bind one exact temporary ref and complete public dispatch input set.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe operation identifier, a non-lowercase SHA-256, an
    /// operation/ref mismatch, or an unexpectedly large serialized body.
    pub fn new(
        repository: Repository,
        workflow: WorkflowRegistration,
        temporary_ref: TemporaryGitRef,
        operation_id: impl Into<String>,
        request_sha256: impl Into<String>,
        source_revision: CommitSha,
        dispatch_revision: CommitSha,
    ) -> Result<Self, TransportConfigError> {
        let operation_id = operation_id.into();
        if repository != workflow.repository {
            return Err(TransportConfigError::InvalidFormat {
                field: "workflow dispatch repository",
            });
        }
        validate_workflow_dispatch_operation(&operation_id)?;
        if temporary_ref
            .branch()
            .as_str()
            .rsplit_once('/')
            .is_none_or(|(_, suffix)| suffix != operation_id)
        {
            return Err(TransportConfigError::InvalidFormat {
                field: "workflow dispatch operation ref",
            });
        }
        let request_sha256 = request_sha256.into();
        validate_lower_sha256("request sha256", &request_sha256)?;
        let run_name = canonical_workflow_dispatch_run_name(
            &operation_id,
            &request_sha256,
            &source_revision,
            &dispatch_revision,
        )?;
        let body = serde_json::to_vec(&WorkflowDispatchBody {
            git_ref: temporary_ref.branch().as_str(),
            inputs: WorkflowDispatchInputs {
                operation_id: &operation_id,
                request_sha256: &request_sha256,
                source_revision: source_revision.as_str(),
                dispatch_revision: dispatch_revision.as_str(),
            },
        })
        .map_err(|_| TransportConfigError::InvalidFormat {
            field: "workflow dispatch body",
        })?;
        if body.len() > MAX_WORKFLOW_DISPATCH_BODY_BYTES {
            return Err(TransportConfigError::TooLong {
                field: "workflow dispatch body",
                maximum: MAX_WORKFLOW_DISPATCH_BODY_BYTES,
            });
        }
        let body_sha256 = hex::encode(Sha256::digest(&body));
        Ok(Self {
            repository,
            workflow,
            temporary_ref,
            operation_id,
            request_sha256,
            source_revision,
            dispatch_revision,
            run_name,
            body_sha256,
            body,
        })
    }

    /// Exact target repository.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Active workflow selected before dispatch.
    pub const fn workflow(&self) -> &WorkflowRegistration {
        &self.workflow
    }

    /// Exact temporary branch passed as the dispatch ref.
    pub const fn temporary_ref(&self) -> &TemporaryGitRef {
        &self.temporary_ref
    }

    /// Provider operation identifier.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Canonical complete request digest.
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    /// Exact trusted source commit.
    pub const fn source_revision(&self) -> &CommitSha {
        &self.source_revision
    }

    /// Exact temporary-ref commit expected as `GITHUB_SHA`.
    pub const fn dispatch_revision(&self) -> &CommitSha {
        &self.dispatch_revision
    }

    /// Exact public run title derived from all four dispatch inputs.
    pub fn run_name(&self) -> &str {
        &self.run_name
    }

    /// SHA-256 of the canonical no-secret dispatch body and its complete input set.
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }
}

#[derive(Serialize)]
struct WorkflowDispatchBody<'a> {
    #[serde(rename = "ref")]
    git_ref: &'a str,
    inputs: WorkflowDispatchInputs<'a>,
}

#[derive(Serialize)]
struct WorkflowDispatchInputs<'a> {
    operation_id: &'a str,
    request_sha256: &'a str,
    source_revision: &'a str,
    dispatch_revision: &'a str,
}

pub(crate) fn canonical_workflow_dispatch_run_name(
    operation_id: &str,
    request_sha256: &str,
    source_revision: &CommitSha,
    dispatch_revision: &CommitSha,
) -> Result<String, TransportConfigError> {
    validate_workflow_dispatch_operation(operation_id)?;
    validate_lower_sha256("request sha256", request_sha256)?;
    let run_name = format!(
        "{WORKFLOW_DISPATCH_RUN_NAME_PREFIX}{operation_id}|{request_sha256}|{}|{}",
        source_revision.as_str(),
        dispatch_revision.as_str()
    );
    if run_name.len() > MAX_WORKFLOW_DISPATCH_RUN_NAME_BYTES {
        return Err(TransportConfigError::TooLong {
            field: "workflow dispatch run name",
            maximum: MAX_WORKFLOW_DISPATCH_RUN_NAME_BYTES,
        });
    }
    Ok(run_name)
}

/// Bounded direct HTTPS request for one workflow dispatch.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWorkflowDispatchHttpRequest {
    endpoint: String,
    body: Vec<u8>,
    timeout: Duration,
}

impl fmt::Debug for GithubWorkflowDispatchHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchHttpRequest")
            .field("endpoint", &"<redacted>")
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl GithubWorkflowDispatchHttpRequest {
    /// Fixed GitHub API path. HTTP adapters must not log this value.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Exact deterministic JSON body. It contains no credential or raw device value.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Required GitHub media type.
    pub const fn accept(&self) -> &'static str {
        WORKFLOW_DISPATCH_ACCEPT
    }

    /// Required request content type.
    pub const fn content_type(&self) -> &'static str {
        WORKFLOW_DISPATCH_CONTENT_TYPE
    }

    /// Required API contract version.
    pub const fn api_version(&self) -> &'static str {
        WORKFLOW_DISPATCH_API_VERSION
    }

    /// Whole-request deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Maximum accepted response bytes.
    pub const fn response_limit(&self) -> usize {
        MAX_WORKFLOW_DISPATCH_RESPONSE_BYTES
    }
}

/// Bounded HTTP result. Debug output never includes response bytes or URLs.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWorkflowDispatchHttpResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl fmt::Debug for GithubWorkflowDispatchHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchHttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl GithubWorkflowDispatchHttpResponse {
    /// Construct one adapter response for strict transport validation.
    pub fn new(status: u16, content_type: Option<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }
}

/// Redacted direct-HTTPS dispatch failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubWorkflowDispatchHttpError {
    /// The fixed API endpoint or HTTP exchange violated the protocol.
    Protocol,
    /// The request exceeded its deadline.
    TimedOut,
    /// The response body could not be read.
    BodyRead,
    /// The response body exceeded the fixed cap.
    ResponseTooLarge,
    /// The HTTP client or network was unavailable.
    Unavailable,
}

impl fmt::Display for GithubWorkflowDispatchHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => formatter.write_str("GitHub workflow dispatch protocol failed"),
            Self::TimedOut => formatter.write_str("GitHub workflow dispatch timed out"),
            Self::BodyRead => formatter.write_str("GitHub workflow dispatch response read failed"),
            Self::ResponseTooLarge => {
                formatter.write_str("GitHub workflow dispatch response exceeded its limit")
            }
            Self::Unavailable => formatter.write_str("GitHub workflow dispatch is unavailable"),
        }
    }
}

impl Error for GithubWorkflowDispatchHttpError {}

/// Injectable no-auto-redirect HTTPS adapter for workflow dispatch.
pub trait GithubWorkflowDispatchHttpClient {
    /// Send one fixed-origin API request and return a bounded response.
    ///
    /// # Errors
    ///
    /// Returns only redacted transport categories; credentials, endpoints,
    /// bodies, response URLs, and underlying diagnostics must not surface.
    fn post(
        &mut self,
        request: &GithubWorkflowDispatchHttpRequest,
    ) -> Result<GithubWorkflowDispatchHttpResponse, GithubWorkflowDispatchHttpError>;
}

/// Lazy factory detached from the provider's metadata-transport lock.
pub trait GithubWorkflowDispatchHttpClientFactory: Send {
    /// Consume the factory and acquire one credential-owning direct HTTPS client.
    ///
    /// # Errors
    ///
    /// Returns only redacted authentication or bounded process failures.
    fn create(
        self: Box<Self>,
    ) -> Result<Box<dyn GithubWorkflowDispatchHttpClient + Send>, GhExecutionError>;
}

/// One request-scoped dispatch attempt detached from the metadata transport lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowDispatchAttempt {
    http_request: GithubWorkflowDispatchHttpRequest,
    request: WorkflowDispatchRequest,
}

impl WorkflowDispatchAttempt {
    pub(crate) fn send(
        self,
        client: &mut (impl GithubWorkflowDispatchHttpClient + ?Sized),
    ) -> Result<WorkflowDispatchReceipt, TransportError> {
        let response = client.post(&self.http_request)?;
        if response.status != 200 {
            return Err(TransportError::WorkflowDispatchStatusMismatch);
        }
        if response.body.len() > MAX_WORKFLOW_DISPATCH_RESPONSE_BYTES
            || response.content_type.as_deref().is_none_or(|content_type| {
                content_type
                    .split_once(';')
                    .map_or(content_type, |(media_type, _)| media_type)
                    .trim()
                    != WORKFLOW_DISPATCH_CONTENT_TYPE
            })
        {
            return Err(TransportError::MalformedResponse {
                operation: "workflow dispatch receipt",
            });
        }
        let wire: WorkflowDispatchReceiptWire =
            crate::strict_json::decode(&response.body, MAX_WORKFLOW_DISPATCH_RESPONSE_BYTES)
                .map_err(|_| TransportError::MalformedResponse {
                    operation: "workflow dispatch receipt",
                })?;
        let run_id =
            RunId::new(wire.workflow_run_id).map_err(|_| TransportError::MalformedResponse {
                operation: "workflow dispatch receipt",
            })?;
        if !valid_workflow_dispatch_receipt_url(
            &wire.run_url,
            "https://api.github.com/repos/",
            &self.request.repository,
            run_id,
        ) || !valid_workflow_dispatch_receipt_url(
            &wire.html_url,
            "https://github.com/",
            &self.request.repository,
            run_id,
        ) {
            return Err(TransportError::MalformedResponse {
                operation: "workflow dispatch receipt",
            });
        }
        Ok(WorkflowDispatchReceipt {
            repository: self.request.repository.clone(),
            run_id,
            workflow_id: self.request.workflow.id,
            workflow_path: self.request.workflow.path.clone(),
            dispatch_revision: self.request.dispatch_revision.clone(),
            branch: self.request.temporary_ref.branch().clone(),
            run_name: self.request.run_name.clone(),
        })
    }
}

#[cfg(feature = "secure-job-log-http")]
impl GithubWorkflowDispatchHttpClientFactory for GhProcessRunner {
    fn create(
        self: Box<Self>,
    ) -> Result<Box<dyn GithubWorkflowDispatchHttpClient + Send>, GhExecutionError> {
        self.github_api_http_client()
            .map(|client| Box::new(client) as Box<dyn GithubWorkflowDispatchHttpClient + Send>)
    }
}

/// Secret-free receipt binding one positive run ID to every expected run identity field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDispatchReceipt {
    repository: Repository,
    run_id: RunId,
    workflow_id: WorkflowId,
    workflow_path: String,
    dispatch_revision: CommitSha,
    branch: BranchName,
    run_name: String,
}

impl WorkflowDispatchReceipt {
    pub(crate) fn restore(
        repository: Repository,
        run_id: RunId,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        dispatch_revision: CommitSha,
        branch: BranchName,
        run_name: impl Into<String>,
    ) -> Result<Self, TransportConfigError> {
        let workflow_path = workflow_path.into();
        let run_name = run_name.into();
        validated_workflow_filename(&workflow_path).map_err(|_| {
            TransportConfigError::InvalidFormat {
                field: "workflow dispatch receipt path",
            }
        })?;
        if run_name.is_empty() || run_name.len() > MAX_WORKFLOW_DISPATCH_RUN_NAME_BYTES {
            return Err(TransportConfigError::InvalidFormat {
                field: "workflow dispatch receipt run name",
            });
        }
        Ok(Self {
            repository,
            run_id,
            workflow_id,
            workflow_path,
            dispatch_revision,
            branch,
            run_name,
        })
    }

    /// Exact repository that accepted the dispatch.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Positive run identifier returned by the 2026-03-10 API.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Workflow registration used for the dispatch.
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Exact registered workflow path.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Exact commit expected from the run metadata and worker `GITHUB_SHA`.
    pub const fn dispatch_revision(&self) -> &CommitSha {
        &self.dispatch_revision
    }

    /// Exact temporary branch expected from run metadata and worker `GITHUB_REF`.
    pub const fn branch(&self) -> &BranchName {
        &self.branch
    }

    /// Exact public run title binding all four dispatch inputs.
    pub fn run_name(&self) -> &str {
        &self.run_name
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowDispatchReceiptWire {
    workflow_run_id: u64,
    run_url: String,
    html_url: String,
}

/// Security-relevant metadata for one exact GitHub Environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentInfo {
    name: String,
    protected_branches: bool,
    custom_branch_policies: bool,
    has_required_reviewers: bool,
}

impl EnvironmentInfo {
    /// Exact environment name returned by GitHub.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether deployments are limited to repository-protected branches.
    pub const fn protected_branches(&self) -> bool {
        self.protected_branches
    }

    /// Whether deployments require a custom branch-policy match.
    pub const fn custom_branch_policies(&self) -> bool {
        self.custom_branch_policies
    }

    /// Whether at least one required deployment reviewer is configured.
    pub const fn has_required_reviewers(&self) -> bool {
        self.has_required_reviewers
    }
}

/// One bounded custom deployment branch policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentBranchPolicy {
    id: u64,
    name: String,
}

impl DeploymentBranchPolicy {
    /// Stable GitHub branch-policy identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Exact branch name pattern returned by GitHub.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Metadata for one environment secret; secret values are never readable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSecret {
    name: SecretName,
}

impl EnvironmentSecret {
    /// Exact configured secret name.
    pub fn name(&self) -> &SecretName {
        &self.name
    }
}

/// Current GitHub Actions run state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunStatus {
    /// Run was requested but has not entered the queue.
    Requested,
    /// Run is queued.
    Queued,
    /// Run is pending.
    Pending,
    /// Run awaits an external gate such as environment approval.
    Waiting,
    /// Run is executing.
    InProgress,
    /// Run reached a terminal conclusion.
    Completed,
}

impl RunStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "queued" => Some(Self::Queued),
            "pending" => Some(Self::Pending),
            "waiting" => Some(Self::Waiting),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }

    /// Whether GitHub considers the run terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// Terminal GitHub Actions run conclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunConclusion {
    /// All required jobs succeeded.
    Success,
    /// At least one required job failed.
    Failure,
    /// The run was cancelled.
    Cancelled,
    /// The run exceeded a GitHub timeout.
    TimedOut,
    /// The run completed without a pass/fail result.
    Neutral,
    /// The run was skipped.
    Skipped,
    /// GitHub marked the run stale.
    Stale,
    /// The run requires action outside its jobs.
    ActionRequired,
    /// GitHub rejected startup before executing jobs.
    StartupFailure,
}

impl RunConclusion {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "cancelled" => Some(Self::Cancelled),
            "timed_out" => Some(Self::TimedOut),
            "neutral" => Some(Self::Neutral),
            "skipped" => Some(Self::Skipped),
            "stale" => Some(Self::Stale),
            "action_required" => Some(Self::ActionRequired),
            "startup_failure" => Some(Self::StartupFailure),
            _ => None,
        }
    }
}

/// Exact identity selected during run lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunHandle {
    id: RunId,
    workflow_id: WorkflowId,
    workflow_path: String,
    head_sha: CommitSha,
    branch: BranchName,
    event: RunEvent,
}

impl RunHandle {
    /// Reconstruct one already validated durable run identity inside this crate.
    pub(crate) fn restore(
        id: u64,
        workflow_id: u64,
        workflow_path: String,
        head_sha: String,
        branch: String,
        event: RunEvent,
    ) -> Result<Self, TransportConfigError> {
        validated_workflow_filename(&workflow_path).map_err(|_| {
            TransportConfigError::InvalidFormat {
                field: "workflow path",
            }
        })?;
        Ok(Self {
            id: RunId::new(id)?,
            workflow_id: WorkflowId::new(workflow_id)?,
            workflow_path,
            head_sha: CommitSha::new(head_sha)?,
            branch: BranchName::new(branch)?,
            event,
        })
    }

    /// Stable run identifier.
    pub const fn id(&self) -> RunId {
        self.id
    }

    /// Workflow owning the run.
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Repository-relative workflow file path returned by GitHub.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Exact head commit.
    pub fn head_sha(&self) -> &CommitSha {
        &self.head_sha
    }

    /// Exact temporary branch.
    pub fn branch(&self) -> &BranchName {
        &self.branch
    }

    /// Trigger event.
    pub const fn event(&self) -> RunEvent {
        self.event
    }
}

/// One locally identity-checked run observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshot {
    handle: RunHandle,
    run_number: u64,
    run_attempt: u64,
    status: RunStatus,
    conclusion: Option<RunConclusion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowDispatchRunSnapshot {
    snapshot: RunSnapshot,
    run_name: String,
}

impl RunSnapshot {
    /// Reconstruct one validated durable observation inside this crate.
    pub(crate) fn restore(
        handle: RunHandle,
        run_number: u64,
        run_attempt: u64,
        status: RunStatus,
        conclusion: Option<RunConclusion>,
    ) -> Result<Self, TransportConfigError> {
        if run_number == 0 || run_attempt == 0 || (status.is_terminal() != conclusion.is_some()) {
            return Err(TransportConfigError::InvalidFormat {
                field: "run snapshot",
            });
        }
        Ok(Self {
            handle,
            run_number,
            run_attempt,
            status,
            conclusion,
        })
    }

    /// Exact immutable run identity.
    pub fn handle(&self) -> &RunHandle {
        &self.handle
    }

    /// Repository-local run number.
    pub const fn run_number(&self) -> u64 {
        self.run_number
    }

    /// Current attempt number.
    pub const fn run_attempt(&self) -> u64 {
        self.run_attempt
    }

    /// Current status.
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    /// Terminal conclusion, present only for completed runs.
    pub const fn conclusion(&self) -> Option<RunConclusion> {
        self.conclusion
    }
}

/// Bounded artifact metadata returned by one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactInfo {
    id: ArtifactId,
    name: String,
    size_bytes: u64,
    expired: bool,
    digest: Option<String>,
}

impl ArtifactInfo {
    /// Stable artifact identifier.
    pub const fn id(&self) -> ArtifactId {
        self.id
    }

    /// Exact GitHub artifact name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Size reported by the GitHub API.
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Whether GitHub has expired the artifact.
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// Optional lowercase `sha256:<hex>` digest reported by GitHub.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// Canonical download directory plus a safe ZIP basename.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDownloadTarget {
    directory: PathBuf,
    filename: String,
}

impl ArtifactDownloadTarget {
    /// Validate a pre-existing destination directory and new ZIP basename.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical directories, paths in the basename, traversal,
    /// and names not ending in `.zip`.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn new(
        directory: impl AsRef<Path>,
        filename: impl Into<String>,
    ) -> Result<Self, TransportConfigError> {
        let directory = canonical_directory(directory.as_ref(), "artifact directory")?;
        let filename = filename.into();
        validate_nonempty_length("artifact filename", &filename, 128)?;
        validate_ascii_allowlist("artifact filename", &filename, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })?;
        if !filename.as_bytes()[0].is_ascii_alphanumeric()
            || !filename.ends_with(".zip")
            || filename.contains("..")
        {
            return Err(TransportConfigError::InvalidFormat {
                field: "artifact filename",
            });
        }
        Ok(Self {
            directory,
            filename,
        })
    }

    /// Final absolute path. The file must not exist before download.
    pub fn path(&self) -> PathBuf {
        self.directory.join(&self.filename)
    }
}

/// Completed bounded artifact download.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadedArtifact {
    path: PathBuf,
    bytes: u64,
}

impl DownloadedArtifact {
    /// Absolute ZIP path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Exact downloaded byte count.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Redacted transport or response-validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The underlying fixed-argv request failed.
    Execution(GhExecutionError),
    /// The direct no-auto-redirect workflow-dispatch exchange failed.
    WorkflowDispatchHttp(GithubWorkflowDispatchHttpError),
    /// One Environment-secret value exceeded GitHub's fixed 48 KiB limit.
    EnvironmentSecretTooLarge,
    /// GitHub returned malformed or unsupported metadata.
    MalformedResponse {
        /// Stable operation name; response bytes are intentionally omitted.
        operation: &'static str,
    },
    /// Repository metadata did not match the exact requested owner/name.
    RepositoryIdentityMismatch,
    /// An installation credential did not include the exact requested repository.
    RepositoryAuthorizationMissing,
    /// Environment metadata did not match the exact configured name.
    EnvironmentIdentityMismatch,
    /// Workflow path was not one validated `.github/workflows/*.yml` file.
    InvalidWorkflowPath,
    /// Workflow metadata did not match the exact requested path.
    WorkflowIdentityMismatch,
    /// The exact registered workflow is not active.
    WorkflowInactive,
    /// Workflow dispatch did not return the required HTTP 200 response.
    WorkflowDispatchStatusMismatch,
    /// No exact matching run was found within the page bound.
    RunNotFound,
    /// More than one exact matching run was returned.
    AmbiguousRun,
    /// A known run changed immutable identity fields.
    RunIdentityMismatch,
    /// Polling ended before the run became terminal.
    PollLimitReached,
    /// Pagination filled every allowed page, so results may be incomplete.
    PaginationLimitReached {
        /// Stable resource kind.
        resource: &'static str,
    },
    /// No exact artifact name matched.
    ArtifactNotFound,
    /// More than one artifact had the exact expected name.
    AmbiguousArtifact,
    /// The selected artifact has expired.
    ArtifactExpired,
    /// Artifact metadata or response exceeded the configured size bound.
    ArtifactTooLarge,
    /// Downloaded bytes were not structurally recognizable as one ZIP file.
    InvalidArtifactZip,
    /// Downloaded byte count differs from the exact GitHub metadata.
    ArtifactSizeMismatch,
    /// Downloaded SHA-256 differs from the exact GitHub metadata.
    ArtifactDigestMismatch,
    /// The exact destination already exists; it is never overwritten.
    DestinationExists,
    /// Creating, writing, syncing, or verifying the new destination failed.
    ArtifactWriteFailed,
    /// A failed create, write, or verification may have left the new destination on disk.
    ArtifactCleanupUncertain,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Execution(error) => error.fmt(formatter),
            Self::WorkflowDispatchHttp(error) => error.fmt(formatter),
            Self::EnvironmentSecretTooLarge => {
                formatter.write_str("GitHub Environment secret exceeds size limit")
            }
            Self::MalformedResponse { operation } => {
                write!(formatter, "GitHub returned malformed {operation} metadata")
            }
            Self::RepositoryIdentityMismatch => {
                formatter.write_str("GitHub returned a different repository identity")
            }
            Self::RepositoryAuthorizationMissing => formatter.write_str(
                "the GitHub installation credential does not authorize the exact repository",
            ),
            Self::EnvironmentIdentityMismatch => {
                formatter.write_str("GitHub returned a different environment identity")
            }
            Self::InvalidWorkflowPath => formatter.write_str("workflow path is invalid"),
            Self::WorkflowIdentityMismatch => {
                formatter.write_str("GitHub returned a different workflow identity")
            }
            Self::WorkflowInactive => formatter.write_str("GitHub workflow is not active"),
            Self::WorkflowDispatchStatusMismatch => {
                formatter.write_str("GitHub workflow dispatch returned an unexpected status")
            }
            Self::RunNotFound => formatter.write_str("matching GitHub Actions run was not found"),
            Self::AmbiguousRun => {
                formatter.write_str("multiple GitHub Actions runs matched exact identity")
            }
            Self::RunIdentityMismatch => formatter.write_str("GitHub Actions run identity changed"),
            Self::PollLimitReached => {
                formatter.write_str("GitHub Actions polling limit was reached")
            }
            Self::PaginationLimitReached { resource } => {
                write!(formatter, "GitHub {resource} pagination limit was reached")
            }
            Self::ArtifactNotFound => formatter.write_str("matching artifact was not found"),
            Self::AmbiguousArtifact => {
                formatter.write_str("multiple artifacts had the expected name")
            }
            Self::ArtifactExpired => formatter.write_str("GitHub artifact has expired"),
            Self::ArtifactTooLarge => formatter.write_str("GitHub artifact exceeds size limit"),
            Self::InvalidArtifactZip => {
                formatter.write_str("GitHub artifact response is not a valid ZIP envelope")
            }
            Self::ArtifactSizeMismatch => {
                formatter.write_str("downloaded artifact size differs from GitHub metadata")
            }
            Self::ArtifactDigestMismatch => {
                formatter.write_str("downloaded artifact digest differs from GitHub metadata")
            }
            Self::DestinationExists => formatter.write_str("artifact destination already exists"),
            Self::ArtifactWriteFailed => formatter.write_str("artifact write failed"),
            Self::ArtifactCleanupUncertain => {
                formatter.write_str("artifact cleanup could not be confirmed")
            }
        }
    }
}

impl Error for TransportError {}

impl From<GhExecutionError> for TransportError {
    fn from(value: GhExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<GithubWorkflowDispatchHttpError> for TransportError {
    fn from(value: GithubWorkflowDispatchHttpError) -> Self {
        Self::WorkflowDispatchHttp(value)
    }
}

/// Sleeper injection used to test bounded polling without wall-clock delay.
pub trait PollSleeper {
    /// Wait once between two API polls.
    fn sleep(&mut self, duration: Duration);
}

/// Standard thread-based polling sleeper.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThreadPollSleeper;

impl PollSleeper for ThreadPollSleeper {
    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// GitHub.com transport over an injectable `gh api` runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubTransport<R> {
    runner: R,
    limits: TransportLimits,
}

impl<R> GithubTransport<R> {
    /// Bind a runner to explicit bounded transport limits.
    pub const fn new(runner: R, limits: TransportLimits) -> Self {
        Self { runner, limits }
    }

    /// Recover the runner, including captured requests in test adapters.
    pub fn into_runner(self) -> R {
        self.runner
    }

    /// Borrow the runner for adapter-specific inspection.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Dispatch one active registered workflow through a direct, no-redirect
    /// HTTPS adapter and parse the strict 2026-03-10 receipt.
    ///
    /// # Errors
    ///
    /// Requires HTTP 200, JSON content, an exact bounded response object, and
    /// a positive workflow run identifier. Response URLs are validated then
    /// discarded and never enter the returned receipt or diagnostics.
    pub fn dispatch_workflow(
        &self,
        client: &mut (impl GithubWorkflowDispatchHttpClient + ?Sized),
        request: &WorkflowDispatchRequest,
    ) -> Result<WorkflowDispatchReceipt, TransportError> {
        self.workflow_dispatch_attempt(request).send(client)
    }

    pub(crate) fn workflow_dispatch_attempt(
        &self,
        request: &WorkflowDispatchRequest,
    ) -> WorkflowDispatchAttempt {
        WorkflowDispatchAttempt {
            http_request: GithubWorkflowDispatchHttpRequest {
                endpoint: request.repository.endpoint(&format!(
                    "/actions/workflows/{}/dispatches",
                    request.workflow.id.get()
                )),
                body: request.body.clone(),
                timeout: self.limits.api_timeout,
            },
            request: request.clone(),
        }
    }
}

impl<R: GhSecretRunner> GithubTransport<R> {
    /// Set one bounded GitHub Environment secret through fixed argv and stdin.
    ///
    /// # Errors
    ///
    /// Rejects values above GitHub's 48 KiB limit before invoking the runner.
    /// Process failures are redacted and never include the secret value.
    pub fn set_environment_secret(
        &mut self,
        request: &EnvironmentSecretWriteRequest,
        value: &SecretBytes,
    ) -> Result<EnvironmentSecretWriteReceipt, TransportError> {
        if value.len() > MAX_ENVIRONMENT_SECRET_BYTES {
            return Err(TransportError::EnvironmentSecretTooLarge);
        }
        self.runner
            .set_environment_secret(request, value, self.limits.api_timeout)?;
        Ok(EnvironmentSecretWriteReceipt {
            repository: request.repository.clone(),
            environment: request.environment.clone(),
            name: request.name.clone(),
        })
    }
}

impl<R: GhRunner> GithubTransport<R> {
    /// Prove the configured credential by API capability, then bind it to the
    /// exact repository when it is an installation token.
    ///
    /// # Errors
    ///
    /// Returns a redacted execution or response-validation failure. A user
    /// credential must satisfy `GET /user`. If that capability is
    /// rejected, the credential must satisfy the installation-only accessible
    /// repositories endpoint and list the exact target. Environment variable
    /// names are never used to infer token type.
    pub fn authenticate(
        &mut self,
        repository: &Repository,
    ) -> Result<AuthenticatedPrincipal, TransportError> {
        match self.authenticated_user() {
            Ok(user) => Ok(AuthenticatedPrincipal::User(user)),
            Err(TransportError::Execution(GhExecutionError::CommandFailed { .. })) => {
                let repository_id = self.prove_installation_repository_access(repository)?;
                Ok(AuthenticatedPrincipal::RepositoryCredential { repository_id })
            }
            Err(error) => Err(error),
        }
    }

    /// Verify authentication through `GET /user`.
    ///
    /// # Errors
    ///
    /// Returns a redacted execution or response-validation failure.
    pub fn authenticated_user(&mut self) -> Result<AuthenticatedUser, TransportError> {
        let request = self.metadata_request(ApiMethod::Get, "/user".to_owned(), USER_QUERY);
        let output = self.runner.execute(&request)?;
        let line = parse_single_utf8_line(&output, "authenticated user")?;
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 2 {
            return Err(TransportError::MalformedResponse {
                operation: "authenticated user",
            });
        }
        let id = columns[0].parse::<u64>().ok().filter(|id| *id != 0).ok_or(
            TransportError::MalformedResponse {
                operation: "authenticated user",
            },
        )?;
        let login = decode_base64(columns[1])
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or(TransportError::MalformedResponse {
                operation: "authenticated user",
            })?;
        validate_owner(&login).map_err(|_| TransportError::MalformedResponse {
            operation: "authenticated user",
        })?;
        Ok(AuthenticatedUser { id, login })
    }

    /// Fetch and locally bind repository metadata to the exact owner/name.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata and case-insensitive identity mismatches.
    pub fn repository(
        &mut self,
        repository: &Repository,
    ) -> Result<RepositoryInfo, TransportError> {
        let request =
            self.metadata_request(ApiMethod::Get, repository.endpoint(""), REPOSITORY_QUERY);
        let output = self.runner.execute(&request)?;
        parse_repository(&output, repository)
    }

    /// Fetch the exact repository's GitHub Actions enablement policy.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or malformed repository policy metadata.
    pub fn actions_permissions(
        &mut self,
        repository: &Repository,
    ) -> Result<ActionsPermissions, TransportError> {
        let request = self.metadata_request(
            ApiMethod::Get,
            repository.endpoint("/actions/permissions"),
            ACTIONS_PERMISSIONS_QUERY,
        );
        let output = self.runner.execute(&request)?;
        parse_actions_permissions(&output)
    }

    /// Resolve one workflow file through GitHub's registry and require an
    /// active registration at the exact repository-relative path.
    ///
    /// # Errors
    ///
    /// Rejects an invalid requested path, malformed metadata, path drift, or
    /// any state other than `active`.
    pub fn workflow_registration(
        &mut self,
        repository: &Repository,
        workflow_path: &str,
    ) -> Result<WorkflowRegistration, TransportError> {
        let filename = validated_workflow_filename(workflow_path)?;
        let endpoint = repository.endpoint(&format!("/actions/workflows/{filename}"));
        let request = self.metadata_request_at_version(
            ApiMethod::Get,
            endpoint,
            WORKFLOW_QUERY,
            WORKFLOW_DISPATCH_API_VERSION_HEADER,
        );
        let output = self.runner.execute(&request)?;
        parse_workflow_registration(&output, repository, workflow_path)
    }

    fn prove_installation_repository_access(
        &mut self,
        repository: &Repository,
    ) -> Result<u64, TransportError> {
        for page in 1..=self.limits.pages {
            let fields = vec![
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let request = self.metadata_request_with_fields(
                ApiMethod::Get,
                "/installation/repositories".to_owned(),
                fields,
                INSTALLATION_REPOSITORY_QUERY,
            );
            let output = self.runner.execute(&request)?;
            let repositories = parse_installation_repositories(&output)?;
            let page_length = repositories.len();
            if let Some(candidate) = repositories.iter().find(|candidate| {
                candidate
                    .repository
                    .full_name()
                    .eq_ignore_ascii_case(&repository.full_name())
            }) {
                return Ok(candidate.id);
            }
            if page_length < usize::from(self.limits.per_page) {
                return Err(TransportError::RepositoryAuthorizationMissing);
            }
        }
        Err(TransportError::PaginationLimitReached {
            resource: "installation repository",
        })
    }

    /// Fetch and bind one exact protected signing environment.
    ///
    /// # Errors
    ///
    /// Rejects malformed policy metadata or an environment identity mismatch.
    pub fn environment(
        &mut self,
        repository: &Repository,
        environment: &ProtectedEnvironment,
    ) -> Result<EnvironmentInfo, TransportError> {
        let endpoint = repository.endpoint(&format!("/environments/{}", environment.as_str()));
        let request = self.metadata_request(ApiMethod::Get, endpoint, ENVIRONMENT_QUERY);
        let output = self.runner.execute(&request)?;
        parse_environment(&output, environment)
    }

    /// List every custom deployment branch policy within the page bound.
    ///
    /// # Errors
    ///
    /// Rejects malformed or duplicate metadata and incomplete pagination.
    pub fn list_deployment_branch_policies(
        &mut self,
        repository: &Repository,
        environment: &ProtectedEnvironment,
    ) -> Result<Vec<DeploymentBranchPolicy>, TransportError> {
        let mut policies = Vec::new();
        let mut names = BTreeSet::new();
        for page in 1..=self.limits.pages {
            let endpoint = repository.endpoint(&format!(
                "/environments/{}/deployment-branch-policies",
                environment.as_str()
            ));
            let fields = vec![
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let request = self.metadata_request_with_fields(
                ApiMethod::Get,
                endpoint,
                fields,
                DEPLOYMENT_BRANCH_POLICY_LIST_QUERY,
            );
            let output = self.runner.execute(&request)?;
            let page_policies = parse_deployment_branch_policies(&output)?;
            let page_length = page_policies.len();
            for policy in page_policies {
                if !names.insert(policy.name.clone()) {
                    return Err(TransportError::MalformedResponse {
                        operation: "deployment branch policy list",
                    });
                }
                policies.push(policy);
            }
            if page_length < usize::from(self.limits.per_page) {
                return Ok(policies);
            }
        }
        Err(TransportError::PaginationLimitReached {
            resource: "deployment branch policy",
        })
    }

    /// List environment-secret names without reading any secret value.
    ///
    /// # Errors
    ///
    /// Rejects malformed or duplicate names and incomplete pagination.
    pub fn list_environment_secrets(
        &mut self,
        repository: &Repository,
        environment: &ProtectedEnvironment,
    ) -> Result<Vec<EnvironmentSecret>, TransportError> {
        let mut secrets = Vec::new();
        let mut names = BTreeSet::new();
        for page in 1..=self.limits.pages {
            let endpoint =
                repository.endpoint(&format!("/environments/{}/secrets", environment.as_str()));
            let fields = vec![
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let request = self.metadata_request_with_fields(
                ApiMethod::Get,
                endpoint,
                fields,
                ENVIRONMENT_SECRET_LIST_QUERY,
            );
            let output = self.runner.execute(&request)?;
            let page_secrets = parse_environment_secrets(&output)?;
            let page_length = page_secrets.len();
            for secret in page_secrets {
                if !names.insert(secret.name.clone()) {
                    return Err(TransportError::MalformedResponse {
                        operation: "environment secret list",
                    });
                }
                secrets.push(secret);
            }
            if page_length < usize::from(self.limits.per_page) {
                return Ok(secrets);
            }
        }
        Err(TransportError::PaginationLimitReached {
            resource: "environment secret",
        })
    }

    /// Find exactly one workflow run by workflow path, head SHA, branch, and event.
    ///
    /// # Errors
    ///
    /// Rejects malformed pages, ambiguity, missing exact matches, and a full
    /// final page at the pagination bound.
    pub fn find_run(
        &mut self,
        repository: &Repository,
        workflow_path: &str,
        head_sha: &CommitSha,
        branch: &BranchName,
        event: RunEvent,
    ) -> Result<RunHandle, TransportError> {
        validated_workflow_filename(workflow_path)?;
        let mut matching: Option<RunSnapshot> = None;
        for page in 1..=self.limits.pages {
            let endpoint = repository.endpoint("/actions/runs");
            let fields = vec![
                ("head_sha".to_owned(), head_sha.as_str().to_owned()),
                ("branch".to_owned(), branch.as_str().to_owned()),
                ("event".to_owned(), event.as_str().to_owned()),
                ("exclude_pull_requests".to_owned(), "true".to_owned()),
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let request =
                self.metadata_request_with_fields(ApiMethod::Get, endpoint, fields, RUN_LIST_QUERY);
            let output = self.runner.execute(&request)?;
            let rows = parse_run_rows(&output, "run list")?;
            for candidate in &rows {
                if workflow_run_path_matches(&candidate.handle.workflow_path, workflow_path, branch)
                    && candidate.handle.head_sha == *head_sha
                    && candidate.handle.branch == *branch
                    && candidate.handle.event == event
                {
                    let mut candidate = candidate.clone();
                    workflow_path.clone_into(&mut candidate.handle.workflow_path);
                    match &matching {
                        None => matching = Some(candidate),
                        Some(previous) if *previous == candidate => {}
                        Some(_) => return Err(TransportError::AmbiguousRun),
                    }
                }
            }
            if rows.len() < usize::from(self.limits.per_page) {
                return matching
                    .map(|snapshot| snapshot.handle)
                    .ok_or(TransportError::RunNotFound);
            }
        }
        Err(TransportError::PaginationLimitReached { resource: "run" })
    }

    /// Find exactly one workflow-dispatch run whose public title binds all four inputs.
    ///
    /// # Errors
    ///
    /// Rejects malformed pages, missing or ambiguous exact matches, correlation drift, and
    /// incomplete pagination.
    pub fn find_workflow_dispatch_run(
        &mut self,
        request: &WorkflowDispatchRequest,
    ) -> Result<RunHandle, TransportError> {
        let mut matching: Option<RunSnapshot> = None;
        for page in 1..=self.limits.pages {
            let endpoint = request.repository.endpoint("/actions/runs");
            let fields = vec![
                (
                    "head_sha".to_owned(),
                    request.dispatch_revision.as_str().to_owned(),
                ),
                (
                    "branch".to_owned(),
                    request.temporary_ref.branch().as_str().to_owned(),
                ),
                (
                    "event".to_owned(),
                    RunEvent::WorkflowDispatch.as_str().to_owned(),
                ),
                ("exclude_pull_requests".to_owned(), "true".to_owned()),
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let api_request = self.metadata_request_with_fields(
                ApiMethod::Get,
                endpoint,
                fields,
                WORKFLOW_DISPATCH_RUN_LIST_QUERY,
            );
            let output = self.runner.execute(&api_request)?;
            let rows = parse_workflow_dispatch_run_rows(&output, "workflow dispatch run list")?;
            for candidate in &rows {
                let handle = candidate.snapshot.handle();
                if workflow_run_path_matches(
                    handle.workflow_path(),
                    request.workflow.path(),
                    request.temporary_ref.branch(),
                ) && handle.workflow_id() == request.workflow.id()
                    && handle.head_sha() == request.dispatch_revision()
                    && handle.branch() == request.temporary_ref.branch()
                    && handle.event() == RunEvent::WorkflowDispatch
                    && candidate.run_name == request.run_name
                {
                    let mut candidate = candidate.snapshot.clone();
                    request
                        .workflow
                        .path()
                        .clone_into(&mut candidate.handle.workflow_path);
                    match &matching {
                        None => matching = Some(candidate),
                        Some(previous) if *previous == candidate => {}
                        Some(_) => return Err(TransportError::AmbiguousRun),
                    }
                }
            }
            if rows.len() < usize::from(self.limits.per_page) {
                return matching
                    .map(|snapshot| snapshot.handle)
                    .ok_or(TransportError::RunNotFound);
            }
        }
        Err(TransportError::PaginationLimitReached { resource: "run" })
    }

    /// Fetch one run and re-check every immutable identity field locally.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata or any identity drift.
    pub fn run(
        &mut self,
        repository: &Repository,
        handle: &RunHandle,
    ) -> Result<RunSnapshot, TransportError> {
        let endpoint = repository.endpoint(&format!("/actions/runs/{}", handle.id.get()));
        let request = self.metadata_request(ApiMethod::Get, endpoint, RUN_QUERY);
        let output = self.runner.execute(&request)?;
        let mut rows = parse_run_rows(&output, "run")?;
        if rows.len() != 1 {
            return Err(TransportError::MalformedResponse { operation: "run" });
        }
        let mut snapshot = rows.remove(0);
        if workflow_run_path_matches(
            &snapshot.handle.workflow_path,
            &handle.workflow_path,
            &handle.branch,
        ) {
            snapshot
                .handle
                .workflow_path
                .clone_from(&handle.workflow_path);
        }
        if snapshot.handle != *handle {
            return Err(TransportError::RunIdentityMismatch);
        }
        Ok(snapshot)
    }

    /// Fetch the run ID returned directly by workflow dispatch and re-check
    /// workflow ID/path, dispatch commit, temporary branch, and event locally.
    ///
    /// # Errors
    ///
    /// Rejects malformed run metadata or any immutable identity mismatch.
    pub fn run_by_id(
        &mut self,
        receipt: &WorkflowDispatchReceipt,
    ) -> Result<RunSnapshot, TransportError> {
        let endpoint = receipt
            .repository
            .endpoint(&format!("/actions/runs/{}", receipt.run_id.get()));
        let request = self.metadata_request_at_version(
            ApiMethod::Get,
            endpoint,
            WORKFLOW_DISPATCH_RUN_QUERY,
            WORKFLOW_DISPATCH_API_VERSION_HEADER,
        );
        let output = self.runner.execute(&request)?;
        let mut rows = parse_workflow_dispatch_run_rows(&output, "workflow dispatch run")?;
        if rows.len() != 1 {
            return Err(TransportError::MalformedResponse {
                operation: "workflow dispatch run",
            });
        }
        let correlated = rows.remove(0);
        if correlated.run_name != receipt.run_name {
            return Err(TransportError::RunIdentityMismatch);
        }
        let mut snapshot = correlated.snapshot;
        if workflow_run_path_matches(
            &snapshot.handle.workflow_path,
            &receipt.workflow_path,
            &receipt.branch,
        ) {
            snapshot
                .handle
                .workflow_path
                .clone_from(&receipt.workflow_path);
        }
        let handle = snapshot.handle();
        if handle.id != receipt.run_id
            || handle.workflow_id != receipt.workflow_id
            || handle.workflow_path != receipt.workflow_path
            || handle.head_sha != receipt.dispatch_revision
            || handle.branch != receipt.branch
            || handle.event != RunEvent::WorkflowDispatch
        {
            return Err(TransportError::RunIdentityMismatch);
        }
        Ok(snapshot)
    }

    /// Poll a known run until completion using the standard thread sleeper.
    ///
    /// # Errors
    ///
    /// Returns when a request fails, identity changes, or the polling bound is
    /// exhausted.
    pub fn wait_for_run(
        &mut self,
        repository: &Repository,
        handle: &RunHandle,
        policy: PollPolicy,
    ) -> Result<RunSnapshot, TransportError> {
        self.wait_for_run_with(repository, handle, policy, &mut ThreadPollSleeper)
    }

    /// Poll with an injected sleeper for deterministic orchestration tests.
    ///
    /// # Errors
    ///
    /// Returns when a request fails, identity changes, or the polling bound is
    /// exhausted.
    pub fn wait_for_run_with(
        &mut self,
        repository: &Repository,
        handle: &RunHandle,
        policy: PollPolicy,
        sleeper: &mut impl PollSleeper,
    ) -> Result<RunSnapshot, TransportError> {
        for attempt in 0..policy.attempts {
            let snapshot = self.run(repository, handle)?;
            if snapshot.status.is_terminal() {
                return Ok(snapshot);
            }
            if attempt + 1 < policy.attempts {
                sleeper.sleep(policy.interval);
            }
        }
        Err(TransportError::PollLimitReached)
    }

    /// Request cancellation of one exact numeric run.
    ///
    /// # Errors
    ///
    /// Returns a redacted API failure. A successful REST acceptance does not
    /// imply the asynchronous cancellation has completed.
    pub fn cancel_run(
        &mut self,
        repository: &Repository,
        run_id: RunId,
    ) -> Result<(), TransportError> {
        let endpoint = repository.endpoint(&format!("/actions/runs/{}/cancel", run_id.get()));
        let request = self.silent_request(ApiMethod::Post, endpoint);
        self.runner.execute(&request)?;
        Ok(())
    }

    /// List all artifacts for one run within the pagination bound.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata and a full final page at the configured
    /// pagination limit.
    pub fn list_artifacts(
        &mut self,
        repository: &Repository,
        run_id: RunId,
    ) -> Result<Vec<ArtifactInfo>, TransportError> {
        let mut artifacts = Vec::new();
        for page in 1..=self.limits.pages {
            let endpoint =
                repository.endpoint(&format!("/actions/runs/{}/artifacts", run_id.get()));
            let fields = vec![
                ("per_page".to_owned(), self.limits.per_page.to_string()),
                ("page".to_owned(), page.to_string()),
            ];
            let request = self.metadata_request_with_fields(
                ApiMethod::Get,
                endpoint,
                fields,
                ARTIFACT_LIST_QUERY,
            );
            let output = self.runner.execute(&request)?;
            let page_artifacts = parse_artifacts(&output)?;
            let page_length = page_artifacts.len();
            for artifact in page_artifacts {
                if let Some(previous) = artifacts
                    .iter()
                    .find(|previous: &&ArtifactInfo| previous.id == artifact.id)
                {
                    if previous != &artifact {
                        return Err(TransportError::MalformedResponse {
                            operation: "artifact list",
                        });
                    }
                } else {
                    artifacts.push(artifact);
                }
            }
            if page_length < usize::from(self.limits.per_page) {
                return Ok(artifacts);
            }
        }
        Err(TransportError::PaginationLimitReached {
            resource: "artifact",
        })
    }

    /// Select exactly one non-expired artifact by exact name.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate, expired, malformed, or oversized artifacts.
    pub fn find_artifact(
        &mut self,
        repository: &Repository,
        run_id: RunId,
        expected_name: &ArtifactName,
    ) -> Result<ArtifactInfo, TransportError> {
        let mut matching = self
            .list_artifacts(repository, run_id)?
            .into_iter()
            .filter(|artifact| artifact.name == expected_name.as_str());
        let artifact = matching.next().ok_or(TransportError::ArtifactNotFound)?;
        if matching.next().is_some() {
            return Err(TransportError::AmbiguousArtifact);
        }
        if artifact.expired {
            return Err(TransportError::ArtifactExpired);
        }
        if artifact.size_bytes > self.limits.artifact_bytes {
            return Err(TransportError::ArtifactTooLarge);
        }
        Ok(artifact)
    }

    /// Download one exact artifact ZIP without extracting it.
    ///
    /// The destination is created with no-clobber semantics, a strict private
    /// DACL on Windows, and mode 0600 on Unix. Both API metadata and actual
    /// stdout are independently bounded.
    ///
    /// # Errors
    ///
    /// Rejects expired/oversized metadata, oversized output, non-ZIP bytes,
    /// an existing destination, and redacted filesystem failures.
    pub fn download_artifact_zip(
        &mut self,
        repository: &Repository,
        artifact: &ArtifactInfo,
        target: &ArtifactDownloadTarget,
    ) -> Result<DownloadedArtifact, TransportError> {
        if artifact.expired {
            return Err(TransportError::ArtifactExpired);
        }
        if artifact.size_bytes > self.limits.artifact_bytes {
            return Err(TransportError::ArtifactTooLarge);
        }
        let output_limit = usize::try_from(self.limits.artifact_bytes)
            .map_err(|_| TransportError::ArtifactTooLarge)?;
        let endpoint =
            repository.endpoint(&format!("/actions/artifacts/{}/zip", artifact.id.get()));
        let request = GhRequest {
            method: ApiMethod::Get,
            endpoint,
            fields: Vec::new(),
            jq: None,
            silent: false,
            output_limit,
            timeout: self.limits.download_timeout,
            api_version: API_VERSION,
        };
        let bytes = self.runner.execute(&request)?;
        if usize_to_u64(bytes.len()) > self.limits.artifact_bytes || !looks_like_zip(&bytes) {
            return Err(if usize_to_u64(bytes.len()) > self.limits.artifact_bytes {
                TransportError::ArtifactTooLarge
            } else {
                TransportError::InvalidArtifactZip
            });
        }
        if usize_to_u64(bytes.len()) != artifact.size_bytes {
            return Err(TransportError::ArtifactSizeMismatch);
        }
        if let Some(expected) = artifact.digest.as_deref() {
            let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            if actual != expected {
                return Err(TransportError::ArtifactDigestMismatch);
            }
        }
        write_new_artifact(target, &bytes)?;
        Ok(DownloadedArtifact {
            path: target.path(),
            bytes: usize_to_u64(bytes.len()),
        })
    }

    fn metadata_request(&self, method: ApiMethod, endpoint: String, jq: &'static str) -> GhRequest {
        self.metadata_request_with_fields(method, endpoint, Vec::new(), jq)
    }

    fn metadata_request_at_version(
        &self,
        method: ApiMethod,
        endpoint: String,
        jq: &'static str,
        api_version: &'static str,
    ) -> GhRequest {
        GhRequest {
            method,
            endpoint,
            fields: Vec::new(),
            jq: Some(jq),
            silent: false,
            output_limit: self.limits.api_response_bytes,
            timeout: self.limits.api_timeout,
            api_version,
        }
    }

    fn metadata_request_with_fields(
        &self,
        method: ApiMethod,
        endpoint: String,
        fields: Vec<(String, String)>,
        jq: &'static str,
    ) -> GhRequest {
        GhRequest {
            method,
            endpoint,
            fields,
            jq: Some(jq),
            silent: false,
            output_limit: self.limits.api_response_bytes,
            timeout: self.limits.api_timeout,
            api_version: API_VERSION,
        }
    }

    fn silent_request(&self, method: ApiMethod, endpoint: String) -> GhRequest {
        GhRequest {
            method,
            endpoint,
            fields: Vec::new(),
            jq: None,
            silent: true,
            output_limit: 1_024,
            timeout: self.limits.api_timeout,
            api_version: API_VERSION,
        }
    }
}

fn parse_repository(
    output: &[u8],
    expected: &Repository,
) -> Result<RepositoryInfo, TransportError> {
    let line = parse_single_utf8_line(output, "repository")?;
    let columns = split_columns(line, 6, "repository")?;
    let id = parse_nonzero_u64(columns[0], "repository")?;
    if !columns[1].eq_ignore_ascii_case(&expected.full_name()) {
        return Err(TransportError::RepositoryIdentityMismatch);
    }
    let private = parse_bool(columns[2], "repository")?;
    let archived = parse_bool(columns[3], "repository")?;
    let disabled = parse_bool(columns[4], "repository")?;
    let default_branch =
        BranchName::new(columns[5]).map_err(|_| TransportError::MalformedResponse {
            operation: "repository",
        })?;
    Ok(RepositoryInfo {
        id,
        full_name: columns[1].to_owned(),
        private,
        archived,
        disabled,
        default_branch,
    })
}

fn parse_actions_permissions(output: &[u8]) -> Result<ActionsPermissions, TransportError> {
    let operation = "GitHub Actions permissions";
    let line = parse_single_utf8_line(output, operation)?;
    Ok(ActionsPermissions {
        enabled: parse_bool(line, operation)?,
    })
}

fn parse_workflow_registration(
    output: &[u8],
    repository: &Repository,
    expected_path: &str,
) -> Result<WorkflowRegistration, TransportError> {
    let operation = "workflow registration";
    let line = parse_single_utf8_line(output, operation)?;
    let columns = split_columns(line, 3, operation)?;
    let id = WorkflowId::new(parse_nonzero_u64(columns[0], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let path = parse_base64_metadata_name(columns[1], operation, 4_096)?;
    if path != expected_path {
        return Err(TransportError::WorkflowIdentityMismatch);
    }
    if columns[2] != "active" {
        return Err(TransportError::WorkflowInactive);
    }
    Ok(WorkflowRegistration {
        repository: repository.clone(),
        id,
        path,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstallationRepository {
    id: u64,
    repository: Repository,
}

fn parse_installation_repositories(
    output: &[u8],
) -> Result<Vec<InstallationRepository>, TransportError> {
    let operation = "installation repository list";
    let text = parse_utf8(output, operation)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .map(|line| {
            let columns = split_columns(line, 2, operation)?;
            let id = parse_nonzero_u64(columns[0], operation)?;
            let full_name = parse_base64_metadata_name(columns[1], operation, 256)?;
            let (owner, name) = full_name
                .split_once('/')
                .ok_or(TransportError::MalformedResponse { operation })?;
            if name.contains('/') {
                return Err(TransportError::MalformedResponse { operation });
            }
            let repository = Repository::new(owner, name)
                .map_err(|_| TransportError::MalformedResponse { operation })?;
            Ok(InstallationRepository { id, repository })
        })
        .collect()
}

fn parse_environment(
    output: &[u8],
    expected: &ProtectedEnvironment,
) -> Result<EnvironmentInfo, TransportError> {
    let operation = "environment";
    let line = parse_single_utf8_line(output, operation)?;
    let columns = split_columns(line, 4, operation)?;
    let name = parse_base64_metadata_name(columns[0], operation, 64)?;
    if name != expected.as_str() {
        return Err(TransportError::EnvironmentIdentityMismatch);
    }
    Ok(EnvironmentInfo {
        name,
        protected_branches: parse_bool(columns[1], operation)?,
        custom_branch_policies: parse_bool(columns[2], operation)?,
        has_required_reviewers: parse_bool(columns[3], operation)?,
    })
}

fn parse_deployment_branch_policies(
    output: &[u8],
) -> Result<Vec<DeploymentBranchPolicy>, TransportError> {
    let operation = "deployment branch policy list";
    let text = parse_utf8(output, operation)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .map(|line| {
            let columns = split_columns(line, 2, operation)?;
            Ok(DeploymentBranchPolicy {
                id: parse_nonzero_u64(columns[0], operation)?,
                name: parse_base64_metadata_name(
                    columns[1],
                    operation,
                    MAX_DEPLOYMENT_POLICY_NAME_BYTES,
                )?,
            })
        })
        .collect()
}

fn parse_environment_secrets(output: &[u8]) -> Result<Vec<EnvironmentSecret>, TransportError> {
    let operation = "environment secret list";
    let text = parse_utf8(output, operation)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .map(|line| {
            let columns = split_columns(line, 1, operation)?;
            let name = parse_base64_metadata_name(columns[0], operation, 128)?;
            Ok(EnvironmentSecret {
                name: SecretName::new(name)
                    .map_err(|_| TransportError::MalformedResponse { operation })?,
            })
        })
        .collect()
}

fn parse_base64_metadata_name(
    value: &str,
    operation: &'static str,
    maximum: usize,
) -> Result<String, TransportError> {
    let bytes = decode_base64(value).ok_or(TransportError::MalformedResponse { operation })?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.iter().any(u8::is_ascii_control) {
        return Err(TransportError::MalformedResponse { operation });
    }
    let name =
        String::from_utf8(bytes).map_err(|_| TransportError::MalformedResponse { operation })?;
    if name.chars().any(char::is_control) {
        return Err(TransportError::MalformedResponse { operation });
    }
    Ok(name)
}

fn parse_run_rows(
    output: &[u8],
    operation: &'static str,
) -> Result<Vec<RunSnapshot>, TransportError> {
    let text = parse_utf8(output, operation)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .map(|line| parse_run_row(line, operation))
        .collect()
}

fn parse_workflow_dispatch_run_rows(
    output: &[u8],
    operation: &'static str,
) -> Result<Vec<WorkflowDispatchRunSnapshot>, TransportError> {
    let text = parse_utf8(output, operation)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .map(|line| {
            let columns = split_columns(line, 11, operation)?;
            let run_name = parse_base64_metadata_name(
                columns[10],
                operation,
                MAX_WORKFLOW_DISPATCH_RUN_NAME_BYTES,
            )?;
            let snapshot = parse_run_row(&columns[..10].join("\t"), operation)?;
            Ok(WorkflowDispatchRunSnapshot { snapshot, run_name })
        })
        .collect()
}

fn parse_run_row(line: &str, operation: &'static str) -> Result<RunSnapshot, TransportError> {
    let columns = split_columns(line, 10, operation)?;
    let id = RunId::new(parse_nonzero_u64(columns[0], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let workflow_id = WorkflowId::new(parse_nonzero_u64(columns[1], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let workflow_path = parse_base64_metadata_name(columns[2], operation, 4_096)?;
    let run_number = parse_nonzero_u64(columns[3], operation)?;
    let run_attempt = parse_nonzero_u64(columns[4], operation)?;
    let head_sha =
        CommitSha::new(columns[5]).map_err(|_| TransportError::MalformedResponse { operation })?;
    let branch_bytes =
        decode_base64(columns[6]).ok_or(TransportError::MalformedResponse { operation })?;
    let branch_text = String::from_utf8(branch_bytes)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let branch = BranchName::new(branch_text)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let event =
        RunEvent::parse(columns[7]).ok_or(TransportError::MalformedResponse { operation })?;
    let status =
        RunStatus::parse(columns[8]).ok_or(TransportError::MalformedResponse { operation })?;
    let conclusion = if columns[9].is_empty() {
        None
    } else {
        Some(
            RunConclusion::parse(columns[9])
                .ok_or(TransportError::MalformedResponse { operation })?,
        )
    };
    if status.is_terminal() != conclusion.is_some() {
        return Err(TransportError::MalformedResponse { operation });
    }
    Ok(RunSnapshot {
        handle: RunHandle {
            id,
            workflow_id,
            workflow_path,
            head_sha,
            branch,
            event,
        },
        run_number,
        run_attempt,
        status,
        conclusion,
    })
}

fn workflow_run_path_matches(value: &str, expected_path: &str, branch: &BranchName) -> bool {
    value == expected_path
        || value
            .strip_prefix(expected_path)
            .and_then(|suffix| suffix.strip_prefix('@'))
            == Some(branch.as_str())
}

fn parse_artifacts(output: &[u8]) -> Result<Vec<ArtifactInfo>, TransportError> {
    let text = parse_utf8(output, "artifact list")?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines().map(parse_artifact_row).collect()
}

fn parse_artifact_row(line: &str) -> Result<ArtifactInfo, TransportError> {
    let operation = "artifact list";
    let columns = split_columns(line, 5, operation)?;
    let id = ArtifactId::new(parse_nonzero_u64(columns[0], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let name_bytes =
        decode_base64(columns[1]).ok_or(TransportError::MalformedResponse { operation })?;
    if name_bytes.is_empty()
        || name_bytes.len() > 256
        || name_bytes
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b'/')
    {
        return Err(TransportError::MalformedResponse { operation });
    }
    let name = String::from_utf8(name_bytes)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let size_bytes = columns[2]
        .parse::<u64>()
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let expired = parse_bool(columns[3], operation)?;
    let digest = parse_artifact_digest(columns[4])?;
    Ok(ArtifactInfo {
        id,
        name,
        size_bytes,
        expired,
        digest,
    })
}

fn parse_artifact_digest(value: &str) -> Result<Option<String>, TransportError> {
    if value.is_empty() {
        return Ok(None);
    }
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(TransportError::MalformedResponse {
            operation: "artifact list",
        });
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(TransportError::MalformedResponse {
            operation: "artifact list",
        });
    }
    Ok(Some(value.to_owned()))
}

fn parse_single_utf8_line<'a>(
    output: &'a [u8],
    operation: &'static str,
) -> Result<&'a str, TransportError> {
    let text = parse_utf8(output, operation)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains('\n') || text.contains('\r') {
        return Err(TransportError::MalformedResponse { operation });
    }
    Ok(text)
}

fn parse_utf8<'a>(output: &'a [u8], operation: &'static str) -> Result<&'a str, TransportError> {
    std::str::from_utf8(output).map_err(|_| TransportError::MalformedResponse { operation })
}

fn split_columns<'a>(
    line: &'a str,
    count: usize,
    operation: &'static str,
) -> Result<Vec<&'a str>, TransportError> {
    let columns = line.split('\t').collect::<Vec<_>>();
    if columns.len() != count
        || columns
            .iter()
            .any(|column| column.contains('\r') || column.contains('\n'))
    {
        return Err(TransportError::MalformedResponse { operation });
    }
    Ok(columns)
}

fn parse_nonzero_u64(value: &str, operation: &'static str) -> Result<u64, TransportError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    if parsed == 0 {
        return Err(TransportError::MalformedResponse { operation });
    }
    Ok(parsed)
}

fn parse_bool(value: &str, operation: &'static str) -> Result<bool, TransportError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(TransportError::MalformedResponse { operation }),
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(4) || value.bytes().any(|byte| !is_base64_byte(byte)) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    let chunks = value.as_bytes().chunks_exact(4);
    for (index, chunk) in chunks.enumerate() {
        let final_chunk = (index + 1) * 4 == value.len();
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third_padding = chunk[2] == b'=';
        let fourth_padding = chunk[3] == b'=';
        if third_padding && !fourth_padding {
            return None;
        }
        if (third_padding || fourth_padding) && !final_chunk {
            return None;
        }
        let third = if third_padding {
            0
        } else {
            base64_value(chunk[2])?
        };
        let fourth = if fourth_padding {
            0
        } else {
            base64_value(chunk[3])?
        };
        if (third_padding && second & 0x0f != 0)
            || (fourth_padding && !third_padding && third & 0x03 != 0)
        {
            return None;
        }
        output.push(first << 2 | second >> 4);
        if !third_padding {
            output.push(second << 4 | third >> 2);
        }
        if !fourth_padding {
            output.push(third << 6 | fourth);
        }
    }
    Some(output)
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    if bytes.len() < ZIP_END_RECORD_MINIMUM_BYTES
        || !(bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06"))
    {
        return false;
    }
    let search_start = bytes.len().saturating_sub(ZIP_END_RECORD_SEARCH_BYTES);
    bytes[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .is_some()
}

#[cfg(windows)]
fn write_new_artifact(target: &ArtifactDownloadTarget, bytes: &[u8]) -> Result<(), TransportError> {
    let path = target.path();
    let mut file = create_windows_private_file(&path)
        .map_err(|error| map_windows_artifact_create_error(&error))?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        remove_failed_windows_artifact(file)?;
        return Err(TransportError::ArtifactWriteFailed);
    }
    if verify_windows_private_file_handle(file.as_handle()).is_err() {
        remove_failed_windows_artifact(file)?;
        return Err(TransportError::ArtifactWriteFailed);
    }
    Ok(())
}

#[cfg(windows)]
fn map_windows_artifact_create_error(error: &PrivateDirectoryError) -> TransportError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        TransportError::ArtifactCleanupUncertain
    } else if error.kind() == PrivateDirectoryErrorKind::AlreadyExists {
        TransportError::DestinationExists
    } else {
        TransportError::ArtifactWriteFailed
    }
}

#[cfg(windows)]
fn remove_failed_windows_artifact(file: fs::File) -> Result<(), TransportError> {
    remove_windows_private_file_handle(file).map_err(|_| TransportError::ArtifactCleanupUncertain)
}

#[cfg(not(windows))]
fn write_new_artifact(target: &ArtifactDownloadTarget, bytes: &[u8]) -> Result<(), TransportError> {
    let path = target.path();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            TransportError::DestinationExists
        } else {
            TransportError::ArtifactWriteFailed
        }
    })?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        if fs::remove_file(&path).is_err() && path.exists() {
            return Err(TransportError::ArtifactWriteFailed);
        }
        return Err(TransportError::ArtifactWriteFailed);
    }
    Ok(())
}

fn run_process(
    command: Command,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Vec<u8>, GhExecutionError> {
    run_process_inner(
        command,
        timeout,
        stdout_limit,
        None,
        true,
        PROCESS_POLL_INTERVAL,
    )
}

fn run_process_with_secret_input(
    command: Command,
    timeout: Duration,
    stdout_limit: usize,
    input: &SecretBytes,
) -> Result<(), GhExecutionError> {
    run_process_inner(
        command,
        timeout,
        stdout_limit,
        Some(input),
        false,
        PROCESS_POLL_INTERVAL,
    )
    .map(drop)
}

fn run_process_inner(
    mut command: Command,
    timeout: Duration,
    stdout_limit: usize,
    input: Option<&SecretBytes>,
    retain_stdout: bool,
    poll_interval: Duration,
) -> Result<Vec<u8>, GhExecutionError> {
    let mut child = command.spawn().map_err(|_| GhExecutionError::SpawnFailed)?;
    let mut process_tree = ProcessTreeGuard::attach(&child).inspect_err(|_| {
        terminate_child(&mut child, process_cleanup_deadline());
    })?;
    let Some(stdout) = child.stdout.take() else {
        let cleanup_deadline = process_cleanup_deadline();
        terminate_process_tree(&mut child, &mut process_tree, cleanup_deadline);
        return Err(GhExecutionError::ProcessIo);
    };
    let Some(stderr) = child.stderr.take() else {
        let cleanup_deadline = process_cleanup_deadline();
        terminate_process_tree(&mut child, &mut process_tree, cleanup_deadline);
        return Err(GhExecutionError::ProcessIo);
    };
    let stdin_writer = if let Some(input) = input {
        let Some(mut stdin) = child.stdin.take() else {
            let cleanup_deadline = process_cleanup_deadline();
            terminate_process_tree(&mut child, &mut process_tree, cleanup_deadline);
            return Err(GhExecutionError::ProcessIo);
        };
        // A bounded zeroizing copy lets timeout handling kill `gh` even if its
        // stdin reader stalls while the writer thread is active.
        let input = SecretBytes::new(input.expose_secret_bytes().to_vec());
        Some(spawn_process_worker(move || {
            stdin
                .write_all(input.expose_secret_bytes())
                .map_err(|_| GhExecutionError::ProcessIo)
        }))
    } else {
        None
    };
    let stdout_reader =
        spawn_process_worker(move || read_capped(stdout, stdout_limit, retain_stdout));
    let stderr_reader = spawn_process_worker(move || read_capped(stderr, MAX_STDERR_BYTES, false));
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        terminate_and_discard_process_output(
            &mut child,
            &mut process_tree,
            stdin_writer.as_ref(),
            &stdout_reader,
            &stderr_reader,
        );
        return Err(GhExecutionError::TimedOut);
    };

    let status = match wait_for_process_exit(&mut child, deadline, poll_interval) {
        Ok(status) => status,
        Err(error) => {
            terminate_and_discard_process_output(
                &mut child,
                &mut process_tree,
                stdin_writer.as_ref(),
                &stdout_reader,
                &stderr_reader,
            );
            return Err(error);
        }
    };
    // `gh` has exited, but a descendant may still hold one of its inherited
    // pipes open. End the complete supervised tree before collecting output.
    process_tree.terminate_descendants();
    if Instant::now() >= deadline {
        terminate_and_discard_process_output(
            &mut child,
            &mut process_tree,
            stdin_writer.as_ref(),
            &stdout_reader,
            &stderr_reader,
        );
        return Err(GhExecutionError::TimedOut);
    }
    let output = collect_process_workers(
        stdin_writer.as_ref(),
        &stdout_reader,
        &stderr_reader,
        deadline,
    );
    if Instant::now() >= deadline {
        drop(output);
        return Err(GhExecutionError::TimedOut);
    }
    let (mut stdout, stderr) = output?;
    if !status.success() {
        return Err(command_failed(status));
    }
    if stdout.truncated || stderr.truncated {
        return Err(GhExecutionError::OutputLimitExceeded);
    }
    if Instant::now() >= deadline {
        return Err(GhExecutionError::TimedOut);
    }
    Ok(std::mem::take(&mut stdout.bytes))
}

fn wait_for_process_exit(
    child: &mut Child,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<ExitStatus, GhExecutionError> {
    debug_assert!(!poll_interval.is_zero());
    loop {
        if Instant::now() >= deadline {
            return Err(GhExecutionError::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) if Instant::now() < deadline => return Ok(status),
            Ok(Some(_)) => return Err(GhExecutionError::TimedOut),
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    thread::sleep(remaining.min(poll_interval));
                }
            }
            Err(_) => return Err(GhExecutionError::ProcessIo),
        }
    }
}

fn terminate_and_discard_process_output(
    child: &mut Child,
    process_tree: &mut ProcessTreeGuard,
    stdin_writer: Option<&Receiver<Result<(), GhExecutionError>>>,
    stdout_reader: &Receiver<Result<CapturedOutput, GhExecutionError>>,
    stderr_reader: &Receiver<Result<CapturedOutput, GhExecutionError>>,
) {
    // The fresh grace is teardown-only; its output can never determine success.
    let cleanup_deadline = process_cleanup_deadline();
    terminate_process_tree(child, process_tree, cleanup_deadline);
    let _ = collect_process_workers(stdin_writer, stdout_reader, stderr_reader, cleanup_deadline);
}

fn spawn_process_worker<T>(
    worker: impl FnOnce() -> Result<T, GhExecutionError> + Send + 'static,
) -> Receiver<Result<T, GhExecutionError>>
where
    T: Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    // Completion is observed through the bounded receiver; the detached handle
    // must never turn a process timeout into an unbounded thread join.
    drop(thread::spawn(move || {
        let _ = sender.send(worker());
    }));
    receiver
}

fn collect_process_workers(
    stdin_writer: Option<&Receiver<Result<(), GhExecutionError>>>,
    stdout_reader: &Receiver<Result<CapturedOutput, GhExecutionError>>,
    stderr_reader: &Receiver<Result<CapturedOutput, GhExecutionError>>,
    deadline: Instant,
) -> Result<(CapturedOutput, CapturedOutput), GhExecutionError> {
    if let Some(stdin_writer) = stdin_writer {
        receive_process_worker(stdin_writer, deadline)?;
    }
    let stdout = receive_process_worker(stdout_reader, deadline)?;
    let stderr = receive_process_worker(stderr_reader, deadline)?;
    Ok((stdout, stderr))
}

fn receive_process_worker<T>(
    receiver: &Receiver<Result<T, GhExecutionError>>,
    deadline: Instant,
) -> Result<T, GhExecutionError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
            Err(GhExecutionError::ProcessIo)
        }
    }
}

fn process_cleanup_deadline() -> Instant {
    Instant::now()
        .checked_add(PROCESS_CLEANUP_GRACE)
        .unwrap_or_else(Instant::now)
}

#[cfg(unix)]
fn configure_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_tree(_command: &mut Command) {}

struct ProcessTreeGuard {
    #[cfg(unix)]
    process_group: Option<u32>,
    platform_guard: Option<rustferry_core::process_control::ProcessGroupGuard>,
}

impl ProcessTreeGuard {
    fn attach(child: &Child) -> Result<Self, GhExecutionError> {
        let platform_guard = Some(
            rustferry_core::process_control::track_child(child)
                .map_err(|_| GhExecutionError::ProcessIo)?,
        );
        Ok(Self {
            #[cfg(unix)]
            process_group: Some(child.id()),
            platform_guard,
        })
    }

    fn terminate_descendants(&mut self) {
        #[cfg(unix)]
        if let Some(process_group) = self.process_group.take() {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{process_group}")])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        drop(self.platform_guard.take());
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        self.terminate_descendants();
    }
}

fn terminate_process_tree(
    child: &mut Child,
    process_tree: &mut ProcessTreeGuard,
    deadline: Instant,
) {
    process_tree.terminate_descendants();
    terminate_child(child, deadline);
}

fn terminate_child(child: &mut Child, deadline: Instant) {
    let _ = child.kill();
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                thread::sleep(remaining.min(Duration::from_millis(20)));
            }
        }
    }
}

fn command_failed(status: ExitStatus) -> GhExecutionError {
    GhExecutionError::CommandFailed {
        exit_code: status.code(),
    }
}

struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

impl Drop for CapturedOutput {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

fn read_capped(
    mut reader: impl Read,
    limit: usize,
    retain: bool,
) -> Result<CapturedOutput, GhExecutionError> {
    let mut bytes = if retain {
        Vec::with_capacity(limit.min(64 * 1024))
    } else {
        Vec::new()
    };
    let mut total = 0_usize;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| GhExecutionError::ProcessIo)?;
        if read == 0 {
            break;
        }
        let retained = limit.saturating_sub(total).min(read);
        if retain && retained > 0 {
            bytes.extend_from_slice(&buffer[..retained]);
        }
        total = total.saturating_add(read);
    }
    Ok(CapturedOutput {
        bytes,
        truncated: total > limit,
    })
}

fn canonical_file(path: &Path, field: &'static str) -> Result<PathBuf, TransportConfigError> {
    if !is_absolute_normal_path(path) {
        return Err(TransportConfigError::InvalidLocalPath { field });
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| TransportConfigError::InvalidLocalPath { field })?;
    if metadata.file_type().is_symlink() {
        let canonical =
            fs::canonicalize(path).map_err(|_| TransportConfigError::InvalidLocalPath { field })?;
        if !canonical.is_file() {
            return Err(TransportConfigError::InvalidLocalPath { field });
        }
        return Ok(canonical);
    }
    if !metadata.is_file() {
        return Err(TransportConfigError::InvalidLocalPath { field });
    }
    fs::canonicalize(path).map_err(|_| TransportConfigError::InvalidLocalPath { field })
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

fn canonical_directory(path: &Path, field: &'static str) -> Result<PathBuf, TransportConfigError> {
    if !is_absolute_normal_path(path) {
        return Err(TransportConfigError::InvalidLocalPath { field });
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| TransportConfigError::InvalidLocalPath { field })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TransportConfigError::InvalidLocalPath { field });
    }
    fs::canonicalize(path).map_err(|_| TransportConfigError::InvalidLocalPath { field })
}

fn is_absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn validate_owner(value: &str) -> Result<(), TransportConfigError> {
    validate_nonempty_length("repository owner", value, 39)?;
    validate_ascii_allowlist("repository owner", value, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'-'
    })?;
    if !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        || value.contains("--")
    {
        return Err(TransportConfigError::InvalidFormat {
            field: "repository owner",
        });
    }
    Ok(())
}

fn validate_repository_name(value: &str) -> Result<(), TransportConfigError> {
    validate_nonempty_length("repository name", value, 100)?;
    validate_ascii_allowlist("repository name", value, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
    })?;
    if value.starts_with('-')
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || value.contains("..")
    {
        return Err(TransportConfigError::InvalidFormat {
            field: "repository name",
        });
    }
    Ok(())
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_workflow_dispatch_operation(value: &str) -> Result<(), TransportConfigError> {
    validate_nonempty_length("workflow dispatch operation", value, 64)?;
    validate_ascii_allowlist("workflow dispatch operation", value, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
    })?;
    if value.starts_with('.')
        || value.ends_with('.')
        || value.ends_with(".lock")
        || value.contains("..")
    {
        return Err(TransportConfigError::InvalidFormat {
            field: "workflow dispatch operation",
        });
    }
    Ok(())
}

fn validate_lower_sha256(field: &'static str, value: &str) -> Result<(), TransportConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(TransportConfigError::InvalidFormat { field });
    }
    Ok(())
}

fn valid_workflow_dispatch_receipt_url(
    value: &str,
    origin: &str,
    repository: &Repository,
    run_id: RunId,
) -> bool {
    let expected = format!(
        "{origin}{}/{}/actions/runs/{}",
        repository.owner(),
        repository.name(),
        run_id.get()
    );
    !value.is_empty()
        && value.len() <= 2_048
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.eq_ignore_ascii_case(&expected)
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validated_workflow_filename(workflow_path: &str) -> Result<&str, TransportError> {
    let filename = workflow_path
        .strip_prefix(".github/workflows/")
        .ok_or(TransportError::InvalidWorkflowPath)?;
    if filename.is_empty()
        || filename.len() > 128
        || !filename.as_bytes()[0].is_ascii_alphanumeric()
        || filename.contains("..")
        || !(filename.ends_with(".yml") || filename.ends_with(".yaml"))
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(TransportError::InvalidWorkflowPath);
    }
    Ok(filename)
}

fn validate_nonempty_length(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), TransportConfigError> {
    if value.is_empty() {
        return Err(TransportConfigError::Empty { field });
    }
    if value.len() > maximum {
        return Err(TransportConfigError::TooLong { field, maximum });
    }
    Ok(())
}

fn validate_ascii_allowlist(
    field: &'static str,
    value: &str,
    allowed: impl Fn(u8) -> bool,
) -> Result<(), TransportConfigError> {
    if let Some((index, _)) = value.bytes().enumerate().find(|(_, byte)| !allowed(*byte)) {
        return Err(TransportConfigError::InvalidCharacter { field, index });
    }
    Ok(())
}

fn validate_range(
    field: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), TransportConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(TransportConfigError::OutOfRange {
            field,
            minimum,
            maximum,
        });
    }
    Ok(())
}

fn validate_duration(
    field: &'static str,
    value: Duration,
    minimum_seconds: u64,
    maximum_seconds: u64,
) -> Result<(), TransportConfigError> {
    if value.subsec_nanos() != 0 {
        return Err(TransportConfigError::InvalidFormat { field });
    }
    validate_range(field, value.as_secs(), minimum_seconds, maximum_seconds)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "secure-job-log-http")]
    use std::io::Cursor;
    #[cfg(windows)]
    use std::os::windows::io::AsHandle as _;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const BRANCH_B64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy9qb2ItMQ==";
    const WORKFLOW_PATH: &str = ".github/workflows/rustferry-goal3-iphone.yml";
    const WORKFLOW_PATH_B64: &str = "LmdpdGh1Yi93b3JrZmxvd3MvcnVzdGZlcnJ5LWdvYWwzLWlwaG9uZS55bWw=";
    const WORKFLOW_DISPATCH_RUN_PATH_B64: &str = "LmdpdGh1Yi93b3JrZmxvd3MvcnVzdGZlcnJ5LWdvYWwzLWlwaG9uZS55bWxAcnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy9qb2ItMQ==";
    const ENVIRONMENT_B64: &str = "cnVzdGZlcnJ5LWdvYWwzLXNpZ25pbmc=";
    const DEPLOYMENT_POLICY_B64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy8q";
    const CERTIFICATE_P12_B64: &str = "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QMTI=";
    const CERTIFICATE_PASSWORD_B64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QQVNTV09SRA==";
    const PROVISIONING_PROFILE_B64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19QUk9WSVNJT05JTkdfUFJPRklMRQ==";

    fn base64_fixture(value: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
        for chunk in value.as_bytes().chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
            encoded.push(char::from(
                ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)],
            ));
            encoded.push(if chunk.len() > 1 {
                char::from(ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)])
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                char::from(ALPHABET[usize::from(third & 0x3f)])
            } else {
                '='
            });
        }
        encoded
    }

    #[cfg(target_os = "linux")]
    fn process_is_zombie(process_id: u32) -> bool {
        fs::read_to_string(format!("/proc/{process_id}/status"))
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.strip_prefix("State:")
                    .is_some_and(|state| state.trim_start().starts_with('Z'))
            })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    const fn process_is_zombie(_: u32) -> bool {
        false
    }

    #[cfg(unix)]
    fn assert_process_exits(process_id: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let live = Command::new("/bin/kill")
                .args(["-0", &process_id.to_string()])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe fake gh descendant")
                .success();
            if !live || process_is_zombie(process_id) {
                return;
            }
            if Instant::now() >= deadline {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &process_id.to_string()])
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                panic!("fake gh descendant {process_id} remained live");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[derive(Debug, Default)]
    struct FakeRunner {
        responses: VecDeque<Result<Vec<u8>, GhExecutionError>>,
        requests: Vec<GhRequest>,
        secret_responses: VecDeque<Result<(), GhExecutionError>>,
        secret_writes: Vec<RecordedSecretWrite>,
    }

    #[derive(Debug, Default)]
    struct FakeWorkflowDispatchHttpClient {
        responses:
            VecDeque<Result<GithubWorkflowDispatchHttpResponse, GithubWorkflowDispatchHttpError>>,
        requests: Vec<GithubWorkflowDispatchHttpRequest>,
    }

    impl FakeWorkflowDispatchHttpClient {
        fn with(
            responses: impl IntoIterator<
                Item = Result<GithubWorkflowDispatchHttpResponse, GithubWorkflowDispatchHttpError>,
            >,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }
        }
    }

    impl GithubWorkflowDispatchHttpClient for FakeWorkflowDispatchHttpClient {
        fn post(
            &mut self,
            request: &GithubWorkflowDispatchHttpRequest,
        ) -> Result<GithubWorkflowDispatchHttpResponse, GithubWorkflowDispatchHttpError> {
            self.requests.push(request.clone());
            self.responses.pop_front().expect("unexpected dispatch")
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RecordedSecretWrite {
        request: EnvironmentSecretWriteRequest,
        stdin_bytes: usize,
        stdin_sha256: String,
    }

    impl FakeRunner {
        fn with(responses: impl IntoIterator<Item = Result<Vec<u8>, GhExecutionError>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
                ..Self::default()
            }
        }

        fn with_secret(responses: impl IntoIterator<Item = Result<(), GhExecutionError>>) -> Self {
            Self {
                secret_responses: responses.into_iter().collect(),
                ..Self::default()
            }
        }
    }

    impl GhRunner for FakeRunner {
        fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
            self.requests.push(request.clone());
            self.responses.pop_front().expect("unexpected request")
        }
    }

    impl GhSecretRunner for FakeRunner {
        fn set_environment_secret(
            &mut self,
            request: &EnvironmentSecretWriteRequest,
            value: &SecretBytes,
            _timeout: Duration,
        ) -> Result<(), GhExecutionError> {
            self.secret_writes.push(RecordedSecretWrite {
                request: request.clone(),
                stdin_bytes: value.len(),
                stdin_sha256: hex::encode(Sha256::digest(value.expose_secret_bytes())),
            });
            self.secret_responses
                .pop_front()
                .expect("unexpected secret write")
        }
    }

    #[derive(Debug, Default)]
    struct FakeSleeper(Vec<Duration>);

    impl PollSleeper for FakeSleeper {
        fn sleep(&mut self, duration: Duration) {
            self.0.push(duration);
        }
    }

    fn repository() -> Repository {
        Repository::new("ShiroKSH", "rustferry").expect("repository")
    }

    fn environment() -> ProtectedEnvironment {
        ProtectedEnvironment::new("rustferry-goal3-signing").expect("environment")
    }

    fn workflow_registration() -> WorkflowRegistration {
        WorkflowRegistration {
            repository: repository(),
            id: WorkflowId::new(42).expect("workflow id"),
            path: WORKFLOW_PATH.to_owned(),
        }
    }

    fn workflow_dispatch_request() -> WorkflowDispatchRequest {
        let namespace = TemporaryBranchNamespace::new("rustferry/goal3/builds").expect("namespace");
        let temporary_ref = TemporaryGitRef::new(
            &namespace,
            BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
        )
        .expect("temporary ref");
        WorkflowDispatchRequest::new(
            repository(),
            workflow_registration(),
            temporary_ref,
            "job-1",
            "f".repeat(64),
            CommitSha::new(SHA).expect("source revision"),
            CommitSha::new("fedcba9876543210fedcba9876543210fedcba98").expect("dispatch revision"),
        )
        .expect("workflow dispatch request")
    }

    fn workflow_dispatch_receipt_body(run_id: u64) -> Vec<u8> {
        format!(
            "{{\"workflow_run_id\":{run_id},\"run_url\":\"https://api.github.com/repos/ShiroKSH/rustferry/actions/runs/{run_id}\",\"html_url\":\"https://github.com/ShiroKSH/rustferry/actions/runs/{run_id}\"}}"
        )
        .into_bytes()
    }

    fn environment_secret_write_request() -> EnvironmentSecretWriteRequest {
        EnvironmentSecretWriteRequest::new(
            repository(),
            environment(),
            SecretName::new("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD").expect("secret name"),
        )
    }

    fn limits(pages: u16, per_page: u8) -> TransportLimits {
        TransportLimits::new(
            pages,
            per_page,
            4 * 1024,
            4 * 1024 * 1024,
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
        .expect("limits")
    }

    fn run_row(id: u64, status: &str, conclusion: &str) -> Vec<u8> {
        format!(
            "{id}\t17\t{WORKFLOW_PATH_B64}\t9\t1\t{SHA}\t{BRANCH_B64}\tpush\t{status}\t{conclusion}\n"
        )
        .into_bytes()
    }

    fn handle() -> RunHandle {
        RunHandle {
            id: RunId::new(41).expect("run id"),
            workflow_id: WorkflowId::new(17).expect("workflow id"),
            workflow_path: WORKFLOW_PATH.to_owned(),
            head_sha: CommitSha::new(SHA).expect("sha"),
            branch: BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
            event: RunEvent::Push,
        }
    }

    #[test]
    fn identifiers_reject_option_path_and_expression_syntax() {
        for owner in ["", "-owner", "owner-", "owner/name", "${{x}}", "a--b"] {
            assert!(
                Repository::new(owner, "repo").is_err(),
                "accepted {owner:?}"
            );
        }
        for name in ["", "-repo", "repo/child", "repo..child", "repo.", "${{x}}"] {
            assert!(Repository::new("owner", name).is_err(), "accepted {name:?}");
        }
        for branch in [
            "refs/heads/main",
            "../main",
            "job//one",
            "job.lock",
            "job~one",
            "-job",
            "${{x}}",
        ] {
            assert!(BranchName::new(branch).is_err(), "accepted {branch:?}");
        }
        assert!(CommitSha::new(SHA).is_ok());
        assert!(CommitSha::new(SHA.to_uppercase()).is_err());
        assert!(RunId::new(0).is_err());
        assert!(ArtifactName::new("rustferry-signed-42-1").is_ok());
        assert!(ArtifactName::new("../artifact").is_err());
    }

    #[test]
    fn gh_executable_basename_is_platform_exact() {
        #[cfg(windows)]
        assert!(executable_basename_matches(
            Path::new(r"C:\GitHub\gh.exe"),
            "gh"
        ));
        #[cfg(not(windows))]
        assert!(executable_basename_matches(Path::new("/usr/bin/gh"), "gh"));
        assert!(!executable_basename_matches(
            Path::new("/usr/bin/not-gh"),
            "gh"
        ));
    }

    #[test]
    fn private_gh_state_is_canonical_and_outside_the_project() {
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let neutral_path = fs::canonicalize(neutral.path()).expect("canonical neutral directory");
        let state = create_private_gh_state(&neutral_path).expect("private gh state");
        assert!(state.root.is_absolute());
        assert!(!state.root.starts_with(neutral_path));
        let metadata = fs::symlink_metadata(&state.root).expect("private state metadata");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
    }

    #[test]
    fn private_gh_state_rejects_project_local_roots() {
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let project_local_state =
            tempfile::TempDir::new_in(neutral.path()).expect("project-local state directory");
        assert!(matches!(
            validate_private_gh_state_root(project_local_state.path(), neutral.path()),
            Err(TransportConfigError::InvalidLocalPath {
                field: "private gh state directory"
            })
        ));
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_agent_is_direct_https_no_redirect_and_trace_suppressed() {
        let client = UreqGithubJobLogHttpClient::new(SecretBytes::new(b"test-token".to_vec()))
            .expect("job-log client");
        let config = client.agent.config();

        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.max_redirects_will_error());
        assert_eq!(
            config.redirect_auth_headers(),
            ureq::config::RedirectAuthHeaders::Never
        );
        assert!(!config.save_redirect_history());
        assert_eq!(
            config.max_response_header_size(),
            MAX_JOB_LOG_RESPONSE_HEADER_BYTES
        );
        assert_eq!(
            config.tls_config().provider(),
            ureq::tls::TlsProvider::Rustls
        );
        let timeouts = config.timeouts();
        assert_eq!(timeouts.global, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        assert_eq!(timeouts.resolve, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        assert_eq!(timeouts.connect, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        assert_eq!(timeouts.send_request, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        assert_eq!(timeouts.recv_response, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        assert_eq!(timeouts.recv_body, Some(MAX_JOB_LOG_HTTP_TIMEOUT));
        // ureq reveals paths, queries, and Location at TRACE. The facade cap is
        // therefore a signed-redirect confidentiality boundary, not a tuning knob.
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_request_attaches_auth_only_to_the_fixed_api_origin() {
        const TOKEN: &str = "fake-job-log-token-sentinel";
        let client = UreqGithubJobLogHttpClient::new(SecretBytes::new(TOKEN.as_bytes().to_vec()))
            .expect("job-log client");
        let api = client
            .prepare_get(
                "/repos/ShiroKSH/rustferry/actions/jobs/42/logs",
                true,
                GithubJobLogAuthorization::GithubApi,
                GithubJobLogAccept::Json,
                Duration::from_secs(5),
            )
            .expect("API request");
        let api_headers = api.headers_ref().expect("API headers");
        let authorization = api_headers.get("authorization").expect("API authorization");
        assert_eq!(
            authorization.as_bytes(),
            format!("Bearer {TOKEN}").as_bytes()
        );
        assert!(authorization.is_sensitive());
        assert_eq!(
            api_headers
                .get("x-github-api-version")
                .expect("API version"),
            JOB_LOG_API_VERSION
        );
        assert_eq!(JOB_LOG_API_VERSION, "2026-03-10");
        assert_eq!(
            api.uri_ref().expect("API URI").to_string(),
            "https://api.github.com/repos/ShiroKSH/rustferry/actions/jobs/42/logs"
        );

        let redirect = client
            .prepare_get(
                "https://pipelines.actions.githubusercontent.com/results/log.txt?signed=secret",
                false,
                GithubJobLogAuthorization::Omit,
                GithubJobLogAccept::PlainText,
                Duration::from_secs(5),
            )
            .expect("signed redirect request");
        let redirect_headers = redirect.headers_ref().expect("redirect headers");
        assert!(redirect_headers.get("authorization").is_none());
        assert!(redirect_headers.get("proxy-authorization").is_none());
        assert!(redirect_headers.get("x-github-api-version").is_none());
        assert!(redirect_headers.get("cookie").is_none());
        assert_eq!(
            redirect_headers.get("accept").expect("plain-text accept"),
            JOB_LOG_PLAINTEXT_ACCEPT
        );
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn workflow_dispatch_http_request_uses_fixed_origin_headers_and_no_redirects() {
        const TOKEN: &str = "fake-dispatch-token-sentinel";
        let client = UreqGithubApiHttpClient::new(SecretBytes::new(TOKEN.as_bytes().to_vec()))
            .expect("GitHub API client");
        let request = workflow_dispatch_request();
        let http_request = GithubWorkflowDispatchHttpRequest {
            endpoint: request.repository.endpoint(&format!(
                "/actions/workflows/{}/dispatches",
                request.workflow.id.get()
            )),
            body: request.body.clone(),
            timeout: Duration::from_secs(5),
        };
        let planned = client
            .prepare_workflow_dispatch_post(&http_request)
            .expect("dispatch request");
        let headers = planned.headers_ref().expect("dispatch headers");
        let authorization = headers
            .get("authorization")
            .expect("dispatch authorization");
        assert_eq!(
            authorization.as_bytes(),
            format!("Bearer {TOKEN}").as_bytes()
        );
        assert!(authorization.is_sensitive());
        assert_eq!(
            headers.get("accept").expect("accept"),
            WORKFLOW_DISPATCH_ACCEPT
        );
        assert_eq!(
            headers.get("content-type").expect("content type"),
            WORKFLOW_DISPATCH_CONTENT_TYPE
        );
        assert_eq!(
            headers.get("x-github-api-version").expect("API version"),
            WORKFLOW_DISPATCH_API_VERSION
        );
        assert_eq!(
            planned.uri_ref().expect("dispatch URI").to_string(),
            "https://api.github.com/repos/ShiroKSH/rustferry/actions/workflows/42/dispatches"
        );
        assert_eq!(client.agent.config().max_redirects(), 0);
        assert_eq!(
            client.agent.config().redirect_auth_headers(),
            ureq::config::RedirectAuthHeaders::Never
        );
        let rendered = format!("{client:?}\n{http_request:?}");
        assert!(!rendered.contains(TOKEN));
        assert!(!rendered.contains("api.github.com"));
        assert!(!rendered.contains("request_sha256"));
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_request_modes_and_errors_fail_closed_without_sensitive_values() {
        const SENTINEL: &str = "signed-url-token-never-surface";
        let client = UreqGithubJobLogHttpClient::new(SecretBytes::new(b"test-token".to_vec()))
            .expect("job-log client");
        for error in [
            client
                .prepare_get(
                    &format!("http://example.invalid/log?sig={SENTINEL}"),
                    false,
                    GithubJobLogAuthorization::Omit,
                    GithubJobLogAccept::PlainText,
                    Duration::from_secs(5),
                )
                .expect_err("HTTP redirect must fail"),
            client
                .prepare_get(
                    "/repos/ShiroKSH/rustferry/actions/jobs/42/logs",
                    true,
                    GithubJobLogAuthorization::Omit,
                    GithubJobLogAccept::Json,
                    Duration::from_secs(5),
                )
                .expect_err("API auth omission must fail"),
            map_ureq_request_error(ureq::Error::BadUri(SENTINEL.to_owned())),
            map_ureq_body_error(&io::Error::other(SENTINEL)),
        ] {
            let rendered = format!("{error:?}\n{error}");
            assert!(!rendered.contains(SENTINEL));
        }
        let rendered_client = format!("{client:?}");
        assert!(!rendered_client.contains("test-token"));
        assert!(rendered_client.contains("<redacted>"));
        let response = GithubJobLogHttpResponse::new(
            302,
            None,
            Some(format!("https://example.invalid/log?sig={SENTINEL}")),
            Cursor::new(Vec::<u8>::new()),
        );
        assert!(!format!("{response:?}").contains(SENTINEL));
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_body_reads_bounded_chunks_and_checks_cancellation_first() {
        let cancellation = rustferry_remote::CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut body = Cursor::new(b"abcdefgh".to_vec());

        assert_eq!(
            read_job_log_body_chunk(&mut body, 3, deadline, &cancellation,).expect("first chunk"),
            Some(b"abc".to_vec())
        );
        assert_eq!(
            read_job_log_body_chunk(
                &mut body,
                MAX_JOB_LOG_HTTP_CHUNK_BYTES + 1,
                deadline,
                &cancellation,
            ),
            Err(GithubJobLogHttpError::Protocol)
        );
        assert!(cancellation.cancel());
        assert_eq!(
            read_job_log_body_chunk(&mut body, 3, deadline, &cancellation,),
            Err(GithubJobLogHttpError::Cancelled)
        );
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_deadlines_and_post_io_cancellation_fail_closed() {
        struct StallingReader;

        impl Read for StallingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                thread::sleep(Duration::from_millis(30));
                buffer[0] = b'x';
                Ok(1)
            }
        }

        struct CancellingReader(rustferry_remote::CancellationToken);

        impl Read for CancellingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer[0] = b'x';
                assert!(self.0.cancel());
                Ok(1)
            }
        }

        struct CancellingEofReader(rustferry_remote::CancellationToken);

        impl Read for CancellingEofReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                assert!(self.0.cancel());
                Ok(0)
            }
        }

        let active = rustferry_remote::CancellationToken::new();
        assert_eq!(
            read_job_log_body_chunk(
                &mut StallingReader,
                1,
                Instant::now() + Duration::from_millis(10),
                &active,
            ),
            Err(GithubJobLogHttpError::TimedOut)
        );

        let cancelled_during_read = rustferry_remote::CancellationToken::new();
        assert_eq!(
            read_job_log_body_chunk(
                &mut CancellingReader(cancelled_during_read.clone()),
                1,
                Instant::now() + Duration::from_secs(1),
                &cancelled_during_read,
            ),
            Err(GithubJobLogHttpError::Cancelled)
        );

        let cancelled_at_eof = rustferry_remote::CancellationToken::new();
        assert_eq!(
            read_job_log_body_chunk(
                &mut CancellingEofReader(cancelled_at_eof.clone()),
                1,
                Instant::now() + Duration::from_secs(1),
                &cancelled_at_eof,
            ),
            Err(GithubJobLogHttpError::Cancelled)
        );

        let cancelled_after_get = rustferry_remote::CancellationToken::new();
        assert!(cancelled_after_get.cancel());
        assert_eq!(
            check_job_log_http_active(
                &cancelled_after_get,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(GithubJobLogHttpError::Cancelled)
        );
        assert_eq!(
            check_job_log_http_active(
                &rustferry_remote::CancellationToken::new(),
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .expect("past deadline"),
            ),
            Err(GithubJobLogHttpError::TimedOut)
        );
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the self-contained fake keeps ureq's unversioned transport API out of production code"
    )]
    fn job_log_ureq_deadline_and_redirect_policy_are_enforced() {
        use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
        use ureq::unversioned::transport::{
            Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
        };

        #[derive(Debug)]
        struct LoopbackResolver;

        impl Resolver for LoopbackResolver {
            fn resolve(
                &self,
                _uri: &ureq::http::Uri,
                _config: &ureq::config::Config,
                _timeout: NextTimeout,
            ) -> Result<ResolvedSocketAddrs, ureq::Error> {
                let mut addresses = self.empty();
                addresses.push(std::net::SocketAddr::from(([127, 0, 0, 1], 443)));
                Ok(addresses)
            }
        }

        const DELAYED_BODY_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\nConnection: close\r\n\r\n";
        const REDIRECT_RESPONSE: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: https://redirect.example.invalid/job.txt?signed=redirect-must-not-surface\r\nContent-Length: 0\r\n\r\n";

        #[derive(Debug)]
        struct ScriptedConnector {
            response: &'static [u8],
            connects: Arc<AtomicU64>,
        }

        impl Connector for ScriptedConnector {
            type Out = ScriptedTransport;

            fn connect(
                &self,
                details: &ConnectionDetails<'_>,
                _chained: Option<()>,
            ) -> Result<Option<Self::Out>, ureq::Error> {
                self.connects.fetch_add(1, Ordering::SeqCst);
                Ok(Some(ScriptedTransport {
                    buffers: LazyBuffers::new(
                        details.config.input_buffer_size(),
                        details.config.output_buffer_size(),
                    ),
                    response: self.response,
                    response_head_sent: false,
                }))
            }
        }

        #[derive(Debug)]
        struct ScriptedTransport {
            buffers: LazyBuffers,
            response: &'static [u8],
            response_head_sent: bool,
        }

        impl Transport for ScriptedTransport {
            fn buffers(&mut self) -> &mut dyn Buffers {
                &mut self.buffers
            }

            fn transmit_output(
                &mut self,
                _amount: usize,
                _timeout: NextTimeout,
            ) -> Result<(), ureq::Error> {
                Ok(())
            }

            fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
                if !self.response_head_sent {
                    let input = self.buffers.input_append_buf();
                    input[..self.response.len()].copy_from_slice(self.response);
                    self.buffers.input_appended(self.response.len());
                    self.response_head_sent = true;
                    return Ok(true);
                }

                let delay = timeout
                    .not_zero()
                    .map_or(Duration::from_millis(100), |duration| *duration)
                    .min(Duration::from_millis(100));
                thread::sleep(delay.saturating_add(Duration::from_millis(5)));
                Err(ureq::Error::Timeout(timeout.reason))
            }

            fn is_open(&mut self) -> bool {
                true
            }

            fn is_tls(&self) -> bool {
                true
            }
        }

        const SIGNED_TARGET_SENTINEL: &str =
            "https://logs.example.invalid/job.txt?signed=must-not-surface";
        const TOKEN_SENTINEL: &[u8] = b"fake-transport-token-must-not-surface";
        let mut client = UreqGithubJobLogHttpClient::new(SecretBytes::new(TOKEN_SENTINEL.to_vec()))
            .expect("job-log client");
        let delayed_connects = Arc::new(AtomicU64::new(0));
        client.agent = ureq::Agent::with_parts(
            client.agent.config().clone(),
            ScriptedConnector {
                response: DELAYED_BODY_RESPONSE,
                connects: Arc::clone(&delayed_connects),
            },
            LoopbackResolver,
        );
        let timeout = Duration::from_millis(40);
        let started = Instant::now();
        let response = client
            .prepare_get(
                SIGNED_TARGET_SENTINEL,
                false,
                GithubJobLogAuthorization::Omit,
                GithubJobLogAccept::PlainText,
                timeout,
            )
            .expect("signed request")
            .call()
            .expect("response head before deadline");
        let (_, body) = response.into_parts();
        let mut body = UreqGithubJobLogHttpBody {
            reader: body.into_reader(),
            request_deadline: started.checked_add(timeout).expect("request deadline"),
        };
        let error = body
            .next_chunk(1, &rustferry_remote::CancellationToken::new())
            .expect_err("body must time out");

        assert_eq!(error, GithubJobLogHttpError::TimedOut);
        let rendered = format!("{error:?}\n{error}");
        assert!(!rendered.contains(SIGNED_TARGET_SENTINEL));
        assert!(!rendered.contains("logs.example.invalid"));
        assert!(!rendered.contains("signed=must-not-surface"));
        assert!(!rendered.contains(std::str::from_utf8(TOKEN_SENTINEL).expect("ASCII token")));
        assert_eq!(delayed_connects.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_secs(1));

        let redirect_connects = Arc::new(AtomicU64::new(0));
        client.agent = ureq::Agent::with_parts(
            client.agent.config().clone(),
            ScriptedConnector {
                response: REDIRECT_RESPONSE,
                connects: Arc::clone(&redirect_connects),
            },
            LoopbackResolver,
        );
        let redirect = client
            .prepare_get(
                SIGNED_TARGET_SENTINEL,
                false,
                GithubJobLogAuthorization::Omit,
                GithubJobLogAccept::PlainText,
                Duration::from_secs(1),
            )
            .expect("signed request")
            .call()
            .expect("redirect response");

        assert_eq!(redirect.status().as_u16(), 302);
        assert_eq!(redirect_connects.load(Ordering::SeqCst), 1);
        assert_eq!(
            redirect.headers().get("location").expect("Location"),
            "https://redirect.example.invalid/job.txt?signed=redirect-must-not-surface"
        );
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_token_validation_is_bounded_and_never_accepts_output_lines() {
        assert_eq!(
            validate_github_token(vec![b'x'; MAX_GITHUB_TOKEN_BYTES], false)
                .expect("maximum token")
                .len(),
            MAX_GITHUB_TOKEN_BYTES
        );
        assert_eq!(
            validate_github_token(b"test-token\r\n".to_vec(), true)
                .expect("gh output token")
                .len(),
            "test-token".len()
        );
        assert!(matches!(
            validate_github_token(b"test-token\nsecond-line".to_vec(), true),
            Err(GhExecutionError::AuthenticationUnavailable)
        ));
        assert!(matches!(
            validate_github_token(vec![b'x'; MAX_GITHUB_TOKEN_BYTES + 1], false),
            Err(GhExecutionError::OutputLimitExceeded)
        ));
    }

    #[cfg(feature = "secure-job-log-http")]
    #[test]
    fn job_log_token_process_uses_only_fixed_auth_argv() {
        let executable_directory = tempfile::TempDir::new().expect("executable directory");
        let executable =
            executable_directory
                .path()
                .join(if cfg!(windows) { "gh.exe" } else { "gh" });
        fs::write(&executable, []).expect("fake gh executable");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let config = tempfile::TempDir::new().expect("config directory");
        let runner = GhProcessRunner::new(
            &executable,
            neutral.path(),
            GhAuthentication::config_directory(config.path()).expect("gh config"),
        )
        .expect("isolated gh runner");
        let command = runner.authentication_token_command();

        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["auth", "token", "--hostname", "github.com"]
                .map(OsStr::new)
                .as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_gh_state_rejects_a_parent_symlink_alias_into_the_project() {
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let state = neutral.path().join("state");
        fs::create_dir(&state).expect("project-local state directory");
        let alias_parent = tempfile::TempDir::new().expect("alias parent");
        let alias = alias_parent.path().join("project-alias");
        std::os::unix::fs::symlink(neutral.path(), &alias).expect("project symlink alias");

        assert!(matches!(
            validate_private_gh_state_root(&alias.join("state"), neutral.path()),
            Err(TransportConfigError::InvalidLocalPath {
                field: "private gh state directory"
            })
        ));
    }

    #[test]
    fn gh_process_environment_uses_only_private_state_and_disables_telemetry() {
        let executable_directory = tempfile::TempDir::new().expect("executable directory");
        let executable =
            executable_directory
                .path()
                .join(if cfg!(windows) { "gh.exe" } else { "gh" });
        fs::write(&executable, []).expect("fake gh executable");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let runner = GhProcessRunner::new(
            &executable,
            neutral.path(),
            GhAuthentication::environment_token(TokenEnvironmentVariable::GithubToken),
        )
        .expect("isolated gh runner");
        let request = GhRequest {
            method: ApiMethod::Get,
            endpoint: "/user".to_owned(),
            fields: Vec::new(),
            jq: Some(USER_QUERY),
            silent: false,
            output_limit: 1024,
            timeout: Duration::from_secs(1),
            api_version: API_VERSION,
        };
        let command = runner.command(&request);
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let value = |name: &str| {
            environment
                .get(OsStr::new(name))
                .and_then(Option::as_ref)
                .map(OsString::as_os_str)
        };

        assert_eq!(
            value("GH_CONFIG_DIR"),
            Some(runner.private_state.root.as_os_str())
        );
        assert_eq!(value("GH_TELEMETRY"), Some(OsStr::new("false")));
        assert_eq!(value("DO_NOT_TRACK"), Some(OsStr::new("true")));
        for name in [
            "XDG_STATE_HOME",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
        ] {
            assert_eq!(value(name), Some(runner.private_state.root.as_os_str()));
        }
        #[cfg(windows)]
        {
            assert_eq!(value("SystemRoot"), Some(runner.system_root.as_os_str()));
            assert!(runner.system_root.is_absolute());
            assert_eq!(environment.len(), 16);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(value("SystemRoot"), None);
            assert_eq!(environment.len(), 15);
        }
        for name in [
            "PATH",
            "PATHEXT",
            "WINDIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "GH_TOKEN",
            "GITHUB_TOKEN",
        ] {
            assert_eq!(value(name), None, "unexpected child variable {name}");
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires explicit live gh executable and config-directory paths"]
    fn live_windows_config_directory_authenticates_through_keyring() {
        let executable = std::env::var_os("RUSTFERRY_LIVE_GH_EXECUTABLE")
            .expect("set RUSTFERRY_LIVE_GH_EXECUTABLE to the real gh.exe path");
        let configuration_directory = std::env::var_os("RUSTFERRY_LIVE_GH_CONFIG_DIR")
            .expect("set RUSTFERRY_LIVE_GH_CONFIG_DIR to the authenticated gh config directory");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let authentication = GhAuthentication::config_directory(configuration_directory)
            .expect("canonical live gh config directory");
        let runner = GhProcessRunner::new(executable, neutral.path(), authentication)
            .expect("isolated live gh runner");
        let mut transport = GithubTransport::new(runner, TransportLimits::secure_defaults());

        let user = transport
            .authenticated_user()
            .expect("GET /user through Windows keyring authentication");

        assert_ne!(user.id(), 0);
        assert!(!user.login().is_empty());
    }

    #[test]
    fn environment_secret_write_uses_fixed_argv_and_separate_stdin() {
        const SENTINEL: &str = "fake-manual-signing-password-sentinel";

        let request = environment_secret_write_request();
        let value = SecretBytes::new(SENTINEL.as_bytes().to_vec());
        let mut transport = GithubTransport::new(FakeRunner::with_secret([Ok(())]), limits(1, 2));
        let receipt = transport
            .set_environment_secret(&request, &value)
            .expect("secret write");

        assert_eq!(receipt.repository(), request.repository());
        assert_eq!(receipt.environment(), request.environment());
        assert_eq!(receipt.name(), request.name());
        let runner = transport.into_runner();
        assert!(runner.requests.is_empty());
        assert_eq!(runner.secret_writes.len(), 1);
        let write = &runner.secret_writes[0];
        assert_eq!(write.request, request);
        assert_eq!(write.stdin_bytes, SENTINEL.len());
        assert_eq!(
            write.stdin_sha256,
            hex::encode(Sha256::digest(SENTINEL.as_bytes()))
        );
        assert_eq!(
            write.request.arguments(),
            [
                "secret",
                "set",
                "RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD",
                "--repo",
                "ShiroKSH/rustferry",
                "--env",
                "rustferry-goal3-signing",
            ]
            .map(OsString::from)
        );
        let rendered_arguments = format!("{:?}", write.request.arguments());
        assert!(!rendered_arguments.contains("--body"));
        assert!(!rendered_arguments.contains(SENTINEL));
        assert!(!format!("{runner:?}").contains(SENTINEL));
    }

    #[test]
    fn environment_secret_write_accepts_limit_and_rejects_oversize_before_runner() {
        let request = environment_secret_write_request();
        let maximum = SecretBytes::new(vec![b'x'; MAX_ENVIRONMENT_SECRET_BYTES]);
        let mut at_limit = GithubTransport::new(FakeRunner::with_secret([Ok(())]), limits(1, 2));
        at_limit
            .set_environment_secret(&request, &maximum)
            .expect("maximum-size secret");
        assert_eq!(at_limit.into_runner().secret_writes.len(), 1);

        let value = SecretBytes::new(vec![b'x'; MAX_ENVIRONMENT_SECRET_BYTES + 1]);
        let mut transport = GithubTransport::new(FakeRunner::default(), limits(1, 2));

        let error = transport
            .set_environment_secret(&request, &value)
            .expect_err("oversized secret must fail");

        assert_eq!(error, TransportError::EnvironmentSecretTooLarge);
        assert!(transport.into_runner().secret_writes.is_empty());
    }

    #[test]
    fn environment_secret_write_failure_does_not_expose_sentinel() {
        const SENTINEL: &str = "fake-never-log-this-secret-sentinel";

        let request = environment_secret_write_request();
        let value = SecretBytes::new(SENTINEL.as_bytes().to_vec());
        let mut transport = GithubTransport::new(
            FakeRunner::with_secret([Err(GhExecutionError::CommandFailed {
                exit_code: Some(17),
            })]),
            limits(1, 2),
        );

        let error = transport
            .set_environment_secret(&request, &value)
            .expect_err("failed secret write");
        let runner = transport.into_runner();
        let rendered = format!("{error:?}\n{error}\n{request:?}\n{runner:?}");
        assert!(!rendered.contains(SENTINEL));
        assert!(rendered.contains("status 17"));
    }

    #[cfg(unix)]
    #[test]
    fn gh_process_runner_sends_environment_secret_only_through_stdin() {
        use std::os::unix::fs::PermissionsExt as _;

        const SENTINEL: &str = "fake-process-stdin-only-secret-sentinel";
        let executable_directory = tempfile::TempDir::new().expect("executable directory");
        let executable = executable_directory.path().join("gh");
        fs::write(
            &executable,
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > secret-argv\ncat > secret-stdin\n",
        )
        .expect("fake gh executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fake gh permissions");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let config = tempfile::TempDir::new().expect("config directory");
        let runner = GhProcessRunner::new(
            &executable,
            neutral.path(),
            GhAuthentication::config_directory(config.path()).expect("gh config"),
        )
        .expect("isolated gh runner");
        let request = environment_secret_write_request();
        let value = SecretBytes::new(SENTINEL.as_bytes().to_vec());
        let mut transport = GithubTransport::new(runner, limits(1, 2));

        transport
            .set_environment_secret(&request, &value)
            .expect("secret write");

        assert_eq!(
            fs::read_to_string(neutral.path().join("secret-argv")).expect("recorded argv"),
            "secret\nset\nRUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD\n--repo\nShiroKSH/rustferry\n--env\nrustferry-goal3-signing\n"
        );
        assert_eq!(
            fs::read(neutral.path().join("secret-stdin")).expect("recorded stdin"),
            SENTINEL.as_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn gh_process_runner_discards_secret_command_output_on_failure() {
        use std::os::unix::fs::PermissionsExt as _;

        const SENTINEL: &str = "fake-secret-command-output-sentinel";
        let executable_directory = tempfile::TempDir::new().expect("executable directory");
        let executable = executable_directory.path().join("gh");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{SENTINEL}'\nprintf '%s' '{SENTINEL}' >&2\nexit 23\n"
            ),
        )
        .expect("fake gh executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fake gh permissions");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let config = tempfile::TempDir::new().expect("config directory");
        let runner = GhProcessRunner::new(
            &executable,
            neutral.path(),
            GhAuthentication::config_directory(config.path()).expect("gh config"),
        )
        .expect("isolated gh runner");
        let request = environment_secret_write_request();
        let value = SecretBytes::new(SENTINEL.as_bytes().to_vec());
        let mut transport = GithubTransport::new(runner, limits(1, 2));

        let error = transport
            .set_environment_secret(&request, &value)
            .expect_err("fake gh failure");

        let rendered = format!("{error:?}\n{error}");
        assert!(!rendered.contains(SENTINEL));
        assert!(rendered.contains("status 23"));
    }

    #[test]
    fn process_worker_drain_stops_at_cleanup_deadline() {
        let (_stdout_sender, stdout_reader) =
            mpsc::sync_channel::<Result<CapturedOutput, GhExecutionError>>(1);
        let (_stderr_sender, stderr_reader) =
            mpsc::sync_channel::<Result<CapturedOutput, GhExecutionError>>(1);
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(50))
            .expect("short cleanup deadline");

        let Err(error) = collect_process_workers(None, &stdout_reader, &stderr_reader, deadline)
        else {
            panic!("open output pipe must stop at the cleanup deadline");
        };

        assert_eq!(error, GhExecutionError::ProcessIo);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "bounded output drain exceeded its grace"
        );
    }

    #[test]
    fn process_deadline_child_helper() {
        const CHILD_MODE: &str = "RUSTFERRY_PROCESS_DEADLINE_CHILD";
        const LATE_OUTPUT: &[u8] = b"late-process-output-must-not-succeed";
        if std::env::var_os(CHILD_MODE).as_deref() != Some(OsStr::new("1")) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
        std::io::stdout()
            .write_all(LATE_OUTPUT)
            .expect("write late child output");
    }

    #[test]
    fn process_deadline_rejects_exit_and_output_during_poll_sleep() {
        const CHILD_MODE: &str = "RUSTFERRY_PROCESS_DEADLINE_CHILD";
        const LATE_OUTPUT: &str = "late-process-output-must-not-succeed";
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "transport::tests::process_deadline_child_helper",
                "--nocapture",
            ])
            .env(CHILD_MODE, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_tree(&mut command);

        let started = Instant::now();
        let error = run_process_inner(
            command,
            Duration::from_millis(25),
            64 * 1024,
            None,
            true,
            Duration::from_secs(2),
        )
        .expect_err("an exit observed after the original deadline must time out");

        assert_eq!(error, GhExecutionError::TimedOut);
        assert!(!format!("{error:?}\n{error}").contains(LATE_OUTPUT));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cleanup grace must not become an output-success deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gh_process_runner_timeout_kills_descendants_holding_output_pipes() {
        use std::os::unix::fs::PermissionsExt as _;

        const SENTINEL: &str = "fake-timeout-secret-sentinel";
        let executable_directory = tempfile::TempDir::new().expect("executable directory");
        let executable = executable_directory.path().join("gh");
        fs::write(
            &executable,
            b"#!/bin/sh\nset -eu\n/bin/sleep 30 &\nprintf '%s\\n' \"$!\" > descendant-pid\n/bin/cat >/dev/null\n/bin/sleep 30\n",
        )
        .expect("fake gh executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fake gh permissions");
        let neutral = tempfile::TempDir::new().expect("neutral directory");
        let config = tempfile::TempDir::new().expect("config directory");
        let runner = GhProcessRunner::new(
            &executable,
            neutral.path(),
            GhAuthentication::config_directory(config.path()).expect("gh config"),
        )
        .expect("isolated gh runner");
        let limits = TransportLimits::new(
            1,
            1,
            4 * 1024,
            4 * 1024 * 1024,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("five-second limits");
        let request = environment_secret_write_request();
        let value = SecretBytes::new(SENTINEL.as_bytes().to_vec());
        let mut transport = GithubTransport::new(runner, limits);

        let started = Instant::now();
        let error = transport
            .set_environment_secret(&request, &value)
            .expect_err("fake gh must time out");
        let elapsed = started.elapsed();

        assert_eq!(error, TransportError::Execution(GhExecutionError::TimedOut));
        assert!(
            elapsed < Duration::from_secs(8),
            "process-tree timeout took {elapsed:?}"
        );
        assert!(!format!("{error:?}\n{error}").contains(SENTINEL));
        let descendant_pid = fs::read_to_string(neutral.path().join("descendant-pid"))
            .expect("recorded descendant PID")
            .trim()
            .parse::<u32>()
            .expect("numeric descendant PID");
        assert_process_exits(descendant_pid);
    }

    #[test]
    fn temporary_ref_can_only_bind_below_exact_namespace() {
        let namespace = TemporaryBranchNamespace::new("rustferry/goal3/builds").expect("namespace");
        assert!(
            TemporaryGitRef::new(
                &namespace,
                BranchName::new("rustferry/goal3/builds/operation-1").expect("branch")
            )
            .is_ok()
        );
        assert!(
            TemporaryGitRef::new(
                &namespace,
                BranchName::new("rustferry/goal3/job-shadow/operation-1").expect("branch")
            )
            .is_err()
        );
    }

    #[test]
    fn workflow_dispatch_uses_exact_v2026_request_and_revalidates_run_id() {
        let registration = format!("42\t{WORKFLOW_PATH_B64}\tactive\n");
        let expected = workflow_dispatch_request();
        let run_name = base64_fixture(expected.run_name());
        let run = format!(
            "777\t42\t{WORKFLOW_DISPATCH_RUN_PATH_B64}\t8\t1\tfedcba9876543210fedcba9876543210fedcba98\t{BRANCH_B64}\tworkflow_dispatch\tqueued\t\t{run_name}\n"
        );
        let runner = FakeRunner::with([Ok(registration.into_bytes()), Ok(run.into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let registration = transport
            .workflow_registration(&repository(), WORKFLOW_PATH)
            .expect("active exact workflow");
        assert_eq!(registration, workflow_registration());

        let mut request = expected;
        request.workflow = registration;
        let mut client =
            FakeWorkflowDispatchHttpClient::with([Ok(GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json; charset=utf-8".to_owned()),
                workflow_dispatch_receipt_body(777),
            ))]);
        let receipt = transport
            .dispatch_workflow(&mut client, &request)
            .expect("strict 200 receipt");
        assert_eq!(receipt.run_id().get(), 777);

        let http_request = &client.requests[0];
        assert_eq!(
            http_request.endpoint(),
            "/repos/ShiroKSH/rustferry/actions/workflows/42/dispatches"
        );
        assert_eq!(http_request.accept(), "application/vnd.github+json");
        assert_eq!(http_request.content_type(), "application/json");
        assert_eq!(http_request.api_version(), "2026-03-10");
        assert_eq!(
            http_request.body(),
            format!(
                "{{\"ref\":\"rustferry/goal3/builds/job-1\",\"inputs\":{{\"operation_id\":\"job-1\",\"request_sha256\":\"{}\",\"source_revision\":\"{SHA}\",\"dispatch_revision\":\"fedcba9876543210fedcba9876543210fedcba98\"}}}}",
                "f".repeat(64)
            )
            .as_bytes()
        );
        let snapshot = transport
            .run_by_id(&receipt)
            .expect("run identity from receipt");
        assert_eq!(snapshot.handle().id(), receipt.run_id());
        assert_eq!(snapshot.handle().event(), RunEvent::WorkflowDispatch);
        assert_eq!(snapshot.handle().workflow_path(), WORKFLOW_PATH);

        let runner = transport.into_runner();
        assert_eq!(runner.requests.len(), 2);
        assert_eq!(
            runner.requests[0].endpoint(),
            "/repos/ShiroKSH/rustferry/actions/workflows/rustferry-goal3-iphone.yml"
        );
        assert_eq!(
            runner.requests[0].api_version_header(),
            WORKFLOW_DISPATCH_API_VERSION_HEADER
        );
        assert_eq!(
            runner.requests[1].endpoint(),
            "/repos/ShiroKSH/rustferry/actions/runs/777"
        );
        assert_eq!(
            runner.requests[1].api_version_header(),
            WORKFLOW_DISPATCH_API_VERSION_HEADER
        );
    }

    #[test]
    fn workflow_dispatch_request_rejects_ref_operation_and_digest_drift() {
        let namespace = TemporaryBranchNamespace::new("rustferry/goal3/builds").expect("namespace");
        let temporary_ref = || {
            TemporaryGitRef::new(
                &namespace,
                BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
            )
            .expect("temporary ref")
        };
        let source = CommitSha::new(SHA).expect("source revision");
        let dispatch =
            CommitSha::new("fedcba9876543210fedcba9876543210fedcba98").expect("dispatch revision");

        for (operation, digest) in [
            ("job-2", "f".repeat(64)),
            ("../job-1", "f".repeat(64)),
            ("job-1", "F".repeat(64)),
            ("job-1", "f".repeat(63)),
        ] {
            assert!(
                WorkflowDispatchRequest::new(
                    repository(),
                    workflow_registration(),
                    temporary_ref(),
                    operation,
                    digest,
                    source.clone(),
                    dispatch.clone(),
                )
                .is_err()
            );
        }
        assert!(
            WorkflowDispatchRequest::new(
                Repository::new("Other", "repository").expect("other repository"),
                workflow_registration(),
                temporary_ref(),
                "job-1",
                "f".repeat(64),
                source,
                dispatch,
            )
            .is_err()
        );
    }

    #[test]
    fn workflow_registration_and_run_by_id_reject_identity_drift() {
        assert!(!workflow_run_path_matches(
            &format!("{WORKFLOW_PATH}@other-branch"),
            WORKFLOW_PATH,
            &BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
        ));
        assert_eq!(
            parse_workflow_registration(
                format!("42\t{WORKFLOW_PATH_B64}\tdisabled_manually\n").as_bytes(),
                &repository(),
                WORKFLOW_PATH,
            ),
            Err(TransportError::WorkflowInactive)
        );
        assert_eq!(
            parse_workflow_registration(
                b"42\tLmdpdGh1Yi93b3JrZmxvd3Mvb3RoZXIueW1s\tactive\n",
                &repository(),
                WORKFLOW_PATH,
            ),
            Err(TransportError::WorkflowIdentityMismatch)
        );

        let request = workflow_dispatch_request();
        let run_name = base64_fixture(request.run_name());
        let drifted = format!(
            "778\t42\t{WORKFLOW_DISPATCH_RUN_PATH_B64}\t8\t1\tfedcba9876543210fedcba9876543210fedcba98\t{BRANCH_B64}\tworkflow_dispatch\tqueued\t\t{run_name}\n"
        );
        let runner = FakeRunner::with([Ok(drifted.into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let receipt = WorkflowDispatchReceipt {
            repository: request.repository.clone(),
            run_id: RunId::new(777).expect("run id"),
            workflow_id: request.workflow.id,
            workflow_path: request.workflow.path.clone(),
            dispatch_revision: request.dispatch_revision.clone(),
            branch: request.temporary_ref.branch().clone(),
            run_name: request.run_name.clone(),
        };
        assert_eq!(
            transport.run_by_id(&receipt),
            Err(TransportError::RunIdentityMismatch)
        );
    }

    #[test]
    fn workflow_dispatch_receipt_requires_exact_200_json_and_positive_id() {
        let request = workflow_dispatch_request();
        let transport = GithubTransport::new(FakeRunner::default(), limits(2, 3));
        let cases = [
            GithubWorkflowDispatchHttpResponse::new(
                302,
                Some("application/json".to_owned()),
                workflow_dispatch_receipt_body(777),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                None,
                workflow_dispatch_receipt_body(777),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("text/plain".to_owned()),
                workflow_dispatch_receipt_body(777),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                workflow_dispatch_receipt_body(0),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                br#"{"workflow_run_id":777,"run_url":"https://api.github.com/repos/x/y/actions/runs/777","html_url":"https://github.com/x/y/actions/runs/777","extra":true}"#.to_vec(),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                br#"{"workflow_run_id":777,"workflow_run_id":778,"run_url":"https://api.github.com/repos/ShiroKSH/rustferry/actions/runs/777","html_url":"https://github.com/ShiroKSH/rustferry/actions/runs/777"}"#.to_vec(),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                [workflow_dispatch_receipt_body(777), b" null".to_vec()].concat(),
            ),
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                vec![b'x'; MAX_WORKFLOW_DISPATCH_RESPONSE_BYTES + 1],
            ),
        ];
        for response in cases {
            let mut client = FakeWorkflowDispatchHttpClient::with([Ok(response)]);
            assert!(transport.dispatch_workflow(&mut client, &request).is_err());
        }

        let mut client =
            FakeWorkflowDispatchHttpClient::with([Err(GithubWorkflowDispatchHttpError::TimedOut)]);
        assert_eq!(
            transport.dispatch_workflow(&mut client, &request),
            Err(TransportError::WorkflowDispatchHttp(
                GithubWorkflowDispatchHttpError::TimedOut
            ))
        );
    }

    #[test]
    fn workflow_dispatch_debug_and_errors_omit_tokens_bodies_and_urls() {
        const TOKEN: &str = "dispatch-token-must-not-surface";
        const URL: &str = "https://api.github.com/repos/private/hidden/actions/runs/777";
        let transport = GithubTransport::new(FakeRunner::default(), limits(2, 3));
        let request = workflow_dispatch_request();
        let mut client = FakeWorkflowDispatchHttpClient::with([Ok(
            GithubWorkflowDispatchHttpResponse::new(
                200,
                Some("application/json".to_owned()),
                format!(
                    "{{\"workflow_run_id\":777,\"run_url\":\"{URL}\",\"html_url\":\"https://github.com/private/hidden/actions/runs/777\"}}"
                )
                .into_bytes(),
            ),
        )]);
        let error = transport
            .dispatch_workflow(&mut client, &request)
            .expect_err("unbound receipt URLs must fail");
        let rendered = format!(
            "{:?}\n{:?}\n{error:?}\n{error}",
            client.requests[0], client.responses
        );
        assert!(!rendered.contains(TOKEN));
        assert!(!rendered.contains(URL));
        assert!(!rendered.contains("private/hidden"));
        assert!(!rendered.contains("request_sha256"));
        assert!(!rendered.contains("/repos/ShiroKSH/rustferry"));
    }

    #[test]
    fn request_arguments_are_explicit_and_do_not_paginate_implicitly() {
        let runner = FakeRunner::with([Ok(Vec::new())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        transport
            .cancel_run(&repository(), RunId::new(42).expect("run"))
            .expect("cancel");
        let runner = transport.into_runner();
        let arguments = runner.requests[0].arguments();
        assert_eq!(
            arguments,
            [
                "api",
                "--hostname",
                "github.com",
                "--method",
                "POST",
                "-H",
                API_ACCEPT,
                "-H",
                API_VERSION,
                "/repos/ShiroKSH/rustferry/actions/runs/42/cancel",
                "--silent",
            ]
            .map(OsString::from)
        );
        assert!(!arguments.iter().any(|argument| argument == "--paginate"));
    }

    #[test]
    fn auth_and_repository_metadata_are_locally_validated() {
        let runner = FakeRunner::with([
            Ok(b"42\tU2hpcm9LU0g=\n".to_vec()),
            Ok(b"991\tshiroksh/RustFerry\tfalse\tfalse\tfalse\tmaster\n".to_vec()),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let user = transport.authenticated_user().expect("auth");
        assert_eq!(user.id(), 42);
        assert_eq!(user.login(), "ShiroKSH");
        let info = transport.repository(&repository()).expect("repository");
        assert_eq!(info.id(), 991);
        assert_eq!(info.full_name(), "shiroksh/RustFerry");
        assert!(!info.is_private());
        assert_eq!(info.default_branch().as_str(), "master");
    }

    #[test]
    fn actions_permissions_require_one_exact_enabled_boolean() {
        let runner = FakeRunner::with([Ok(b"true\n".to_vec()), Ok(b"false\n".to_vec())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert!(
            transport
                .actions_permissions(&repository())
                .expect("enabled Actions policy")
                .enabled()
        );
        assert!(
            !transport
                .actions_permissions(&repository())
                .expect("disabled Actions policy")
                .enabled()
        );
        let runner = transport.into_runner();
        for request in &runner.requests {
            assert_eq!(request.method(), ApiMethod::Get);
            assert_eq!(
                request.endpoint(),
                "/repos/ShiroKSH/rustferry/actions/permissions"
            );
            assert_eq!(request.jq, Some(ACTIONS_PERMISSIONS_QUERY));
            assert!(request.fields.is_empty());
        }

        for malformed in [
            b"".as_slice(),
            b"TRUE\n".as_slice(),
            b"1\n".as_slice(),
            b"true\nfalse\n".as_slice(),
        ] {
            let mut transport =
                GithubTransport::new(FakeRunner::with([Ok(malformed.to_vec())]), limits(2, 3));
            assert_eq!(
                transport.actions_permissions(&repository()),
                Err(TransportError::MalformedResponse {
                    operation: "GitHub Actions permissions"
                })
            );
        }
    }

    #[test]
    fn repository_credential_is_proved_without_claiming_a_user_identity() {
        let runner = FakeRunner::with([
            Err(GhExecutionError::CommandFailed { exit_code: Some(1) }),
            Ok(b"991\tU2hpcm9LU0gvcnVzdGZlcnJ5\n".to_vec()),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let principal = transport
            .authenticate(&repository())
            .expect("repository credential");
        assert_eq!(
            principal,
            AuthenticatedPrincipal::RepositoryCredential { repository_id: 991 }
        );
        assert_eq!(principal.repository_id(), Some(991));
        assert_eq!(principal.label(), "repository-scoped token");
        assert_eq!(principal.user_login(), None);

        let runner = transport.into_runner();
        assert_eq!(runner.requests.len(), 2);
        assert_eq!(runner.requests[0].endpoint(), "/user");
        assert_eq!(runner.requests[1].endpoint(), "/installation/repositories");
    }

    #[test]
    fn successful_user_probe_takes_precedence_over_installation_fallback() {
        let runner = FakeRunner::with([Ok(b"42\tU2hpcm9LU0g=\n".to_vec())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let principal = transport
            .authenticate(&repository())
            .expect("user credential");
        assert_eq!(principal.label(), "ShiroKSH");
        assert_eq!(principal.user_login(), Some("ShiroKSH"));

        let runner = transport.into_runner();
        assert_eq!(runner.requests.len(), 1);
        assert_eq!(runner.requests[0].endpoint(), "/user");
    }

    #[test]
    fn installation_credential_must_include_the_exact_repository() {
        let runner = FakeRunner::with([
            Err(GhExecutionError::CommandFailed { exit_code: Some(1) }),
            Ok(b"992\tU2hpcm9LU0gvb3RoZXI=\n".to_vec()),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.authenticate(&repository()),
            Err(TransportError::RepositoryAuthorizationMissing)
        );
    }

    #[test]
    fn signing_environment_metadata_uses_exact_bounded_rest_routes() {
        let runner = FakeRunner::with([
            Ok(format!("{ENVIRONMENT_B64}\tfalse\ttrue\ttrue\n").into_bytes()),
            Ok(format!("361471\t{DEPLOYMENT_POLICY_B64}\n").into_bytes()),
            Ok(format!(
                "{CERTIFICATE_P12_B64}\n{CERTIFICATE_PASSWORD_B64}\n{PROVISIONING_PROFILE_B64}\n"
            )
            .into_bytes()),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 4));
        let environment = environment();

        let info = transport
            .environment(&repository(), &environment)
            .expect("environment metadata");
        assert_eq!(info.name(), environment.as_str());
        assert!(!info.protected_branches());
        assert!(info.custom_branch_policies());
        assert!(info.has_required_reviewers());

        let policies = transport
            .list_deployment_branch_policies(&repository(), &environment)
            .expect("branch policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id(), 361_471);
        assert_eq!(policies[0].name(), "rustferry/goal3/builds/*");

        let secrets = transport
            .list_environment_secrets(&repository(), &environment)
            .expect("environment secret metadata");
        assert_eq!(
            secrets
                .iter()
                .map(|secret| secret.name().as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12",
                "RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD",
                "RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE",
            ])
        );

        let runner = transport.into_runner();
        assert_eq!(
            runner
                .requests
                .iter()
                .map(GhRequest::endpoint)
                .collect::<Vec<_>>(),
            [
                "/repos/ShiroKSH/rustferry/environments/rustferry-goal3-signing",
                "/repos/ShiroKSH/rustferry/environments/rustferry-goal3-signing/deployment-branch-policies",
                "/repos/ShiroKSH/rustferry/environments/rustferry-goal3-signing/secrets",
            ]
        );
        assert!(
            runner
                .requests
                .iter()
                .all(|request| request.method() == ApiMethod::Get)
        );
        assert!(
            runner
                .requests
                .iter()
                .all(|request| !request.arguments().iter().any(|arg| arg == "--paginate"))
        );
        assert!(runner.requests[0].fields.is_empty());
        assert_eq!(
            runner.requests[1].fields,
            [
                ("per_page".to_owned(), "4".to_owned()),
                ("page".to_owned(), "1".to_owned())
            ]
        );
        assert_eq!(runner.requests[2].fields, runner.requests[1].fields);
        assert_eq!(runner.requests[0].jq, Some(ENVIRONMENT_QUERY));
        assert_eq!(
            runner.requests[1].jq,
            Some(DEPLOYMENT_BRANCH_POLICY_LIST_QUERY)
        );
        assert_eq!(runner.requests[2].jq, Some(ENVIRONMENT_SECRET_LIST_QUERY));
    }

    #[test]
    fn signing_environment_metadata_fails_closed_on_identity_shape_and_pagination() {
        let mut wrong_environment = GithubTransport::new(
            FakeRunner::with([Ok(b"c3RhZ2luZw==\tfalse\ttrue\tfalse\n".to_vec())]),
            limits(1, 2),
        );
        assert_eq!(
            wrong_environment.environment(&repository(), &environment()),
            Err(TransportError::EnvironmentIdentityMismatch)
        );

        let duplicate =
            format!("361471\t{DEPLOYMENT_POLICY_B64}\n361472\t{DEPLOYMENT_POLICY_B64}\n");
        let mut duplicate_policies =
            GithubTransport::new(FakeRunner::with([Ok(duplicate.into_bytes())]), limits(2, 3));
        assert_eq!(
            duplicate_policies.list_deployment_branch_policies(&repository(), &environment()),
            Err(TransportError::MalformedResponse {
                operation: "deployment branch policy list"
            })
        );

        let mut malformed_secret =
            GithubTransport::new(FakeRunner::with([Ok(b"dW5zYWZl\n".to_vec())]), limits(1, 2));
        assert_eq!(
            malformed_secret.list_environment_secrets(&repository(), &environment()),
            Err(TransportError::MalformedResponse {
                operation: "environment secret list"
            })
        );

        let mut incomplete = GithubTransport::new(
            FakeRunner::with([Ok(format!("361471\t{DEPLOYMENT_POLICY_B64}\n").into_bytes())]),
            limits(1, 1),
        );
        assert_eq!(
            incomplete.list_deployment_branch_policies(&repository(), &environment()),
            Err(TransportError::PaginationLimitReached {
                resource: "deployment branch policy"
            })
        );
    }

    #[test]
    fn repository_identity_mismatch_is_rejected() {
        let runner = FakeRunner::with([Ok(
            b"991\tattacker/rustferry\tfalse\tfalse\tfalse\tmaster\n".to_vec(),
        )]);
        let mut transport = GithubTransport::new(runner, limits(1, 3));
        assert_eq!(
            transport.repository(&repository()),
            Err(TransportError::RepositoryIdentityMismatch)
        );
    }

    #[test]
    fn run_lookup_uses_exact_sha_branch_event_and_workflow() {
        let unrelated_sha = format!(
            "40\t17\t{WORKFLOW_PATH_B64}\t8\t1\t{}\t{}\tpush\tqueued\t\n",
            "f".repeat(40),
            BRANCH_B64
        );
        let unusual_path_b64 = "LmdpdGh1Yi93b3JrZmxvd3Mvb3RoZXIgd29ya2Zsb3cueW1s";
        let unrelated_workflow =
            format!("39\t16\t{unusual_path_b64}\t7\t1\t{SHA}\t{BRANCH_B64}\tpush\tqueued\t\n");
        let matching = String::from_utf8(run_row(41, "queued", "")).expect("row");
        let runner = FakeRunner::with([Ok(format!(
            "{unrelated_sha}{unrelated_workflow}{matching}"
        )
        .into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 4));
        let branch = BranchName::new("rustferry/goal3/builds/job-1").expect("branch");
        let run = transport
            .find_run(
                &repository(),
                WORKFLOW_PATH,
                &CommitSha::new(SHA).expect("sha"),
                &branch,
                RunEvent::Push,
            )
            .expect("run");
        assert_eq!(run.id().get(), 41);
        assert_eq!(run.workflow_path(), WORKFLOW_PATH);
        let runner = transport.into_runner();
        let arguments = runner.requests[0].arguments();
        assert!(arguments.contains(&OsString::from("/repos/ShiroKSH/rustferry/actions/runs")));
        for expected in [
            format!("head_sha={SHA}"),
            "branch=rustferry/goal3/builds/job-1".to_owned(),
            "event=push".to_owned(),
            "exclude_pull_requests=true".to_owned(),
        ] {
            assert!(arguments.contains(&OsString::from(expected)));
        }
    }

    #[test]
    fn run_lookup_rejects_ambiguity_and_incomplete_pagination() {
        let two = [
            String::from_utf8(run_row(41, "queued", "")).expect("row"),
            String::from_utf8(run_row(42, "queued", "")).expect("row"),
        ]
        .concat();
        let runner = FakeRunner::with([Ok(two.into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let result = transport.find_run(
            &repository(),
            WORKFLOW_PATH,
            &CommitSha::new(SHA).expect("sha"),
            &BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
            RunEvent::Push,
        );
        assert_eq!(result, Err(TransportError::AmbiguousRun));

        let full_page = [run_row(40, "queued", ""), run_row(40, "queued", "")].concat();
        let runner = FakeRunner::with([Ok(full_page)]);
        let mut transport = GithubTransport::new(runner, limits(1, 2));
        let result = transport.find_run(
            &repository(),
            WORKFLOW_PATH,
            &CommitSha::new(SHA).expect("sha"),
            &BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
            RunEvent::Push,
        );
        assert_eq!(
            result,
            Err(TransportError::PaginationLimitReached { resource: "run" })
        );
    }

    #[test]
    fn run_lookup_rejects_invalid_or_mismatched_workflow_paths() {
        let mut invalid_transport = GithubTransport::new(FakeRunner::default(), limits(1, 2));
        assert_eq!(
            invalid_transport.find_run(
                &repository(),
                "../workflows/attacker.yml",
                &CommitSha::new(SHA).expect("sha"),
                &BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
                RunEvent::Push,
            ),
            Err(TransportError::InvalidWorkflowPath)
        );

        let other_path_b64 = "LmdpdGh1Yi93b3JrZmxvd3Mvb3RoZXIueW1s";
        let mismatched =
            format!("41\t17\t{other_path_b64}\t9\t1\t{SHA}\t{BRANCH_B64}\tpush\tqueued\t\n");
        let mut mismatched_transport = GithubTransport::new(
            FakeRunner::with([Ok(mismatched.into_bytes())]),
            limits(1, 2),
        );
        assert_eq!(
            mismatched_transport.find_run(
                &repository(),
                WORKFLOW_PATH,
                &CommitSha::new(SHA).expect("sha"),
                &BranchName::new("rustferry/goal3/builds/job-1").expect("branch"),
                RunEvent::Push,
            ),
            Err(TransportError::RunNotFound)
        );
    }

    #[test]
    fn polling_rechecks_identity_and_stops_at_completion() {
        let runner = FakeRunner::with([
            Ok(run_row(41, "queued", "")),
            Ok(run_row(41, "completed", "success")),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let mut sleeper = FakeSleeper::default();
        let result = transport
            .wait_for_run_with(
                &repository(),
                &handle(),
                PollPolicy::new(2, Duration::from_millis(250)).expect("poll"),
                &mut sleeper,
            )
            .expect("completed run");
        assert_eq!(result.conclusion(), Some(RunConclusion::Success));
        assert_eq!(sleeper.0, [Duration::from_millis(250)]);
    }

    #[test]
    fn polling_rejects_changed_immutable_identity() {
        let changed = format!(
            "41\t17\t{WORKFLOW_PATH_B64}\t9\t1\t{}\t{}\tpush\tqueued\t\n",
            "f".repeat(40),
            BRANCH_B64
        );
        let runner = FakeRunner::with([Ok(changed.into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.run(&repository(), &handle()),
            Err(TransportError::RunIdentityMismatch)
        );
    }

    #[test]
    fn artifact_listing_decodes_names_and_validates_digests() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let row = format!("73\tcnVzdGZlcnJ5LXNpZ25lZC00Mi0x\t22\tfalse\t{digest}\n");
        let runner = FakeRunner::with([Ok(row.into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let artifact = transport
            .find_artifact(
                &repository(),
                RunId::new(42).expect("run"),
                &ArtifactName::new("rustferry-signed-42-1").expect("name"),
            )
            .expect("artifact");
        assert_eq!(artifact.id().get(), 73);
        assert_eq!(artifact.size_bytes(), 22);
        assert_eq!(artifact.digest(), Some(digest.as_str()));
    }

    #[test]
    fn expired_duplicate_and_oversized_artifacts_fail_closed() {
        let expired = b"73\tcnVzdGZlcnJ5LXNpZ25lZC00Mi0x\t22\ttrue\t\n".to_vec();
        let runner = FakeRunner::with([Ok(expired)]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.find_artifact(
                &repository(),
                RunId::new(42).expect("run"),
                &ArtifactName::new("rustferry-signed-42-1").expect("name")
            ),
            Err(TransportError::ArtifactExpired)
        );

        let row = b"73\tcnVzdGZlcnJ5LXNpZ25lZC00Mi0x\t99999999\tfalse\t\n".to_vec();
        let runner = FakeRunner::with([Ok(row)]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.find_artifact(
                &repository(),
                RunId::new(42).expect("run"),
                &ArtifactName::new("rustferry-signed-42-1").expect("name")
            ),
            Err(TransportError::ArtifactTooLarge)
        );
    }

    #[test]
    fn artifact_download_is_no_clobber_and_never_extracts() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "rustferry-github-transport-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("temp directory");
        let target = ArtifactDownloadTarget::new(&directory, "signed.ipa.zip").expect("target");
        let zip = [b"PK\x05\x06".as_slice(), &[0_u8; 18]].concat();
        let artifact = ArtifactInfo {
            id: ArtifactId::new(73).expect("artifact"),
            name: "rustferry-signed-42-1".to_owned(),
            size_bytes: usize_to_u64(zip.len()),
            expired: false,
            digest: None,
        };
        let runner = FakeRunner::with([Ok(zip.clone()), Ok(zip)]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        let downloaded = transport
            .download_artifact_zip(&repository(), &artifact, &target)
            .expect("download");
        assert_eq!(downloaded.bytes(), 22);
        assert_eq!(
            fs::read(downloaded.path()).expect("read"),
            [b"PK\x05\x06".as_slice(), &[0_u8; 18]].concat()
        );
        #[cfg(windows)]
        {
            let file =
                rustferry_core::windows_private_directory::open_private_file(downloaded.path())
                    .expect("open downloaded private file");
            rustferry_core::windows_private_directory::verify_private_file_handle(file.as_handle())
                .expect("verify downloaded private file");
        }
        assert_eq!(
            transport.download_artifact_zip(&repository(), &artifact, &target),
            Err(TransportError::DestinationExists)
        );
        fs::remove_file(downloaded.path()).expect("remove file");
        fs::remove_dir(&directory).expect("remove directory");
    }

    #[cfg(windows)]
    #[test]
    fn failed_windows_artifact_cleanup_consumes_the_created_handle() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let path = directory.path().join("failed-download.zip");
        let file = create_windows_private_file(&path).expect("create private artifact");

        remove_failed_windows_artifact(file).expect("remove exact artifact handle");

        assert!(!path.exists());
    }

    #[test]
    fn artifact_download_binds_metadata_size_and_digest_before_write() {
        static NEXT: AtomicU64 = AtomicU64::new(5_000);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "rustferry-github-transport-metadata-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("temp directory");
        let zip = [b"PK\x05\x06".as_slice(), &[0_u8; 18]].concat();

        let size_target =
            ArtifactDownloadTarget::new(&directory, "size-mismatch.zip").expect("target");
        let size_artifact = ArtifactInfo {
            id: ArtifactId::new(73).expect("artifact"),
            name: "signed".to_owned(),
            size_bytes: usize_to_u64(zip.len()).saturating_add(1),
            expired: false,
            digest: None,
        };
        let mut size_transport =
            GithubTransport::new(FakeRunner::with([Ok(zip.clone())]), limits(2, 3));
        assert_eq!(
            size_transport.download_artifact_zip(&repository(), &size_artifact, &size_target),
            Err(TransportError::ArtifactSizeMismatch)
        );
        assert!(!size_target.path().exists());

        let digest_target =
            ArtifactDownloadTarget::new(&directory, "digest-mismatch.zip").expect("target");
        let digest_artifact = ArtifactInfo {
            id: ArtifactId::new(74).expect("artifact"),
            name: "signed".to_owned(),
            size_bytes: usize_to_u64(zip.len()),
            expired: false,
            digest: Some(format!("sha256:{}", "0".repeat(64))),
        };
        let mut digest_transport = GithubTransport::new(FakeRunner::with([Ok(zip)]), limits(2, 3));
        assert_eq!(
            digest_transport.download_artifact_zip(&repository(), &digest_artifact, &digest_target),
            Err(TransportError::ArtifactDigestMismatch)
        );
        assert!(!digest_target.path().exists());
        fs::remove_dir(&directory).expect("remove directory");
    }

    #[test]
    fn malformed_zip_is_not_written() {
        static NEXT: AtomicU64 = AtomicU64::new(10_000);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "rustferry-github-transport-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("temp directory");
        let target = ArtifactDownloadTarget::new(&directory, "signed.zip").expect("target");
        let artifact = ArtifactInfo {
            id: ArtifactId::new(73).expect("artifact"),
            name: "signed".to_owned(),
            size_bytes: 32,
            expired: false,
            digest: None,
        };
        let runner = FakeRunner::with([Ok(b"not a zip response".to_vec())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.download_artifact_zip(&repository(), &artifact, &target),
            Err(TransportError::InvalidArtifactZip)
        );
        assert!(!target.path().exists());
        fs::remove_dir(&directory).expect("remove directory");
    }

    #[test]
    fn execution_errors_never_contain_command_output_or_tokens() {
        let secret = "ghp_DO_NOT_ECHO_THIS_VALUE";
        let error = GhExecutionError::CommandFailed { exit_code: Some(1) };
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        let transport = TransportError::Execution(error);
        assert!(!transport.to_string().contains(secret));
    }

    #[test]
    fn base64_decoder_is_strict_and_canonical() {
        assert_eq!(decode_base64("am9iLTE="), Some(b"job-1".to_vec()));
        assert_eq!(decode_base64("YQ=="), Some(b"a".to_vec()));
        assert_eq!(decode_base64("YR=="), None);
        assert_eq!(decode_base64("YQ=A"), None);
        assert_eq!(decode_base64("YQ==AAAA"), None);
        assert_eq!(decode_base64("not base64"), None);
    }
}
