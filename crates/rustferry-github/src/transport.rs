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
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use sha2::{Digest, Sha256};

use crate::workflow::{ProtectedEnvironment, SecretName, TemporaryBranchNamespace};

const GITHUB_HOST: &str = "github.com";
const API_ACCEPT: &str = "Accept: application/vnd.github+json";
const API_VERSION: &str = "X-GitHub-Api-Version: 2022-11-28";
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_API_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PAGES: u16 = 100;
const MAX_POLL_ATTEMPTS: u16 = 2_000;
const MAX_DEPLOYMENT_POLICY_NAME_BYTES: usize = 255;
const ZIP_END_RECORD_MINIMUM_BYTES: usize = 22;
const ZIP_END_RECORD_SEARCH_BYTES: usize = 65_557;

const USER_QUERY: &str = ".login";
const REPOSITORY_QUERY: &str =
    "[.id,.full_name,.private,.archived,.disabled,.default_branch] | @tsv";
const RUN_LIST_QUERY: &str = ".workflow_runs[] | [.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\")] | @tsv";
const RUN_QUERY: &str = "[.id,.workflow_id,(.path | @base64),.run_number,.run_attempt,.head_sha,(.head_branch | @base64),.event,.status,(.conclusion // \"\")] | @tsv";
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
            OsString::from(API_VERSION),
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

/// Redacted execution failure from a `gh` runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GhExecutionError {
    /// Authentication was unavailable from the exact configured source.
    AuthenticationUnavailable,
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
        Ok(Self {
            executable,
            neutral_working_directory,
            authentication,
            configuration_directory,
            private_state,
        })
    }

    fn command(&self, request: &GhRequest) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(request.arguments())
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
            .env("LOCALAPPDATA", &self.private_state.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl GhRunner for GhProcessRunner {
    fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
        let mut command = self.command(request);

        if let GhAuthentication::EnvironmentToken { variable, .. } = &self.authentication {
            let name = variable.as_str();
            let value = std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .ok_or(GhExecutionError::AuthenticationUnavailable)?;
            command.env(name, value);
        }

        run_process(command, request.timeout, request.output_limit)
    }
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
    login: String,
}

impl AuthenticatedUser {
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

impl RunSnapshot {
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
    /// GitHub returned malformed or unsupported metadata.
    MalformedResponse {
        /// Stable operation name; response bytes are intentionally omitted.
        operation: &'static str,
    },
    /// Repository metadata did not match the exact requested owner/name.
    RepositoryIdentityMismatch,
    /// Environment metadata did not match the exact configured name.
    EnvironmentIdentityMismatch,
    /// Workflow path was not one validated `.github/workflows/*.yml` file.
    InvalidWorkflowPath,
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
    /// Creating, writing, syncing, or cleaning up the new destination failed.
    ArtifactWriteFailed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Execution(error) => error.fmt(formatter),
            Self::MalformedResponse { operation } => {
                write!(formatter, "GitHub returned malformed {operation} metadata")
            }
            Self::RepositoryIdentityMismatch => {
                formatter.write_str("GitHub returned a different repository identity")
            }
            Self::EnvironmentIdentityMismatch => {
                formatter.write_str("GitHub returned a different environment identity")
            }
            Self::InvalidWorkflowPath => formatter.write_str("workflow path is invalid"),
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
        }
    }
}

impl Error for TransportError {}

impl From<GhExecutionError> for TransportError {
    fn from(value: GhExecutionError) -> Self {
        Self::Execution(value)
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
}

impl<R: GhRunner> GithubTransport<R> {
    /// Verify authentication through `GET /user`.
    ///
    /// # Errors
    ///
    /// Returns a redacted execution or response-validation failure.
    pub fn authenticated_user(&mut self) -> Result<AuthenticatedUser, TransportError> {
        let request = self.metadata_request(ApiMethod::Get, "/user".to_owned(), USER_QUERY);
        let output = self.runner.execute(&request)?;
        let login = parse_single_utf8_line(&output, "authenticated user")?;
        validate_owner(login).map_err(|_| TransportError::MalformedResponse {
            operation: "authenticated user",
        })?;
        Ok(AuthenticatedUser {
            login: login.to_owned(),
        })
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
        let workflow_filename = validated_workflow_filename(workflow_path)?;
        let mut matching: Option<RunSnapshot> = None;
        for page in 1..=self.limits.pages {
            let endpoint =
                repository.endpoint(&format!("/actions/workflows/{workflow_filename}/runs"));
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
                if candidate.handle.workflow_path == workflow_path
                    && candidate.handle.head_sha == *head_sha
                    && candidate.handle.branch == *branch
                    && candidate.handle.event == event
                {
                    match &matching {
                        None => matching = Some(candidate.clone()),
                        Some(previous) if previous == candidate => {}
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
        let snapshot = rows.remove(0);
        if snapshot.handle != *handle {
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
    /// The destination is created with no-clobber semantics and mode 0600 on
    /// Unix. Both API metadata and actual stdout are independently bounded.
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
            let actual = format!("sha256:{:x}", Sha256::digest(&bytes));
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

fn parse_run_row(line: &str, operation: &'static str) -> Result<RunSnapshot, TransportError> {
    let columns = split_columns(line, 10, operation)?;
    let id = RunId::new(parse_nonzero_u64(columns[0], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let workflow_id = WorkflowId::new(parse_nonzero_u64(columns[1], operation)?)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    let workflow_path_bytes =
        decode_base64(columns[2]).ok_or(TransportError::MalformedResponse { operation })?;
    let workflow_path = String::from_utf8(workflow_path_bytes)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
    validated_workflow_filename(&workflow_path)
        .map_err(|_| TransportError::MalformedResponse { operation })?;
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
    mut command: Command,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Vec<u8>, GhExecutionError> {
    let mut child = command.spawn().map_err(|_| GhExecutionError::SpawnFailed)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(GhExecutionError::ProcessIo);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(GhExecutionError::ProcessIo);
    };
    let stdout_reader = thread::spawn(move || read_capped(stdout, stdout_limit, true));
    let stderr_reader = thread::spawn(move || read_capped(stderr, MAX_STDERR_BYTES, false));
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        return Err(GhExecutionError::TimedOut);
    };

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(GhExecutionError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(GhExecutionError::ProcessIo);
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| GhExecutionError::ProcessIo)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| GhExecutionError::ProcessIo)??;
    if !status.success() {
        return Err(command_failed(status));
    }
    if stdout.truncated || stderr.truncated {
        return Err(GhExecutionError::OutputLimitExceeded);
    }
    Ok(stdout.bytes)
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
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const BRANCH_B64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy9qb2ItMQ==";
    const WORKFLOW_PATH: &str = ".github/workflows/rustferry-goal3-iphone.yml";
    const WORKFLOW_PATH_B64: &str = "LmdpdGh1Yi93b3JrZmxvd3MvcnVzdGZlcnJ5LWdvYWwzLWlwaG9uZS55bWw=";
    const ENVIRONMENT_B64: &str = "cnVzdGZlcnJ5LWdvYWwzLXNpZ25pbmc=";
    const DEPLOYMENT_POLICY_B64: &str = "cnVzdGZlcnJ5L2dvYWwzL2J1aWxkcy8q";
    const CERTIFICATE_P12_B64: &str = "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QMTI=";
    const CERTIFICATE_PASSWORD_B64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19DRVJUSUZJQ0FURV9QQVNTV09SRA==";
    const PROVISIONING_PROFILE_B64: &str =
        "UlVTVEZFUlJZX0dPQUwzX0lPU19QUk9WSVNJT05JTkdfUFJPRklMRQ==";

    #[derive(Debug, Default)]
    struct FakeRunner {
        responses: VecDeque<Result<Vec<u8>, GhExecutionError>>,
        requests: Vec<GhRequest>,
    }

    impl FakeRunner {
        fn with(responses: impl IntoIterator<Item = Result<Vec<u8>, GhExecutionError>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }
        }
    }

    impl GhRunner for FakeRunner {
        fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
            self.requests.push(request.clone());
            self.responses.pop_front().expect("unexpected request")
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
            GhAuthentication::environment_token(TokenEnvironmentVariable::GhToken),
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
        assert_eq!(environment.len(), 15);
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
            Ok(b"ShiroKSH\n".to_vec()),
            Ok(b"991\tshiroksh/RustFerry\tfalse\tfalse\tfalse\tmaster\n".to_vec()),
        ]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
        assert_eq!(
            transport.authenticated_user().expect("auth").login(),
            "ShiroKSH"
        );
        let info = transport.repository(&repository()).expect("repository");
        assert_eq!(info.id(), 991);
        assert_eq!(info.full_name(), "shiroksh/RustFerry");
        assert!(!info.is_private());
        assert_eq!(info.default_branch().as_str(), "master");
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
        let unrelated = format!(
            "40\t17\t{WORKFLOW_PATH_B64}\t8\t1\t{}\t{}\tpush\tqueued\t\n",
            "f".repeat(40),
            BRANCH_B64
        );
        let matching = String::from_utf8(run_row(41, "queued", "")).expect("row");
        let runner = FakeRunner::with([Ok(format!("{unrelated}{matching}").into_bytes())]);
        let mut transport = GithubTransport::new(runner, limits(2, 3));
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
        assert!(arguments.contains(&OsString::from(
            "/repos/ShiroKSH/rustferry/actions/workflows/rustferry-goal3-iphone.yml/runs"
        )));
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
        assert_eq!(
            transport.download_artifact_zip(&repository(), &artifact, &target),
            Err(TransportError::DestinationExists)
        );
        fs::remove_file(downloaded.path()).expect("remove file");
        fs::remove_dir(&directory).expect("remove directory");
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
