//! Deterministic rendering of a two-phase GitHub-hosted macOS workflow.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fmt::Write as _,
};

use rustferry_remote::{SigningTarget, SigningTargetKind, canonical_signing_target_graph_sha256};
use sha2::{Digest, Sha256};

const CHECKOUT_ACTION_SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";
const CACHE_ACTION_SHA: &str = "caa296126883cff596d87d8935842f9db880ef25";
const DOWNLOAD_ARTIFACT_ACTION_SHA: &str = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
const UPLOAD_ARTIFACT_ACTION_SHA: &str = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const DEFAULT_DEVELOPER_DIRECTORY: &str = "/Applications/Xcode.app/Contents/Developer";
const DEFAULT_RUNNER: &str = "macos-15";
const DEFAULT_WORKER_BUILD_TIMEOUT_MINUTES: u16 = 30;
const REQUEST_MANIFEST_PATH: &str = ".rustferry/goal3/request.json";
const RUST_TOOLCHAIN: &str = "1.92.0";
const GOAL3_CERTIFICATE_P12_SECRET: &str = "RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12";
const GOAL3_CERTIFICATE_PASSWORD_SECRET: &str = "RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD";
const GOAL3_APPLICATION_PROFILE_SECRET: &str = "RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE";
const GOAL3_EXTENSION_PROFILE_SECRET_PREFIX: &str = "RUSTFERRY_GOAL3_IOS_PROFILE_";

/// Maximum number of application and extension provisioning profiles exposed
/// to one protected GitHub signing job.
pub const MAX_SIGNING_PROFILES: usize = 3;

/// A rejected workflow configuration field.
///
/// Errors name the field and failure class but never echo rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowConfigError {
    /// A required field was empty.
    Empty {
        /// Stable field name.
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
        /// Byte offset of the rejected input, without the byte itself.
        index: usize,
    },
    /// A field did not match its required structure.
    InvalidFormat {
        /// Stable field name.
        field: &'static str,
    },
    /// A reserved GitHub name or namespace was selected.
    Reserved {
        /// Stable field name.
        field: &'static str,
    },
    /// Two signing roles referenced the same GitHub secret.
    DuplicateSecretName,
    /// Signing targets could not form one unambiguous application/profile map.
    InvalidSigningTargets,
    /// More profile-bearing targets were configured than the protected worker accepts.
    TooManySigningProfiles {
        /// Maximum accepted application plus extension profile count.
        maximum: usize,
    },
    /// The temporary dispatch namespace overlaps the trusted source ref.
    RefNamespaceOverlap,
    /// A numeric policy value was outside its bounded range.
    PolicyOutOfRange {
        /// Stable field name.
        field: &'static str,
        /// Inclusive minimum.
        minimum: u16,
        /// Inclusive maximum.
        maximum: u16,
    },
}

impl fmt::Display for WorkflowConfigError {
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
            Self::Reserved { field } => write!(formatter, "{field} uses a reserved value"),
            Self::DuplicateSecretName => {
                formatter.write_str("signing secret names must be distinct")
            }
            Self::InvalidSigningTargets => formatter.write_str(
                "signing targets must contain exactly one application and unique target identities",
            ),
            Self::TooManySigningProfiles { maximum } => {
                write!(
                    formatter,
                    "signing target graph exceeds {maximum} provisioning profiles"
                )
            }
            Self::RefNamespaceOverlap => formatter
                .write_str("temporary dispatch namespace must not overlap the trusted source ref"),
            Self::PolicyOutOfRange {
                field,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field} must be between {minimum} and {maximum} inclusive"
            ),
        }
    }
}

impl Error for WorkflowConfigError {}

/// Validated basename for a generated file below `.github/workflows/`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowFileName(String);

impl WorkflowFileName {
    /// Validate a workflow basename ending in `.yml` or `.yaml`.
    ///
    /// # Errors
    ///
    /// Rejects paths, control characters, YAML syntax, dot sequences, and
    /// names longer than 128 bytes.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_nonempty_length("workflow filename", &value, 128)?;
        validate_ascii_allowlist("workflow filename", &value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })?;
        if !value.as_bytes()[0].is_ascii_alphanumeric()
            || value.contains("..")
            || !(value.ends_with(".yml") || value.ends_with(".yaml"))
        {
            return Err(WorkflowConfigError::InvalidFormat {
                field: "workflow filename",
            });
        }
        Ok(Self(value))
    }

    /// Return the validated basename.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the repository-relative workflow path.
    pub fn repository_path(&self) -> String {
        format!(".github/workflows/{}", self.0)
    }
}

/// Validated GitHub Environment name used only by the signing job.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedEnvironment(String);

impl ProtectedEnvironment {
    /// Validate a conservative GitHub Environment identifier.
    ///
    /// # Errors
    ///
    /// Rejects spaces, expression syntax, path syntax, and values longer than
    /// 64 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_identifier("protected environment", &value, 64, b"._-")?;
        if value.contains("..") {
            return Err(WorkflowConfigError::InvalidFormat {
                field: "protected environment",
            });
        }
        Ok(Self(value))
    }

    /// Return the validated environment name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated name of a GitHub Actions secret, never a secret value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretName(String);

impl SecretName {
    /// Validate an uppercase GitHub Actions secret name.
    ///
    /// # Errors
    ///
    /// Rejects names beginning with a number or `GITHUB_`, lowercase names,
    /// expression syntax, and values longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_nonempty_length("secret name", &value, 128)?;
        let first = value.as_bytes()[0];
        if !(first.is_ascii_uppercase() || first == b'_') {
            return Err(WorkflowConfigError::InvalidFormat {
                field: "secret name",
            });
        }
        validate_ascii_allowlist("secret name", &value, |byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
        })?;
        if value.starts_with("GITHUB_") {
            return Err(WorkflowConfigError::Reserved {
                field: "secret name",
            });
        }
        Ok(Self(value))
    }

    /// Return the validated reference name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SigningProfileSecretName {
    target: Option<String>,
    name: SecretName,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SigningTargetIdentity {
    name: String,
    bundle_identifier: String,
    kind: SigningTargetKind,
}

/// Opaque GitHub secret references needed for manual development signing.
///
/// Legacy configurations retain one target-independent application profile.
/// New configurations bind one deterministic static secret name to each
/// application or extension target before the workflow is installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningSecretNames {
    certificate_p12: SecretName,
    certificate_password: SecretName,
    provisioning_profiles: Vec<SigningProfileSecretName>,
    target_graph: Option<Vec<SigningTargetIdentity>>,
    target_graph_sha256: Option<String>,
}

impl SigningSecretNames {
    /// Bind distinct certificate, password, and provisioning-profile names.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowConfigError::DuplicateSecretName`] when one secret is
    /// reused for multiple roles.
    pub fn new(
        certificate_p12: SecretName,
        certificate_password: SecretName,
        provisioning_profile: SecretName,
    ) -> Result<Self, WorkflowConfigError> {
        if certificate_p12 == certificate_password
            || certificate_p12 == provisioning_profile
            || certificate_password == provisioning_profile
        {
            return Err(WorkflowConfigError::DuplicateSecretName);
        }
        Ok(Self {
            certificate_p12,
            certificate_password,
            provisioning_profiles: vec![SigningProfileSecretName {
                target: None,
                name: provisioning_profile,
            }],
            target_graph: None,
            target_graph_sha256: None,
        })
    }

    /// Derive the exact static profile-secret map for one target graph.
    ///
    /// The application retains the legacy Goal 3 profile name. Extension
    /// names contain the first 128 bits of SHA-256 over the target name, a NUL
    /// separator, and its bundle identifier. Frameworks and dynamic libraries
    /// do not receive provisioning profiles.
    ///
    /// # Errors
    ///
    /// Rejects target graphs without exactly one application, duplicate target
    /// names or bundle identifiers, or more than [`MAX_SIGNING_PROFILES`]
    /// application and extension targets.
    ///
    /// # Panics
    ///
    /// This cannot panic because the fixed certificate and password names
    /// satisfy [`SecretName`] invariants.
    pub fn for_targets(targets: &[SigningTarget]) -> Result<Self, WorkflowConfigError> {
        let target_graph = canonical_signing_target_graph(targets)?;
        let target_graph_sha256 = canonical_signing_target_graph_sha256(targets);
        let mut profiles = BTreeMap::new();

        for target in &target_graph {
            let secret_name = match target.kind {
                SigningTargetKind::Application => GOAL3_APPLICATION_PROFILE_SECRET.to_owned(),
                SigningTargetKind::Extension => extension_profile_secret_name(target),
                SigningTargetKind::DynamicLibrary | SigningTargetKind::Framework => continue,
            };
            profiles.insert(target.name.clone(), SecretName::new(secret_name)?);
        }

        if profiles.len() > MAX_SIGNING_PROFILES {
            return Err(WorkflowConfigError::TooManySigningProfiles {
                maximum: MAX_SIGNING_PROFILES,
            });
        }

        let names = Self {
            certificate_p12: SecretName::new(GOAL3_CERTIFICATE_P12_SECRET)
                .expect("constant secret name is valid"),
            certificate_password: SecretName::new(GOAL3_CERTIFICATE_PASSWORD_SECRET)
                .expect("constant secret name is valid"),
            provisioning_profiles: profiles
                .into_iter()
                .map(|(target, name)| SigningProfileSecretName {
                    target: Some(target),
                    name,
                })
                .collect(),
            target_graph: Some(target_graph),
            target_graph_sha256: Some(target_graph_sha256),
        };
        if names.all_names().collect::<BTreeSet<_>>().len() != names.all_names().count() {
            return Err(WorkflowConfigError::DuplicateSecretName);
        }
        Ok(names)
    }

    /// Goal 3 development secret namespace from the project specification.
    ///
    /// # Panics
    ///
    /// This cannot panic because all three constant names satisfy the
    /// constructor invariants and are distinct.
    pub fn goal3_defaults() -> Self {
        Self::new(
            SecretName::new(GOAL3_CERTIFICATE_P12_SECRET).expect("constant secret name is valid"),
            SecretName::new(GOAL3_CERTIFICATE_PASSWORD_SECRET)
                .expect("constant secret name is valid"),
            SecretName::new(GOAL3_APPLICATION_PROFILE_SECRET)
                .expect("constant secret name is valid"),
        )
        .expect("constant secret names are distinct")
    }

    /// GitHub secret containing the encoded PKCS#12 certificate.
    pub fn certificate_p12(&self) -> &SecretName {
        &self.certificate_p12
    }

    /// GitHub secret containing the PKCS#12 password.
    pub fn certificate_password(&self) -> &SecretName {
        &self.certificate_password
    }

    /// GitHub secret containing the encoded application provisioning profile.
    ///
    /// # Panics
    ///
    /// This cannot panic because every constructor retains at least one
    /// application profile name.
    pub fn provisioning_profile(&self) -> &SecretName {
        let profile = self
            .provisioning_profiles
            .iter()
            .find(|profile| profile.name.as_str() == GOAL3_APPLICATION_PROFILE_SECRET)
            .unwrap_or_else(|| {
                self.provisioning_profiles
                    .first()
                    .expect("signing secret names always contain an application profile")
            });
        &profile.name
    }

    /// Static provisioning-profile secret bound to `target`.
    ///
    /// A legacy one-profile configuration returns its sole profile for any
    /// target. The provider permits that fallback only for one-profile plans.
    pub fn profile_for_target(&self, target: &str) -> Option<&SecretName> {
        self.provisioning_profiles
            .iter()
            .find(|profile| {
                profile
                    .target
                    .as_deref()
                    .is_none_or(|configured| configured == target)
            })
            .map(|profile| &profile.name)
    }

    /// Deterministically ordered provisioning-profile secret names.
    pub fn profile_names(&self) -> impl ExactSizeIterator<Item = &SecretName> {
        self.provisioning_profiles
            .iter()
            .map(|profile| &profile.name)
    }

    /// Exact certificate, password, and provisioning-profile secret set.
    pub fn all_names(&self) -> impl Iterator<Item = &SecretName> {
        std::iter::once(&self.certificate_p12)
            .chain(std::iter::once(&self.certificate_password))
            .chain(self.profile_names())
    }

    /// Canonical full signing-target graph policy digest for modern workflows.
    ///
    /// Legacy target-independent configurations return `None`.
    pub fn target_graph_sha256(&self) -> Option<&str> {
        self.target_graph_sha256.as_deref()
    }

    /// Whether `targets` exactly matches the graph bound during workflow setup.
    ///
    /// Ordering is ignored. Target names, bundle identifiers, and kinds are
    /// compared for every application, extension, framework, and dynamic library.
    /// Legacy target-independent configurations never match a target graph.
    pub fn matches_target_graph(&self, targets: &[SigningTarget]) -> bool {
        self.target_graph.as_ref().is_some_and(|expected| {
            canonical_signing_target_graph(targets).is_ok_and(|actual| actual == *expected)
                && self.target_graph_sha256()
                    == Some(canonical_signing_target_graph_sha256(targets).as_str())
        })
    }

    pub(crate) fn uses_legacy_profile_binding(&self) -> bool {
        self.provisioning_profiles.len() == 1 && self.provisioning_profiles[0].target.is_none()
    }
}

fn canonical_signing_target_graph(
    targets: &[SigningTarget],
) -> Result<Vec<SigningTargetIdentity>, WorkflowConfigError> {
    let mut target_names = BTreeSet::new();
    let mut bundle_identifiers = BTreeSet::new();
    let mut application_count = 0_usize;
    let mut target_graph = Vec::with_capacity(targets.len());

    for target in targets {
        if !valid_signing_target_name(&target.name)
            || !target_names.insert(target.name.as_str())
            || !bundle_identifiers.insert(target.bundle_identifier.as_str())
        {
            return Err(WorkflowConfigError::InvalidSigningTargets);
        }
        if target.kind == SigningTargetKind::Application {
            application_count += 1;
        }
        target_graph.push(SigningTargetIdentity {
            name: target.name.clone(),
            bundle_identifier: target.bundle_identifier.as_str().to_owned(),
            kind: target.kind,
        });
    }

    if application_count != 1 {
        return Err(WorkflowConfigError::InvalidSigningTargets);
    }
    target_graph.sort_unstable();
    Ok(target_graph)
}

fn extension_profile_secret_name(target: &SigningTargetIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(target.name.as_bytes());
    digest.update([0]);
    digest.update(target.bundle_identifier.as_bytes());
    let digest = digest.finalize();
    format!(
        "{GOAL3_EXTENSION_PROFILE_SECRET_PREFIX}{}",
        hex::encode_upper(&digest[..16])
    )
}

fn valid_signing_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !value.contains("..")
}

/// Validated public GitHub repository containing the project source.
///
/// The constructor validates and normalizes repository identity. The caller
/// must separately prove that GitHub reports the repository as public before
/// using it with a private execution repository.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicSourceRepository {
    url: String,
    slug: String,
}

impl PublicSourceRepository {
    /// Normalize an `OWNER/REPOSITORY` slug or HTTPS GitHub repository URL.
    ///
    /// # Errors
    ///
    /// Rejects non-GitHub URLs, credentials, extra path components, expression
    /// syntax, and values longer than 256 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        let (url, slug) = normalize_github_repository("public source repository", &value)?;
        Ok(Self { url, slug })
    }

    /// Normalized lowercase HTTPS repository URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Normalized lowercase `owner/repository` slug for `actions/checkout`.
    pub fn slug(&self) -> &str {
        &self.slug
    }
}

/// Exact trusted branch or tag from which source revisions may be selected.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedSourceRef(String);

impl TrustedSourceRef {
    /// Validate a full `refs/heads/...` or `refs/tags/...` name.
    ///
    /// # Errors
    ///
    /// Rejects pull-request refs, wildcards, ref traversal, expression syntax,
    /// and values longer than 255 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_nonempty_length("trusted source ref", &value, 255)?;
        let tail = value
            .strip_prefix("refs/heads/")
            .or_else(|| value.strip_prefix("refs/tags/"))
            .ok_or(WorkflowConfigError::InvalidFormat {
                field: "trusted source ref",
            })?;
        validate_ref_tail("trusted source ref", tail)?;
        Ok(Self(value))
    }

    /// Return the validated full ref.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Branch namespace used only for temporary provider job refs.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TemporaryBranchNamespace(String);

impl TemporaryBranchNamespace {
    /// Validate a branch prefix such as `rustferry/goal3/builds`.
    ///
    /// The namespace excludes `refs/heads/`; the generator adds it where a
    /// full ref is required and appends `/**` only in the trigger filter.
    ///
    /// # Errors
    ///
    /// Rejects ref syntax, wildcard characters, reserved GitHub namespaces,
    /// and values longer than 192 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_nonempty_length("temporary branch namespace", &value, 192)?;
        if value.starts_with("refs/") || value.starts_with("pull/") {
            return Err(WorkflowConfigError::Reserved {
                field: "temporary branch namespace",
            });
        }
        validate_ref_tail("temporary branch namespace", &value)?;
        Ok(Self(value))
    }

    /// Return the namespace without `refs/heads/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn trigger_pattern(&self) -> String {
        format!("{}/**", self.0)
    }

    fn full_ref_prefix(&self) -> String {
        format!("refs/heads/{}", self.0)
    }
}

/// Absolute Xcode developer directory selected per job through `DEVELOPER_DIR`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeveloperDirectory(String);

impl DeveloperDirectory {
    /// Validate an Xcode developer directory below `/Applications`.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, traversal, shell/YAML syntax, and values longer
    /// than 256 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowConfigError> {
        let value = value.into();
        validate_nonempty_length("developer directory", &value, 256)?;
        validate_ascii_allowlist("developer directory", &value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })?;
        if !value.starts_with("/Applications/Xcode")
            || !value.ends_with(".app/Contents/Developer")
            || value.contains("..")
            || value.contains("//")
        {
            return Err(WorkflowConfigError::InvalidFormat {
                field: "developer directory",
            });
        }
        Ok(Self(value))
    }

    /// Standard GitHub-hosted runner Xcode selection.
    ///
    /// # Panics
    ///
    /// This cannot panic because the constant path satisfies all invariants.
    pub fn github_default() -> Self {
        Self::new(DEFAULT_DEVELOPER_DIRECTORY).expect("constant developer directory is valid")
    }

    /// Return the validated absolute directory.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Trusted macOS worker provisioning policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerDistribution {
    provisioning: WorkerProvisioning,
    version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkerProvisioning {
    Prebuilt {
        download_url: String,
        sha256: String,
    },
    SourceBuild {
        repository: String,
        repository_slug: String,
        revision: String,
    },
}

impl WorkerDistribution {
    /// Validate one public GitHub release asset, SHA-256, and worker version.
    ///
    /// The URL must be a simple HTTPS GitHub release URL without credentials,
    /// a query, a fragment, percent escapes, or shell/YAML metacharacters.
    ///
    /// # Errors
    ///
    /// Rejects a non-GitHub/non-HTTPS URL, malformed lowercase SHA-256, or an
    /// unsafe version label.
    pub fn new(
        download_url: impl Into<String>,
        sha256: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, WorkflowConfigError> {
        let download_url = download_url.into();
        let sha256 = sha256.into();
        let version = version.into();
        validate_worker_url(&download_url)?;
        validate_sha256("worker sha256", &sha256)?;
        validate_nonempty_length("worker version", &version, 64)?;
        validate_ascii_allowlist("worker version", &version, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
        })?;
        if !version.as_bytes()[0].is_ascii_alphanumeric() {
            return Err(WorkflowConfigError::InvalidFormat {
                field: "worker version",
            });
        }
        Ok(Self {
            provisioning: WorkerProvisioning::Prebuilt {
                download_url,
                sha256,
            },
            version,
        })
    }

    /// Bind a source build to one normalized GitHub repository, exact commit,
    /// and expected semantic version.
    ///
    /// Repository inputs may be `OWNER/REPOSITORY` or an HTTPS GitHub URL,
    /// optionally ending in `.git` or `/`. The stored URL and slug are
    /// lowercase and contain exactly two path components.
    ///
    /// # Errors
    ///
    /// Rejects non-GitHub repositories, malformed 40-character lowercase
    /// commit IDs, and non-canonical semantic versions.
    pub fn from_source(
        repository: impl Into<String>,
        revision: impl Into<String>,
        expected_version: impl Into<String>,
    ) -> Result<Self, WorkflowConfigError> {
        let repository = repository.into();
        let revision = revision.into();
        let version = expected_version.into();
        let (repository, repository_slug) =
            normalize_github_repository("worker source repository", &repository)?;
        validate_commit_sha("worker source revision", &revision)?;
        validate_semver("worker version", &version)?;
        Ok(Self {
            provisioning: WorkerProvisioning::SourceBuild {
                repository,
                repository_slug,
                revision,
            },
            version,
        })
    }

    /// Validated public download URL for prebuilt provisioning.
    ///
    /// # Panics
    ///
    /// Panics when source-build provisioning is selected. Use
    /// [`Self::source_repository`] to inspect that mode.
    pub fn download_url(&self) -> &str {
        match &self.provisioning {
            WorkerProvisioning::Prebuilt { download_url, .. } => download_url,
            WorkerProvisioning::SourceBuild { .. } => {
                panic!("source-built workers do not have a download URL")
            }
        }
    }

    /// Expected lowercase SHA-256 for prebuilt provisioning.
    ///
    /// # Panics
    ///
    /// Panics when source-build provisioning is selected. Its SHA-256 is
    /// derived by the isolated worker job and propagated as a job output.
    pub fn sha256(&self) -> &str {
        match &self.provisioning {
            WorkerProvisioning::Prebuilt { sha256, .. } => sha256,
            WorkerProvisioning::SourceBuild { .. } => {
                panic!("source-built worker SHA-256 is derived by the workflow")
            }
        }
    }

    /// Whether the worker is built from an exact trusted source revision.
    pub fn is_source_build(&self) -> bool {
        matches!(&self.provisioning, WorkerProvisioning::SourceBuild { .. })
    }

    /// Exact worker version expected by the workflow contract.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Normalized HTTPS GitHub repository when source provisioning is selected.
    pub fn source_repository(&self) -> Option<&str> {
        match &self.provisioning {
            WorkerProvisioning::Prebuilt { .. } => None,
            WorkerProvisioning::SourceBuild { repository, .. } => Some(repository),
        }
    }

    /// Exact lowercase commit ID when source provisioning is selected.
    pub fn source_revision(&self) -> Option<&str> {
        match &self.provisioning {
            WorkerProvisioning::Prebuilt { .. } => None,
            WorkerProvisioning::SourceBuild { revision, .. } => Some(revision),
        }
    }

    fn source_build(&self) -> Option<(&str, &str, &str)> {
        match &self.provisioning {
            WorkerProvisioning::Prebuilt { .. } => None,
            WorkerProvisioning::SourceBuild {
                repository,
                repository_slug,
                revision,
            } => Some((repository, repository_slug, revision)),
        }
    }
}

/// Bounded execution and artifact-retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowLimits {
    compile_timeout_minutes: u16,
    signing_timeout_minutes: u16,
    retention_days: u16,
}

impl WorkflowLimits {
    /// Construct bounded compile/signing timeouts and artifact retention.
    ///
    /// # Errors
    ///
    /// Compile must be 5–180 minutes, signing 5–60 minutes, and retention
    /// 1–14 days.
    pub fn new(
        compile_timeout_minutes: u16,
        signing_timeout_minutes: u16,
        retention_days: u16,
    ) -> Result<Self, WorkflowConfigError> {
        validate_policy("compile timeout", compile_timeout_minutes, 5, 180)?;
        validate_policy("signing timeout", signing_timeout_minutes, 5, 60)?;
        validate_policy("artifact retention", retention_days, 1, 14)?;
        Ok(Self {
            compile_timeout_minutes,
            signing_timeout_minutes,
            retention_days,
        })
    }

    /// Default 90-minute compile, 30-minute signing, and three-day retention.
    ///
    /// # Panics
    ///
    /// This cannot panic because the constants satisfy the documented bounds.
    pub fn secure_defaults() -> Self {
        Self::new(90, 30, 3).expect("constant workflow limits are valid")
    }

    /// Compile-job timeout in minutes.
    pub const fn compile_timeout_minutes(self) -> u16 {
        self.compile_timeout_minutes
    }

    /// Signing-job timeout in minutes.
    pub const fn signing_timeout_minutes(self) -> u16 {
        self.signing_timeout_minutes
    }

    /// Artifact retention in days.
    pub const fn retention_days(self) -> u16 {
        self.retention_days
    }
}

/// Fully validated inputs for the signed physical-iPhone workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowConfig {
    filename: WorkflowFileName,
    protected_environment: ProtectedEnvironment,
    secret_names: SigningSecretNames,
    worker: WorkerDistribution,
    public_source_repository: PublicSourceRepository,
    trusted_source_ref: TrustedSourceRef,
    temporary_branch_namespace: TemporaryBranchNamespace,
    developer_directory: DeveloperDirectory,
    limits: WorkflowLimits,
}

impl WorkflowConfig {
    /// Bind the security-sensitive workflow configuration.
    ///
    /// Push dispatch through the temporary branch namespace is always enabled.
    ///
    /// # Errors
    ///
    /// Rejects a trusted branch that lives inside the temporary job namespace.
    pub fn new(
        filename: WorkflowFileName,
        protected_environment: ProtectedEnvironment,
        secret_names: SigningSecretNames,
        worker: WorkerDistribution,
        public_source_repository: PublicSourceRepository,
        trusted_source_ref: TrustedSourceRef,
        temporary_branch_namespace: TemporaryBranchNamespace,
    ) -> Result<Self, WorkflowConfigError> {
        let temporary_prefix = temporary_branch_namespace.full_ref_prefix();
        let trusted_source = trusted_source_ref.as_str();
        if trusted_source == temporary_prefix
            || trusted_source
                .strip_prefix(&temporary_prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(WorkflowConfigError::RefNamespaceOverlap);
        }
        Ok(Self {
            filename,
            protected_environment,
            secret_names,
            worker,
            public_source_repository,
            trusted_source_ref,
            temporary_branch_namespace,
            developer_directory: DeveloperDirectory::github_default(),
            limits: WorkflowLimits::secure_defaults(),
        })
    }

    /// Select a validated per-job Xcode developer directory.
    #[must_use]
    pub fn with_developer_directory(mut self, developer_directory: DeveloperDirectory) -> Self {
        self.developer_directory = developer_directory;
        self
    }

    /// Apply bounded timeout and retention policy.
    #[must_use]
    pub fn with_limits(mut self, limits: WorkflowLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Generated workflow basename.
    pub fn filename(&self) -> &WorkflowFileName {
        &self.filename
    }

    /// Protected signing environment.
    pub fn protected_environment(&self) -> &ProtectedEnvironment {
        &self.protected_environment
    }

    /// Opaque signing secret reference names.
    pub fn secret_names(&self) -> &SigningSecretNames {
        &self.secret_names
    }

    /// Trusted worker provisioning policy.
    pub fn worker(&self) -> &WorkerDistribution {
        &self.worker
    }

    /// Public GitHub repository containing trusted and requested source.
    pub fn public_source_repository(&self) -> &PublicSourceRepository {
        &self.public_source_repository
    }

    /// Allowlisted source branch or tag.
    pub fn trusted_source_ref(&self) -> &TrustedSourceRef {
        &self.trusted_source_ref
    }

    /// Temporary provider branch namespace.
    pub fn temporary_branch_namespace(&self) -> &TemporaryBranchNamespace {
        &self.temporary_branch_namespace
    }

    /// Per-job Xcode selection.
    pub fn developer_directory(&self) -> &DeveloperDirectory {
        &self.developer_directory
    }

    /// Bounded execution policy.
    pub const fn limits(&self) -> WorkflowLimits {
        self.limits
    }
}

/// Deterministically generated repository-relative path and YAML bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedWorkflow {
    path: String,
    yaml: String,
}

impl GeneratedWorkflow {
    /// Repository-relative `.github/workflows/...` path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Complete UTF-8 YAML document with one trailing newline.
    pub fn yaml(&self) -> &str {
        &self.yaml
    }

    /// Consume the result into its path and YAML.
    pub fn into_parts(self) -> (String, String) {
        (self.path, self.yaml)
    }
}

/// Generate a deterministic GitHub Actions workflow.
///
/// The compile job has no environment and no `secrets` expressions. The sign
/// job receives the bounded exact configured signing-secret set at its worker
/// invocation, after the sealed archive is downloaded and independently
/// hash-checked. It never checks out or builds project source and always
/// invokes worker cleanup.
pub fn generate_workflow(config: &WorkflowConfig) -> GeneratedWorkflow {
    let mut yaml = String::with_capacity(12 * 1024);
    render_header(&mut yaml, config);
    push(&mut yaml, "\njobs:\n");
    if config.worker.source_build().is_some() {
        render_worker_build_job(&mut yaml, config);
    }
    render_compile_job(&mut yaml, config);
    render_sign_job(&mut yaml, config);
    // Source checkout repository insertion is limited to two unique validated
    // paths. `hashFiles` needs doubled quotes inside its YAML scalar.
    let yaml = yaml
        .replace(
            "          path: .rustferry-trusted-source\n",
            &format!(
                "          path: .rustferry-trusted-source\n          repository: '{}'\n",
                config.public_source_repository.slug()
            ),
        )
        .replace(
            "          path: source\n",
            &format!(
                "          path: source\n          repository: '{}'\n",
                config.public_source_repository.slug()
            ),
        )
        .replace(
            "            --workflow-path \"",
            "            --source-repository \"$RUSTFERRY_SOURCE_REPOSITORY\" \\\n            --workflow-path \"",
        )
        .replace(
            "hashFiles('source/Cargo.lock')",
            "hashFiles(''source/Cargo.lock'')",
        )
        .replace(
            "$RUSTFERRY_WORKER_PATH",
            "$RUNNER_TEMP/rustferry-worker-runtime/ferry-worker-macos",
        );
    debug_assert!(yaml.ends_with('\n'));
    GeneratedWorkflow {
        path: config.filename.repository_path(),
        yaml,
    }
}

fn render_header(yaml: &mut String, config: &WorkflowConfig) {
    push(
        yaml,
        "name: RustFerry physical iPhone\n\non:\n  push:\n    branches:\n",
    );
    line(
        yaml,
        format_args!(
            "      - '{}'",
            config.temporary_branch_namespace.trigger_pattern()
        ),
    );
    push(
        yaml,
        "\npermissions: {}\n\nconcurrency:\n  group: 'rustferry-iphone-${{ github.repository_id }}'\n  cancel-in-progress: false\n\nenv:\n",
    );
    line(
        yaml,
        format_args!("  DEVELOPER_DIR: '{}'", config.developer_directory.as_str()),
    );
    push(yaml, "  CARGO_TERM_COLOR: 'never'\n  RUST_BACKTRACE: '0'\n");
    line(yaml, format_args!("  RUSTUP_TOOLCHAIN: '{RUST_TOOLCHAIN}'"));
    match &config.worker.provisioning {
        WorkerProvisioning::Prebuilt {
            download_url,
            sha256,
        } => {
            line(
                yaml,
                format_args!("  RUSTFERRY_WORKER_URL: '{download_url}'"),
            );
            line(yaml, format_args!("  RUSTFERRY_WORKER_SHA256: '{sha256}'"));
        }
        WorkerProvisioning::SourceBuild {
            repository,
            revision,
            ..
        } => {
            line(
                yaml,
                format_args!("  RUSTFERRY_WORKER_REPOSITORY: '{repository}'"),
            );
            line(
                yaml,
                format_args!("  RUSTFERRY_WORKER_REVISION: '{revision}'"),
            );
        }
    }
    line(
        yaml,
        format_args!("  RUSTFERRY_WORKER_VERSION: '{}'", config.worker.version()),
    );
    line(
        yaml,
        format_args!(
            "  RUSTFERRY_SOURCE_REPOSITORY: '{}'",
            config.public_source_repository.url()
        ),
    );
    line(
        yaml,
        format_args!(
            "  RUSTFERRY_TRUSTED_SOURCE_REF: '{}'",
            config.trusted_source_ref.as_str()
        ),
    );
    line(
        yaml,
        format_args!(
            "  RUSTFERRY_TEMPORARY_REF_PREFIX: '{}'",
            config.temporary_branch_namespace.full_ref_prefix()
        ),
    );
    if let Some(digest) = config.secret_names.target_graph_sha256() {
        line(
            yaml,
            format_args!("  RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256: '{digest}'"),
        );
    }
}

fn render_worker_build_job(yaml: &mut String, config: &WorkflowConfig) {
    let (_, repository_slug, revision) = config
        .worker
        .source_build()
        .expect("source-build job requires source provisioning");
    push(
        yaml,
        "  worker:\n    name: Build trusted macOS worker from exact source revision\n",
    );
    line(yaml, format_args!("    runs-on: {DEFAULT_RUNNER}"));
    line(
        yaml,
        format_args!("    timeout-minutes: {DEFAULT_WORKER_BUILD_TIMEOUT_MINUTES}"),
    );
    push(
        yaml,
        "    permissions:\n      contents: read\n    outputs:\n      sha256: '${{ steps.worker.outputs.sha256 }}'\n    env:\n      CARGO_HOME: '${{ github.workspace }}/.rustferry-worker-cargo-home'\n      CARGO_TARGET_DIR: '${{ github.workspace }}/.rustferry-worker-target'\n    steps:\n      - name: Checkout exact trusted worker revision\n        uses: actions/checkout@",
    );
    push(yaml, CHECKOUT_ACTION_SHA);
    push(yaml, " # v7.0.1\n        with:\n          repository: '");
    push(yaml, repository_slug);
    push(yaml, "'\n          ref: '");
    push(yaml, revision);
    push(
        yaml,
        "'\n          fetch-depth: 1\n          persist-credentials: false\n          path: .rustferry-worker-source\n",
    );
    render_toolchain_setup(yaml, 6, false);
    push(
        yaml,
        "      - name: Build only the trusted RustFerry worker binary\n        shell: bash\n        run: |\n          set -euo pipefail\n          source_root=\"$GITHUB_WORKSPACE/.rustferry-worker-source\"\n          actual_revision=\"$(/usr/bin/git -C \"$source_root\" rev-parse --verify 'HEAD^{commit}')\"\n          if [[ \"$actual_revision\" != \"$RUSTFERRY_WORKER_REVISION\" ]]; then\n            echo 'Trusted worker checkout revision mismatch.' >&2\n            exit 1\n          fi\n          cargo build --locked --release \\\n            --manifest-path \"$source_root/Cargo.toml\" \\\n            --package rustferry-worker-macos \\\n            --bin ferry-worker-macos\n      - name: Verify and package trusted RustFerry worker\n        id: worker\n        shell: bash\n        run: |\n          set -euo pipefail\n          candidate=\"$CARGO_TARGET_DIR/release/ferry-worker-macos\"\n          artifact=\"$RUNNER_TEMP/rustferry-worker-artifact/ferry-worker-macos\"\n          test -f \"$candidate\" -a ! -L \"$candidate\"\n          \"$candidate\" version --expect \"$RUSTFERRY_WORKER_VERSION\"\n          install -d -m 0700 \"$(dirname \"$artifact\")\"\n          install -m 0500 \"$candidate\" \"$artifact\"\n          actual=\"$(shasum -a 256 \"$artifact\" | awk '{print $1}')\"\n          [[ \"$actual\" =~ ^[0-9a-f]{64}$ ]]\n          \"$artifact\" version --expect \"$RUSTFERRY_WORKER_VERSION\"\n          printf 'sha256=%s\\n' \"$actual\" >> \"$GITHUB_OUTPUT\"\n      - name: Upload immutable trusted worker artifact\n        uses: actions/upload-artifact@",
    );
    push(yaml, UPLOAD_ARTIFACT_ACTION_SHA);
    push(
        yaml,
        " # v7\n        with:\n          name: 'rustferry-worker-${{ github.run_id }}-${{ github.run_attempt }}'\n          path: '${{ runner.temp }}/rustferry-worker-artifact/ferry-worker-macos'\n          if-no-files-found: error\n          compression-level: 0\n",
    );
    line(
        yaml,
        format_args!(
            "          retention-days: {}",
            config.limits.retention_days()
        ),
    );
    push(yaml, "\n");
}

fn render_compile_job(yaml: &mut String, config: &WorkflowConfig) {
    push(
        yaml,
        "  compile:\n    name: Phase A - compile without signing secrets\n",
    );
    if config.worker.source_build().is_some() {
        push(yaml, "    needs: worker\n");
    }
    line(yaml, format_args!("    runs-on: {DEFAULT_RUNNER}"));
    line(
        yaml,
        format_args!(
            "    timeout-minutes: {}",
            config.limits.compile_timeout_minutes()
        ),
    );
    push(yaml, "    permissions:\n");
    if config.worker.source_build().is_some() {
        push(yaml, "      actions: read\n");
    }
    push(
        yaml,
        "      contents: read\n    outputs:\n      operation_id: '${{ steps.request.outputs.operation_id }}'\n      project_path: '${{ steps.request.outputs.project_path }}'\n      sealed_sha256: '${{ steps.sealed.outputs.sha256 }}'\n      signing_mode: '${{ steps.request.outputs.signing_mode }}'\n      source_revision: '${{ steps.request.outputs.source_revision }}'\n    env:\n      CARGO_HOME: '${{ github.workspace }}/.rustferry-cargo-home'\n      CARGO_TARGET_DIR: '${{ github.workspace }}/.rustferry-cargo-target'\n    steps:\n",
    );
    render_worker_install(yaml, config, 6);
    render_toolchain_setup(yaml, 6, true);
    push(
        yaml,
        "      - name: Checkout immutable dispatch request\n        uses: actions/checkout@",
    );
    push(yaml, CHECKOUT_ACTION_SHA);
    push(
        yaml,
        " # v7.0.1\n        with:\n          ref: '${{ github.sha }}'\n          fetch-depth: 1\n          persist-credentials: false\n          path: .rustferry-dispatch\n      - name: Checkout trusted source policy ref\n        uses: actions/checkout@",
    );
    push(yaml, CHECKOUT_ACTION_SHA);
    push(
        yaml,
        " # v7.0.1\n        with:\n          ref: '${{ env.RUSTFERRY_TRUSTED_SOURCE_REF }}'\n          fetch-depth: 0\n          persist-credentials: false\n          path: .rustferry-trusted-source\n      - name: Validate dispatch request and workflow revision\n        id: request\n        shell: bash\n        run: |\n          set -euo pipefail\n          \"$RUSTFERRY_WORKER_PATH\" github-request \\\n            --event \"$GITHUB_EVENT_PATH\" \\\n            --dispatch-root \"$GITHUB_WORKSPACE/.rustferry-dispatch\" \\\n            --trusted-source-root \"$GITHUB_WORKSPACE/.rustferry-trusted-source\" \\\n            --workflow-path \"",
    );
    push(yaml, &config.filename.repository_path());
    push(
        yaml,
        "\" \\\n            --push-manifest \"$GITHUB_WORKSPACE/.rustferry-dispatch/",
    );
    push(yaml, REQUEST_MANIFEST_PATH);
    push(
        yaml,
        "\" \\\n            --trusted-source-ref \"$RUSTFERRY_TRUSTED_SOURCE_REF\" \\\n            --temporary-ref-prefix \"$RUSTFERRY_TEMPORARY_REF_PREFIX\"",
    );
    if config.secret_names.target_graph_sha256().is_some() {
        push(
            yaml,
            " \\\n            --expected-signing-target-graph-sha256 \"$RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256\"",
        );
    }
    push(
        yaml,
        " \\\n            --output-manifest \"$RUNNER_TEMP/rustferry-request.json\" \\\n            --github-output \"$GITHUB_OUTPUT\"\n      - name: Checkout exact requested source revision\n        uses: actions/checkout@",
    );
    push(yaml, CHECKOUT_ACTION_SHA);
    push(
        yaml,
        " # v7.0.1\n        with:\n          ref: '${{ steps.request.outputs.source_revision }}'\n          fetch-depth: 1\n          persist-credentials: false\n          path: source\n      - name: Restore source-revision-scoped Cargo cache\n        uses: actions/cache@",
    );
    push(yaml, CACHE_ACTION_SHA);
    push(
        yaml,
        " # v5\n        with:\n          path: |\n            ${{ env.CARGO_HOME }}/registry/index\n            ${{ env.CARGO_HOME }}/registry/cache\n            ${{ env.CARGO_HOME }}/git/db\n            ${{ env.CARGO_TARGET_DIR }}\n          key: 'rustferry-ios-${{ runner.os }}-",
    );
    push(yaml, config.worker.version());
    push(
        yaml,
        "-${{ steps.request.outputs.source_revision }}-${{ hashFiles('source/Cargo.lock') }}'\n      - name: Compile and seal unsigned iPhone archive with worker\n        shell: bash\n        env:\n          RUSTFERRY_OPERATION_ID: '${{ steps.request.outputs.operation_id }}'\n          RUSTFERRY_PROJECT_PATH: '${{ steps.request.outputs.project_path }}'\n          RUSTFERRY_SOURCE_REVISION: '${{ steps.request.outputs.source_revision }}'\n        run: |\n          set -euo pipefail\n          \"$RUSTFERRY_WORKER_PATH\" run-job \\\n            --phase compile \\\n            --manifest \"$RUNNER_TEMP/rustferry-request.json\" \\\n            --source-root \"$GITHUB_WORKSPACE/source\" \\\n            --trusted-source-root \"$GITHUB_WORKSPACE/.rustferry-trusted-source\" \\\n            --job-root \"$RUNNER_TEMP/rustferry-compile-job\" \\\n            --output-directory \"$RUNNER_TEMP/rustferry-handoff\"\n      - name: Record sealed archive digest\n        id: sealed\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive=\"$RUNNER_TEMP/rustferry-handoff/unsigned-archive.zip\"\n          test -f \"$archive\" -a ! -L \"$archive\"\n          digest=\"$(shasum -a 256 \"$archive\" | awk '{print $1}')\"\n          [[ \"$digest\" =~ ^[0-9a-f]{64}$ ]]\n          printf 'sha256=%s\\n' \"$digest\" >> \"$GITHUB_OUTPUT\"\n      - name: Upload sealed unsigned handoff\n        id: unsigned_artifact\n        uses: actions/upload-artifact@",
    );
    push(yaml, UPLOAD_ARTIFACT_ACTION_SHA);
    push(
        yaml,
        " # v7\n        with:\n          name: 'rustferry-unsigned-${{ github.run_id }}-${{ github.run_attempt }}'\n          path: |\n            ${{ runner.temp }}/rustferry-handoff/unsigned-archive.zip\n            ${{ runner.temp }}/rustferry-handoff/sealed-archive.json\n            ${{ runner.temp }}/rustferry-handoff/compile-report.json\n            ${{ runner.temp }}/rustferry-handoff/sanitized-compile-log.txt\n          if-no-files-found: error\n          compression-level: 0\n",
    );
    line(
        yaml,
        format_args!(
            "          retention-days: {}",
            config.limits.retention_days()
        ),
    );
    push(
        yaml,
        "      - name: Clean compile job workspace\n        if: '${{ always() }}'\n        shell: bash\n        run: |\n          set -euo pipefail\n          if [[ -x \"$RUSTFERRY_WORKER_PATH\" ]]; then\n            \"$RUSTFERRY_WORKER_PATH\" cleanup \\\n              --job-root \"$RUNNER_TEMP/rustferry-compile-job\" \\\n              --require-complete\n          elif [[ -d \"$RUNNER_TEMP/rustferry-compile-job\" ]]; then\n            echo 'Compile cleanup could not run because the trusted worker is unavailable.' >&2\n            exit 1\n          fi\n",
    );
}

#[allow(clippy::too_many_lines)]
fn render_sign_job(yaml: &mut String, config: &WorkflowConfig) {
    push(
        yaml,
        "\n  sign:\n    name: Phase B - protected development signing\n",
    );
    if config.worker.source_build().is_some() {
        push(yaml, "    needs:\n      - worker\n      - compile\n");
    } else {
        push(yaml, "    needs: compile\n");
    }
    push(
        yaml,
        "    if: needs.compile.outputs.signing_mode == 'manual_development' && github.event.repository.private == true\n",
    );
    line(yaml, format_args!("    runs-on: {DEFAULT_RUNNER}"));
    line(
        yaml,
        format_args!(
            "    timeout-minutes: {}",
            config.limits.signing_timeout_minutes()
        ),
    );
    push(yaml, "    environment: '");
    push(yaml, config.protected_environment.as_str());
    push(
        yaml,
        "'\n    permissions:\n      actions: read\n    steps:\n",
    );
    render_worker_install(yaml, config, 6);
    render_toolchain_setup(yaml, 6, true);
    push(
        yaml,
        "      - name: Download exact sealed unsigned handoff\n        uses: actions/download-artifact@",
    );
    push(yaml, DOWNLOAD_ARTIFACT_ACTION_SHA);
    push(
        yaml,
        " # v8\n        with:\n          name: 'rustferry-unsigned-${{ github.run_id }}-${{ github.run_attempt }}'\n          path: '${{ runner.temp }}/rustferry-handoff'\n      - name: Verify sealed handoff digest before signing\n        shell: bash\n        env:\n          RUSTFERRY_EXPECTED_SHA256: '${{ needs.compile.outputs.sealed_sha256 }}'\n        run: |\n          set -euo pipefail\n          archive=\"$RUNNER_TEMP/rustferry-handoff/unsigned-archive.zip\"\n          [[ \"$RUSTFERRY_EXPECTED_SHA256\" =~ ^[0-9a-f]{64}$ ]]\n          test -f \"$archive\" -a ! -L \"$archive\"\n          actual=\"$(shasum -a 256 \"$archive\" | awk '{print $1}')\"\n          if [[ \"$actual\" != \"$RUSTFERRY_EXPECTED_SHA256\" ]]; then\n            echo 'Sealed unsigned archive failed integrity verification.' >&2\n            exit 1\n          fi\n      - name: Sign, export, and independently validate IPA with worker\n        id: signed\n        shell: bash\n        env:\n",
    );
    line(
        yaml,
        format_args!(
            "          RUSTFERRY_SIGNING_CERTIFICATE_P12: '${{{{ secrets.{} }}}}'",
            config.secret_names.certificate_p12.as_str()
        ),
    );
    line(
        yaml,
        format_args!(
            "          RUSTFERRY_SIGNING_CERTIFICATE_PASSWORD: '${{{{ secrets.{} }}}}'",
            config.secret_names.certificate_password.as_str()
        ),
    );
    let profile_names = config.secret_names.profile_names().collect::<Vec<_>>();
    if profile_names.len() == 1 {
        line(
            yaml,
            format_args!(
                "          RUSTFERRY_SIGNING_PROVISIONING_PROFILE: '${{{{ secrets.{} }}}}'",
                config.secret_names.provisioning_profile().as_str()
            ),
        );
    } else {
        for (index, profile) in profile_names.iter().enumerate() {
            line(
                yaml,
                format_args!(
                    "          RUSTFERRY_SIGNING_PROVISIONING_PROFILE_{}: '${{{{ secrets.{} }}}}'",
                    index + 1,
                    profile.as_str()
                ),
            );
        }
    }
    push(
        yaml,
        "          RUSTFERRY_EXPECTED_SHA256: '${{ needs.compile.outputs.sealed_sha256 }}'\n          RUSTFERRY_OPERATION_ID: '${{ needs.compile.outputs.operation_id }}'\n          RUSTFERRY_SOURCE_REVISION: '${{ needs.compile.outputs.source_revision }}'\n",
    );
    if profile_names.len() == 1 {
        push(
            yaml,
            "        run: |\n          set -euo pipefail\n          printf '%s\\0%s\\0%s' \\\n            \"$RUSTFERRY_SIGNING_CERTIFICATE_P12\" \\\n            \"$RUSTFERRY_SIGNING_CERTIFICATE_PASSWORD\" \\\n            \"$RUSTFERRY_SIGNING_PROVISIONING_PROFILE\" |\n",
        );
    } else {
        render_v2_signing_frame(yaml, config, &profile_names);
    }
    push(
        yaml,
        "            /usr/bin/env -i \\\n              \"DEVELOPER_DIR=$DEVELOPER_DIR\" \\\n              \"HOME=$HOME\" \\\n              'LC_ALL=C' \\\n              \"PATH=$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin\" \\\n              \"RUSTFERRY_WORKER_ROOT=$RUNNER_TEMP\" \\\n              \"RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN\" \\\n              \"TMPDIR=$RUNNER_TEMP\" \\\n              \"$RUSTFERRY_WORKER_PATH\" run-job \\\n                --phase sign \\\n                --sealed-directory \"$RUNNER_TEMP/rustferry-handoff\" \\\n                --expected-sealed-sha256 \"$RUSTFERRY_EXPECTED_SHA256\" \\\n                --source-revision \"$RUSTFERRY_SOURCE_REVISION\" \\\n                --operation-id \"$RUSTFERRY_OPERATION_ID\" \\\n                --job-root \"$RUNNER_TEMP/rustferry-sign-job\" \\\n                --output-directory \"$RUNNER_TEMP/rustferry-signed\" \\\n",
    );
    line(
        yaml,
        format_args!(
            "                --certificate-p12-reference '{}' \\",
            config.secret_names.certificate_p12.as_str()
        ),
    );
    line(
        yaml,
        format_args!(
            "                --certificate-password-reference '{}' \\",
            config.secret_names.certificate_password.as_str()
        ),
    );
    for (index, profile) in profile_names.iter().enumerate() {
        let continuation = if index + 1 == profile_names.len() {
            ""
        } else {
            " \\"
        };
        line(
            yaml,
            format_args!(
                "                --provisioning-profile-reference '{}'{}",
                profile.as_str(),
                continuation
            ),
        );
    }
    push(
        yaml,
        "      - name: Remove signing material and temporary keychain\n        if: '${{ always() }}'\n        shell: bash\n        run: |\n          set -euo pipefail\n          if [[ -x \"$RUSTFERRY_WORKER_PATH\" ]]; then\n            \"$RUSTFERRY_WORKER_PATH\" cleanup \\\n              --job-root \"$RUNNER_TEMP/rustferry-sign-job\" \\\n              --require-complete\n          elif [[ -d \"$RUNNER_TEMP/rustferry-sign-job\" ]]; then\n            echo 'Signing cleanup could not run because the trusted worker is unavailable.' >&2\n            exit 1\n          fi\n      - name: Upload validated development IPA\n        if: '${{ success() }}'\n        uses: actions/upload-artifact@",
    );
    push(yaml, UPLOAD_ARTIFACT_ACTION_SHA);
    push(
        yaml,
        " # v7\n        with:\n          name: 'rustferry-iphone-${{ github.run_id }}-${{ github.run_attempt }}'\n          path: |\n            ${{ runner.temp }}/rustferry-signed/application-development.ipa\n            ${{ runner.temp }}/rustferry-signed/artifact-manifest.json\n            ${{ runner.temp }}/rustferry-signed/signing-report.json\n            ${{ runner.temp }}/rustferry-signed/validation-report.json\n          if-no-files-found: error\n          compression-level: 0\n",
    );
    line(
        yaml,
        format_args!(
            "          retention-days: {}",
            config.limits.retention_days()
        ),
    );
}

fn render_v2_signing_frame(
    yaml: &mut String,
    config: &WorkflowConfig,
    profile_names: &[&SecretName],
) {
    push(
        yaml,
        "        run: |\n          set -euo pipefail\n          export LC_ALL=C\n          write_u16_be() {\n            local value=\"$1\"\n            printf '%b' \"$(printf '\\\\%03o\\\\%03o' \\\n              \"$(((value >> 8) & 255))\" \"$((value & 255))\")\"\n          }\n          write_u32_be() {\n            local value=\"$1\"\n            printf '%b' \"$(printf '\\\\%03o\\\\%03o\\\\%03o\\\\%03o' \\\n              \"$(((value >> 24) & 255))\" \"$(((value >> 16) & 255))\" \\\n              \"$(((value >> 8) & 255))\" \"$((value & 255))\")\"\n          }\n          write_record() {\n            local reference=\"$1\"\n            local secret_value=\"$2\"\n            write_u16_be \"${#reference}\"\n            write_u32_be \"${#secret_value}\"\n            printf '%s%s' \"$reference\" \"$secret_value\"\n          }\n          {\n            printf 'RFSIGNV2'\n",
    );
    line(
        yaml,
        format_args!("            write_u32_be '{}'", profile_names.len() + 2),
    );
    line(
        yaml,
        format_args!(
            "            write_record '{}' \"$RUSTFERRY_SIGNING_CERTIFICATE_P12\"",
            config.secret_names.certificate_p12.as_str()
        ),
    );
    line(
        yaml,
        format_args!(
            "            write_record '{}' \"$RUSTFERRY_SIGNING_CERTIFICATE_PASSWORD\"",
            config.secret_names.certificate_password.as_str()
        ),
    );
    for (index, profile) in profile_names.iter().enumerate() {
        line(
            yaml,
            format_args!(
                "            write_record '{}' \"$RUSTFERRY_SIGNING_PROVISIONING_PROFILE_{}\"",
                profile.as_str(),
                index + 1
            ),
        );
    }
    push(yaml, "          } |\n");
}

fn render_worker_install(yaml: &mut String, config: &WorkflowConfig, indentation: usize) {
    match &config.worker.provisioning {
        WorkerProvisioning::Prebuilt { .. } => render_prebuilt_worker_install(yaml, indentation),
        WorkerProvisioning::SourceBuild { .. } => {
            render_source_worker_install(yaml, indentation);
        }
    }
}

fn render_prebuilt_worker_install(yaml: &mut String, indentation: usize) {
    let spaces = " ".repeat(indentation);
    line(
        yaml,
        format_args!("{spaces}- name: Install hash-pinned RustFerry worker"),
    );
    line(yaml, format_args!("{spaces}  shell: bash"));
    line(yaml, format_args!("{spaces}  run: |"));
    line(yaml, format_args!("{spaces}    set -euo pipefail"));
    line(
        yaml,
        format_args!("{spaces}    install -d -m 0700 \"$(dirname \"$RUSTFERRY_WORKER_PATH\")\""),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --silent --show-error \\\n{spaces}      \"$RUSTFERRY_WORKER_URL\" --output \"$RUSTFERRY_WORKER_PATH\""
        ),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    actual=\"$(shasum -a 256 \"$RUSTFERRY_WORKER_PATH\" | awk '{{print $1}}')\""
        ),
    );
    line(
        yaml,
        format_args!("{spaces}    if [[ \"$actual\" != \"$RUSTFERRY_WORKER_SHA256\" ]]; then"),
    );
    line(
        yaml,
        format_args!("{spaces}      echo 'RustFerry worker integrity check failed.' >&2"),
    );
    line(yaml, format_args!("{spaces}      exit 1"));
    line(yaml, format_args!("{spaces}    fi"));
    line(
        yaml,
        format_args!("{spaces}    chmod 0500 \"$RUSTFERRY_WORKER_PATH\""),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    \"$RUSTFERRY_WORKER_PATH\" version --expect \"$RUSTFERRY_WORKER_VERSION\""
        ),
    );
}

fn render_source_worker_install(yaml: &mut String, indentation: usize) {
    let spaces = " ".repeat(indentation);
    line(
        yaml,
        format_args!("{spaces}- name: Download exact trusted worker artifact"),
    );
    line(
        yaml,
        format_args!(
            "{spaces}  uses: actions/download-artifact@{DOWNLOAD_ARTIFACT_ACTION_SHA} # v8"
        ),
    );
    line(yaml, format_args!("{spaces}  with:"));
    line(
        yaml,
        format_args!(
            "{spaces}    name: 'rustferry-worker-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}'"
        ),
    );
    line(
        yaml,
        format_args!("{spaces}    path: '${{{{ runner.temp }}}}/rustferry-worker-download'"),
    );
    line(
        yaml,
        format_args!("{spaces}- name: Verify exact trusted worker artifact"),
    );
    line(yaml, format_args!("{spaces}  shell: bash"));
    line(yaml, format_args!("{spaces}  env:"));
    line(
        yaml,
        format_args!(
            "{spaces}    RUSTFERRY_EXPECTED_WORKER_SHA256: '${{{{ needs.worker.outputs.sha256 }}}}'"
        ),
    );
    line(yaml, format_args!("{spaces}  run: |"));
    line(yaml, format_args!("{spaces}    set -euo pipefail"));
    line(
        yaml,
        format_args!(
            "{spaces}    candidate=\"$RUNNER_TEMP/rustferry-worker-download/ferry-worker-macos\""
        ),
    );
    line(
        yaml,
        format_args!("{spaces}    [[ \"$RUSTFERRY_EXPECTED_WORKER_SHA256\" =~ ^[0-9a-f]{{64}}$ ]]"),
    );
    line(
        yaml,
        format_args!("{spaces}    test -f \"$candidate\" -a ! -L \"$candidate\""),
    );
    line(
        yaml,
        format_args!("{spaces}    actual=\"$(shasum -a 256 \"$candidate\" | awk '{{print $1}}')\""),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    if [[ \"$actual\" != \"$RUSTFERRY_EXPECTED_WORKER_SHA256\" ]]; then"
        ),
    );
    line(
        yaml,
        format_args!("{spaces}      echo 'Trusted worker artifact integrity check failed.' >&2"),
    );
    line(yaml, format_args!("{spaces}      exit 1"));
    line(yaml, format_args!("{spaces}    fi"));
    line(
        yaml,
        format_args!("{spaces}    install -d -m 0700 \"$(dirname \"$RUSTFERRY_WORKER_PATH\")\""),
    );
    line(
        yaml,
        format_args!("{spaces}    install -m 0500 \"$candidate\" \"$RUSTFERRY_WORKER_PATH\""),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    installed=\"$(shasum -a 256 \"$RUSTFERRY_WORKER_PATH\" | awk '{{print $1}}')\""
        ),
    );
    line(
        yaml,
        format_args!("{spaces}    [[ \"$installed\" == \"$RUSTFERRY_EXPECTED_WORKER_SHA256\" ]]"),
    );
    line(
        yaml,
        format_args!(
            "{spaces}    \"$RUSTFERRY_WORKER_PATH\" version --expect \"$RUSTFERRY_WORKER_VERSION\""
        ),
    );
}

fn render_toolchain_setup(yaml: &mut String, indentation: usize, install_ios_target: bool) {
    let spaces = " ".repeat(indentation);
    let name = if install_ios_target {
        "Install exact Rust toolchain and physical-iPhone target"
    } else {
        "Install exact Rust toolchain"
    };
    line(yaml, format_args!("{spaces}- name: {name}"));
    line(yaml, format_args!("{spaces}  shell: bash"));
    line(yaml, format_args!("{spaces}  run: |"));
    line(yaml, format_args!("{spaces}    set -euo pipefail"));
    line(
        yaml,
        format_args!(
            "{spaces}    rustup toolchain install \"$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update"
        ),
    );
    if install_ios_target {
        line(
            yaml,
            format_args!(
                "{spaces}    rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios"
            ),
        );
    }
    line(
        yaml,
        format_args!("{spaces}    actual=\"$(rustup run \"$RUSTUP_TOOLCHAIN\" rustc --version)\""),
    );
    line(
        yaml,
        format_args!("{spaces}    [[ \"$actual\" == \"rustc {RUST_TOOLCHAIN} \"* ]]"),
    );
}

fn push(output: &mut String, value: &str) {
    output.push_str(value);
}

fn line(output: &mut String, arguments: fmt::Arguments<'_>) {
    writeln!(output, "{arguments}").expect("writing to a String cannot fail");
}

fn validate_nonempty_length(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), WorkflowConfigError> {
    if value.is_empty() {
        return Err(WorkflowConfigError::Empty { field });
    }
    if value.len() > maximum {
        return Err(WorkflowConfigError::TooLong { field, maximum });
    }
    Ok(())
}

fn validate_ascii_allowlist(
    field: &'static str,
    value: &str,
    allowed: impl Fn(u8) -> bool,
) -> Result<(), WorkflowConfigError> {
    if let Some(index) = value.bytes().position(|byte| !allowed(byte)) {
        return Err(WorkflowConfigError::InvalidCharacter { field, index });
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    maximum: usize,
    punctuation: &[u8],
) -> Result<(), WorkflowConfigError> {
    validate_nonempty_length(field, value, maximum)?;
    if !value.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    validate_ascii_allowlist(field, value, |byte| {
        byte.is_ascii_alphanumeric() || punctuation.contains(&byte)
    })
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_ref_tail(field: &'static str, tail: &str) -> Result<(), WorkflowConfigError> {
    validate_nonempty_length(field, tail, 255)?;
    validate_ascii_allowlist(field, tail, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
    })?;
    if tail.starts_with('/')
        || tail.ends_with('/')
        || tail.ends_with('.')
        || tail.ends_with(".lock")
        || tail.contains("..")
        || tail.contains("//")
        || tail.split('/').any(str::is_empty)
    {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    Ok(())
}

fn validate_worker_url(value: &str) -> Result<(), WorkflowConfigError> {
    validate_nonempty_length("worker download URL", value, 512)?;
    let path =
        value
            .strip_prefix("https://github.com/")
            .ok_or(WorkflowConfigError::InvalidFormat {
                field: "worker download URL",
            })?;
    validate_ascii_allowlist("worker download URL", path, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
    })?;
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() != 6
        || segments.iter().any(|segment| segment.is_empty())
        || segments[2] != "releases"
        || segments[3] != "download"
        || segments
            .iter()
            .any(|segment| matches!(*segment, "." | ".."))
    {
        return Err(WorkflowConfigError::InvalidFormat {
            field: "worker download URL",
        });
    }
    Ok(())
}

fn normalize_github_repository(
    field: &'static str,
    value: &str,
) -> Result<(String, String), WorkflowConfigError> {
    validate_nonempty_length(field, value, 256)?;
    let path = value.strip_prefix("https://github.com/").unwrap_or(value);
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    validate_ascii_allowlist(field, path, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
    })?;
    let mut segments = path.split('/');
    let owner = segments.next().unwrap_or_default();
    let repository = segments.next().unwrap_or_default();
    if segments.next().is_some()
        || owner.is_empty()
        || repository.is_empty()
        || owner.len() > 39
        || repository.len() > 100
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !owner.as_bytes()[0].is_ascii_alphanumeric()
        || !owner.as_bytes()[owner.len() - 1].is_ascii_alphanumeric()
        || !repository.as_bytes()[0].is_ascii_alphanumeric()
        || matches!(repository, "." | "..")
    {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    let slug = format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase()
    );
    Ok((format!("https://github.com/{slug}"), slug))
}

fn validate_commit_sha(field: &'static str, value: &str) -> Result<(), WorkflowConfigError> {
    if value.len() != 40 {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    validate_ascii_allowlist(field, value, |byte| {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    })
}

fn validate_semver(field: &'static str, value: &str) -> Result<(), WorkflowConfigError> {
    validate_nonempty_length(field, value, 64)?;
    let parsed =
        semver::Version::parse(value).map_err(|_| WorkflowConfigError::InvalidFormat { field })?;
    if parsed.to_string() != value {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), WorkflowConfigError> {
    if value.len() != 64 {
        return Err(WorkflowConfigError::InvalidFormat { field });
    }
    validate_ascii_allowlist(field, value, |byte| {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    })
}

fn validate_policy(
    field: &'static str,
    value: u16,
    minimum: u16,
    maximum: u16,
) -> Result<(), WorkflowConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(WorkflowConfigError::PolicyOutOfRange {
            field,
            minimum,
            maximum,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustferry_remote::BundleIdentifier;

    const WORKER_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const WORKER_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn fixture_public_source() -> PublicSourceRepository {
        PublicSourceRepository::new("https://github.com/ShiroKSH/RustFerry.git/").unwrap()
    }

    fn signing_target(
        name: &str,
        bundle_identifier: &str,
        kind: SigningTargetKind,
    ) -> SigningTarget {
        SigningTarget {
            name: name.to_owned(),
            bundle_identifier: BundleIdentifier::new(bundle_identifier).expect("bundle identifier"),
            kind,
        }
    }

    fn fixture_config() -> WorkflowConfig {
        WorkflowConfig::new(
            WorkflowFileName::new("rustferry-goal3-iphone.yml").unwrap(),
            ProtectedEnvironment::new("rustferry-goal3-signing").unwrap(),
            SigningSecretNames::goal3_defaults(),
            WorkerDistribution::new(
                "https://github.com/ShiroKSH/rustferry/releases/download/v0.1.0/ferry-worker-macos",
                WORKER_SHA256,
                "0.1.0",
            )
            .unwrap(),
            fixture_public_source(),
            TrustedSourceRef::new("refs/heads/goal3/macless-iphone-builds").unwrap(),
            TemporaryBranchNamespace::new("rustferry/goal3/builds").unwrap(),
        )
        .unwrap()
    }

    fn fixture_multi_profile_config() -> WorkflowConfig {
        let mut config = fixture_config();
        config.secret_names = SigningSecretNames::for_targets(&[
            signing_target(
                "RuntimeBridge",
                "com.example.weather.runtime-bridge",
                SigningTargetKind::Framework,
            ),
            signing_target(
                "Weather",
                "com.example.weather",
                SigningTargetKind::Application,
            ),
            signing_target(
                "WeatherWidget",
                "com.example.weather.widget",
                SigningTargetKind::Extension,
            ),
        ])
        .expect("multi-profile secret names");
        config
    }

    fn fixture_modern_app_only_config() -> WorkflowConfig {
        let mut config = fixture_config();
        config.secret_names = SigningSecretNames::for_targets(&[signing_target(
            "App",
            "com.example.app",
            SigningTargetKind::Application,
        )])
        .expect("app-only target graph");
        config
    }

    fn fixture_source_config() -> WorkflowConfig {
        WorkflowConfig::new(
            WorkflowFileName::new("rustferry-goal3-iphone.yml").unwrap(),
            ProtectedEnvironment::new("rustferry-goal3-signing").unwrap(),
            SigningSecretNames::goal3_defaults(),
            WorkerDistribution::from_source(
                "https://github.com/ShiroKSH/RustFerry.git/",
                WORKER_REVISION,
                "0.1.0",
            )
            .unwrap(),
            fixture_public_source(),
            TrustedSourceRef::new("refs/heads/goal3/macless-iphone-builds").unwrap(),
            TemporaryBranchNamespace::new("rustferry/goal3/builds").unwrap(),
        )
        .unwrap()
    }

    fn fixture_split_config() -> WorkflowConfig {
        let mut config = fixture_source_config();
        config.public_source_repository =
            PublicSourceRepository::new("Public-Org/Public-App").unwrap();
        config
    }

    #[test]
    fn deterministic_workflow_snapshot() {
        let first = generate_workflow(&fixture_config());
        let second = generate_workflow(&fixture_config());

        assert_eq!(first, second);
        assert_eq!(first.path(), ".github/workflows/rustferry-goal3-iphone.yml");
        assert_eq!(first.yaml().lines().count(), 276);
        assert_eq!(fnv1a64(first.yaml().as_bytes()), 0x5bb3_46e9_17ce_aa34);
    }

    #[test]
    fn deterministic_source_build_workflow_snapshot() {
        let first = generate_workflow(&fixture_source_config());
        let second = generate_workflow(&fixture_source_config());

        assert_eq!(first, second);
        assert_eq!(first.yaml().lines().count(), 365);
        assert_eq!(fnv1a64(first.yaml().as_bytes()), 0xab21_75f0_7c0a_bc44);
    }

    #[test]
    fn source_distribution_normalizes_and_binds_trust_inputs() {
        let worker = fixture_source_config().worker().clone();

        assert_eq!(
            worker.source_repository(),
            Some("https://github.com/shiroksh/rustferry")
        );
        assert_eq!(worker.source_revision(), Some(WORKER_REVISION));
        assert_eq!(worker.version(), "0.1.0");
        assert!(worker.is_source_build());
    }

    #[test]
    fn public_source_repository_normalizes_and_rejects_ambiguous_inputs() {
        let repository =
            PublicSourceRepository::new("https://github.com/Public-Org/Public-App.git/").unwrap();

        assert_eq!(repository.url(), "https://github.com/public-org/public-app");
        assert_eq!(repository.slug(), "public-org/public-app");

        for rejected in [
            "https://example.com/public-org/public-app",
            "https://github.com/public-org/public-app/extra",
            "https://github.com/public-org/public-app?private=true",
            "git@github.com:public-org/public-app.git",
            "${{ github.repository }}",
        ] {
            assert!(
                PublicSourceRepository::new(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    #[test]
    fn split_repository_workflow_keeps_execution_implicit_and_source_explicit() {
        let workflow = generate_workflow(&fixture_split_config());
        let yaml = workflow.yaml();
        let dispatch = yaml
            .split_once("      - name: Checkout immutable dispatch request\n")
            .unwrap()
            .1
            .split_once("      - name: Checkout trusted source policy ref\n")
            .unwrap()
            .0;
        let trusted = yaml
            .split_once("      - name: Checkout trusted source policy ref\n")
            .unwrap()
            .1
            .split_once("      - name: Validate dispatch request and workflow revision\n")
            .unwrap()
            .0;
        let requested = yaml
            .split_once("      - name: Checkout exact requested source revision\n")
            .unwrap()
            .1
            .split_once("      - name: Restore source-revision-scoped Cargo cache\n")
            .unwrap()
            .0;

        assert!(
            yaml.contains(
                "RUSTFERRY_SOURCE_REPOSITORY: 'https://github.com/public-org/public-app'"
            )
        );
        assert!(yaml.contains("--source-repository \"$RUSTFERRY_SOURCE_REPOSITORY\""));
        assert!(!yaml.contains("private-org/private-execution"));

        assert!(dispatch.contains("ref: '${{ github.sha }}'"));
        assert!(dispatch.contains("persist-credentials: false"));
        assert!(!dispatch.contains("repository:"));

        for source_checkout in [trusted, requested] {
            assert!(source_checkout.contains("repository: 'public-org/public-app'"));
            assert!(source_checkout.contains("persist-credentials: false"));
        }
        assert!(trusted.contains("ref: '${{ env.RUSTFERRY_TRUSTED_SOURCE_REF }}'"));
        assert!(requested.contains("ref: '${{ steps.request.outputs.source_revision }}'"));
    }

    #[test]
    fn same_repository_mode_keeps_dispatch_implicit_and_source_exact() {
        let workflow = generate_workflow(&fixture_config());
        let yaml = workflow.yaml();
        let dispatch = yaml
            .split_once("      - name: Checkout immutable dispatch request\n")
            .unwrap()
            .1
            .split_once("      - name: Checkout trusted source policy ref\n")
            .unwrap()
            .0;

        assert!(!dispatch.contains("repository:"));
        assert_eq!(yaml.matches("repository: 'shiroksh/rustferry'").count(), 2);
        assert!(yaml.contains("ref: '${{ env.RUSTFERRY_TRUSTED_SOURCE_REF }}'"));
        assert!(yaml.contains("ref: '${{ steps.request.outputs.source_revision }}'"));
    }

    #[test]
    fn source_distribution_rejects_mutable_or_ambiguous_inputs() {
        for repository in [
            "https://example.com/owner/repository",
            "https://github.com/owner/repository/extra",
            "https://github.com/owner/repository?ref=main",
            "git@github.com:owner/repository.git",
        ] {
            assert!(
                WorkerDistribution::from_source(repository, WORKER_REVISION, "0.1.0").is_err(),
                "accepted {repository}"
            );
        }
        for revision in [
            "main",
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(
                WorkerDistribution::from_source("owner/repository", revision, "0.1.0").is_err(),
                "accepted {revision}"
            );
        }
        for version in ["v0.1.0", "0.1", "01.2.3", "0.1.0_"] {
            assert!(
                WorkerDistribution::from_source("owner/repository", WORKER_REVISION, version)
                    .is_err(),
                "accepted {version}"
            );
        }
    }

    #[test]
    fn source_built_worker_is_isolated_and_hash_propagated() {
        let workflow = generate_workflow(&fixture_source_config());
        let (_, worker_and_later) = workflow.yaml().split_once("\n  worker:\n").unwrap();
        let (worker, compile_and_sign) = worker_and_later.split_once("\n  compile:\n").unwrap();
        let (compile, sign) = compile_and_sign.split_once("\n  sign:\n").unwrap();

        assert!(!worker.contains("secrets."));
        assert!(!worker.contains("environment:"));
        assert!(worker.contains("permissions:\n      contents: read"));
        assert!(worker.contains("repository: 'shiroksh/rustferry'"));
        assert!(worker.contains(&format!("ref: '{WORKER_REVISION}'")));
        assert!(worker.contains("cargo build --locked --release"));
        assert!(worker.contains("--package rustferry-worker-macos"));
        assert!(worker.contains("--bin ferry-worker-macos"));
        assert!(worker.contains("version --expect \"$RUSTFERRY_WORKER_VERSION\""));
        assert!(worker.contains("printf 'sha256=%s\\n' \"$actual\""));
        assert!(worker.contains("Upload immutable trusted worker artifact"));

        assert!(!compile.contains("secrets."));
        assert!(!compile.contains("environment:"));
        assert!(compile.contains("needs: worker"));
        assert!(compile.contains("actions: read"));
        assert!(compile.contains("Download exact trusted worker artifact"));
        assert!(compile.contains("needs.worker.outputs.sha256"));
        assert!(!compile.contains("cargo build --locked --release"));
        assert!(!compile.contains("Upload immutable trusted worker artifact"));

        assert!(sign.contains("      - worker\n      - compile"));
        assert!(sign.contains("Download exact trusted worker artifact"));
        assert!(sign.contains("needs.worker.outputs.sha256"));
        assert!(!sign.contains("actions/checkout@"));
        assert!(!sign.contains("cargo build"));
        assert!(sign.contains(
            "rustup toolchain install \"$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update"
        ));
        assert!(
            sign.contains("rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios")
        );

        assert_eq!(
            workflow
                .yaml()
                .matches("rustferry-worker-${{ github.run_id }}-${{ github.run_attempt }}")
                .count(),
            3
        );
        assert!(!workflow.yaml().contains("RUSTFERRY_WORKER_URL:"));
        assert!(!workflow.yaml().contains("RUSTFERRY_WORKER_SHA256:"));
    }

    #[test]
    fn source_and_application_builds_use_exact_rust_toolchain() {
        let workflow = generate_workflow(&fixture_source_config());
        let yaml = workflow.yaml();
        let (_, worker_and_later) = yaml.split_once("\n  worker:\n").unwrap();
        let (worker, compile_and_sign) = worker_and_later.split_once("\n  compile:\n").unwrap();
        let (compile, sign) = compile_and_sign.split_once("\n  sign:\n").unwrap();

        assert!(yaml.contains("RUSTUP_TOOLCHAIN: '1.92.0'"));
        assert_eq!(
            yaml.matches(
                "rustup toolchain install \"$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update"
            )
            .count(),
            3
        );
        assert!(worker.contains("rustc 1.92.0"));
        assert!(!worker.contains("rustup target add"));
        assert!(
            compile
                .contains("rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios")
        );
        assert!(compile.contains("rustc 1.92.0"));
        assert!(sign.contains("rustc 1.92.0"));
        assert!(
            sign.contains("rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios")
        );
    }

    #[test]
    fn source_mode_actions_are_first_party_and_immutably_pinned() {
        let workflow = generate_workflow(&fixture_source_config());
        let references = workflow
            .yaml()
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("uses:"))
            .collect::<Vec<_>>();

        assert_eq!(references.len(), 11);
        for line in references {
            let reference = line
                .split_ascii_whitespace()
                .nth(1)
                .unwrap()
                .split('#')
                .next()
                .unwrap();
            let (action, revision) = reference.split_once('@').unwrap();
            assert!(action.starts_with("actions/"));
            assert_eq!(revision.len(), 40);
            assert!(revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn prebuilt_mode_retains_url_sha_and_exact_device_toolchain_setup() {
        let config = fixture_config();
        let workflow = generate_workflow(&config);
        let yaml = workflow.yaml();
        let (compile, _) = yaml.split_once("\n  sign:\n").unwrap();

        assert!(!config.worker().is_source_build());
        assert_eq!(
            config.worker().download_url(),
            "https://github.com/ShiroKSH/rustferry/releases/download/v0.1.0/ferry-worker-macos"
        );
        assert_eq!(config.worker().sha256(), WORKER_SHA256);
        assert!(yaml.contains(&format!("RUSTFERRY_WORKER_SHA256: '{WORKER_SHA256}'")));
        assert!(yaml.contains("RUSTFERRY_WORKER_URL: 'https://github.com/"));
        assert!(yaml.contains("curl --fail --location --proto '=https'"));
        assert!(!yaml.contains("\n  worker:\n"));
        assert_eq!(
            yaml.matches(
                "rustup toolchain install \"$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update"
            )
            .count(),
            2
        );
        assert!(
            compile
                .contains("rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios")
        );
    }

    #[test]
    fn source_worker_job_uses_bounded_timeout_and_retention() {
        let workflow = generate_workflow(&fixture_source_config());
        let (_, worker_and_later) = workflow.yaml().split_once("\n  worker:\n").unwrap();
        let (worker, _) = worker_and_later.split_once("\n  compile:\n").unwrap();

        assert!(worker.contains("timeout-minutes: 30"));
        assert!(worker.contains("retention-days: 3"));
        assert_eq!(workflow.yaml().matches("retention-days: 3").count(), 3);
    }

    #[test]
    fn compile_phase_has_no_signing_secret_or_environment() {
        let workflow = generate_workflow(&fixture_config());
        let (compile, sign) = workflow.yaml().split_once("\n  sign:\n").unwrap();

        assert!(!compile.contains("secrets."));
        assert!(!compile.contains("RUSTFERRY_GOAL3_IOS_"));
        assert!(!compile.contains("environment:"));
        assert!(sign.contains("environment: 'rustferry-goal3-signing'"));
        assert_eq!(sign.matches("${{ secrets.").count(), 3);
    }

    #[test]
    fn modern_workflows_publish_only_the_exact_public_target_graph_digest() {
        for (config, expected_digest) in [
            (
                fixture_modern_app_only_config(),
                "144f18f553557a96d6a39105b3aa0928c54bf075a5e32fef077a2eef59b37aff",
            ),
            (
                fixture_multi_profile_config(),
                "112e2935c240c978a4e356b5a0e7b3ffc0068ba249807666e8d1662bd366a691",
            ),
        ] {
            assert_eq!(
                config.secret_names().target_graph_sha256(),
                Some(expected_digest)
            );
            let workflow = generate_workflow(&config);
            let (compile, _) = workflow.yaml().split_once("\n  sign:\n").unwrap();

            assert!(workflow.yaml().contains(&format!(
                "RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256: '{expected_digest}'"
            )));
            assert_eq!(
                workflow
                    .yaml()
                    .matches("--expected-signing-target-graph-sha256")
                    .count(),
                1
            );
            assert!(compile.contains(concat!(
                "--expected-signing-target-graph-sha256 ",
                "\"$RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256\""
            )));
            assert!(!compile.contains("secrets."));
            assert!(
                !workflow
                    .yaml()
                    .contains("secrets.RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256")
            );
        }

        let legacy = generate_workflow(&fixture_config());
        assert!(
            !legacy
                .yaml()
                .contains("RUSTFERRY_SIGNING_TARGET_GRAPH_SHA256")
        );
        assert!(
            !legacy
                .yaml()
                .contains("--expected-signing-target-graph-sha256")
        );
    }

    #[test]
    fn compile_cleanup_fails_closed_when_the_worker_disappears() {
        let workflow = generate_workflow(&fixture_source_config());
        let compile = workflow
            .yaml()
            .split_once("\n  compile:\n")
            .unwrap()
            .1
            .split_once("\n  sign:\n")
            .unwrap()
            .0;

        assert!(compile.contains("if: '${{ always() }}'"));
        assert!(compile.contains("elif [[ -d \"$RUNNER_TEMP/rustferry-compile-job\" ]]"));
        assert!(compile.contains("Compile cleanup could not run"));
        assert!(compile.contains("exit 1"));
    }

    #[test]
    fn signing_phase_never_checks_out_or_compiles_source() {
        let workflow = generate_workflow(&fixture_config());
        let sign = workflow.yaml().split_once("\n  sign:\n").unwrap().1;

        for forbidden in [
            "actions/checkout@",
            "cargo ",
            "xcodebuild ",
            "codesign ",
            "security ",
            "pull_request",
        ] {
            assert!(!sign.contains(forbidden), "found {forbidden}");
        }
        assert!(sign.contains("Verify sealed handoff digest before signing"));
        assert!(sign.contains(
            "rustup toolchain install \"$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update"
        ));
        assert!(
            sign.contains("rustup target add --toolchain \"$RUSTUP_TOOLCHAIN\" aarch64-apple-ios")
        );
        assert!(sign.contains("if: '${{ always() }}'"));
        assert!(sign.contains("--require-complete"));
    }

    #[test]
    fn protected_worker_receives_only_public_references_and_stdin() {
        let config = fixture_config();
        let workflow = generate_workflow(&config);
        let sign = workflow.yaml().split_once("\n  sign:\n").unwrap().1;

        assert!(sign.contains("printf '%s\\0%s\\0%s'"));
        assert!(sign.contains("/usr/bin/env -i \\"));
        assert!(!sign.contains("--certificate-p12-env"));
        assert!(!sign.contains("--certificate-password-env"));
        assert!(!sign.contains("--provisioning-profile-env"));
        for (flag, reference) in [
            (
                "--certificate-p12-reference",
                config.secret_names().certificate_p12().as_str(),
            ),
            (
                "--certificate-password-reference",
                config.secret_names().certificate_password().as_str(),
            ),
            (
                "--provisioning-profile-reference",
                config.secret_names().provisioning_profile().as_str(),
            ),
        ] {
            assert!(sign.contains(&format!("{flag} '{reference}'")));
        }
        let worker_environment = sign.split_once("/usr/bin/env -i").unwrap().1;
        assert!(worker_environment.contains("\"RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN\""));
        assert!(!worker_environment.contains("${{ secrets."));
        assert!(!worker_environment.contains("RUSTFERRY_SIGNING_CERTIFICATE_P12="));
        assert!(!worker_environment.contains("RUSTFERRY_SIGNING_CERTIFICATE_PASSWORD="));
        assert!(!worker_environment.contains("RUSTFERRY_SIGNING_PROVISIONING_PROFILE="));
    }

    #[test]
    fn multi_profile_workflow_uses_static_named_v2_records_only_in_signing_job() {
        let config = fixture_multi_profile_config();
        let workflow = generate_workflow(&config);
        let (compile, sign) = workflow.yaml().split_once("\n  sign:\n").unwrap();
        let profiles = config.secret_names().profile_names().collect::<Vec<_>>();

        assert_eq!(profiles.len(), 2);
        assert!(!compile.contains("secrets."));
        assert!(!compile.contains("RUSTFERRY_GOAL3_IOS_"));
        assert_eq!(sign.matches("${{ secrets.").count(), 4);
        assert!(!sign.contains("secrets["));
        assert!(sign.contains("printf 'RFSIGNV2'"));
        assert!(sign.contains("write_u32_be '4'"));
        assert!(!sign.contains("printf '%s\\0%s\\0%s'"));
        assert_eq!(
            sign.matches("--provisioning-profile-reference").count(),
            profiles.len()
        );

        let certificate_record = sign
            .find("write_record 'RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12'")
            .expect("certificate record");
        let password_record = sign
            .find("write_record 'RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD'")
            .expect("password record");
        assert!(certificate_record < password_record);
        let mut previous_record = password_record;
        for (index, profile) in profiles.iter().enumerate() {
            let secret_expression = format!("${{{{ secrets.{} }}}}", profile.as_str());
            assert_eq!(sign.matches(&secret_expression).count(), 1);
            assert!(sign.contains(&format!(
                "RUSTFERRY_SIGNING_PROVISIONING_PROFILE_{}: '{}'",
                index + 1,
                secret_expression
            )));
            let record = sign
                .find(&format!("write_record '{}'", profile.as_str()))
                .expect("profile record");
            assert!(record > previous_record);
            previous_record = record;
            assert!(sign.contains(&format!(
                "--provisioning-profile-reference '{}'",
                profile.as_str()
            )));
        }

        let worker_environment = sign.split_once("/usr/bin/env -i").unwrap().1;
        assert!(!worker_environment.contains("$RUSTFERRY_SIGNING_CERTIFICATE_P12"));
        assert!(!worker_environment.contains("$RUSTFERRY_SIGNING_CERTIFICATE_PASSWORD"));
        assert!(!worker_environment.contains("$RUSTFERRY_SIGNING_PROVISIONING_PROFILE_"));
    }

    #[test]
    fn signing_job_requires_manual_mode_and_private_event_repository() {
        let yaml = generate_workflow(&fixture_config());

        assert!(
            yaml.yaml()
                .contains("signing_mode: '${{ steps.request.outputs.signing_mode }}'")
        );
        assert!(
            yaml.yaml()
                .contains("if: needs.compile.outputs.signing_mode == 'manual_development' && github.event.repository.private == true")
        );
    }

    #[test]
    fn push_uses_temporary_namespace_and_explicit_source_revision() {
        let workflow = generate_workflow(&fixture_config());
        let yaml = workflow.yaml();

        assert!(yaml.contains("      - 'rustferry/goal3/builds/**'"));
        assert!(yaml.contains("--push-manifest"));
        assert!(yaml.contains(".rustferry/goal3/request.json"));
        assert!(yaml.contains("ref: '${{ steps.request.outputs.source_revision }}'"));
        assert_eq!(yaml.matches("ref: '${{ github.sha }}'").count(), 1);
        assert!(!yaml.contains("pull_request:"));
        assert!(!yaml.contains("pull_request_target:"));
    }

    #[test]
    fn all_actions_are_first_party_and_immutably_pinned() {
        let workflow = generate_workflow(&fixture_config());
        let mut count = 0;
        for line in workflow
            .yaml()
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("uses:"))
        {
            count += 1;
            let reference = line
                .split_ascii_whitespace()
                .nth(1)
                .unwrap()
                .split('#')
                .next()
                .unwrap()
                .trim();
            let (action, revision) = reference.split_once('@').unwrap();
            assert!(action.starts_with("actions/"));
            assert_eq!(revision.len(), 40);
            assert!(revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(count, 7);
    }

    #[test]
    fn security_policy_is_explicit_and_bounded() {
        let workflow = generate_workflow(&fixture_config());
        let yaml = workflow.yaml();

        assert!(yaml.contains("permissions: {}"));
        assert!(yaml.contains("timeout-minutes: 90"));
        assert!(yaml.contains("timeout-minutes: 30"));
        assert_eq!(yaml.matches("retention-days: 3").count(), 2);
        assert!(yaml.contains("cancel-in-progress: false"));
        assert!(yaml.contains("DEVELOPER_DIR: '/Applications/Xcode.app/Contents/Developer'"));
        assert!(!yaml.contains("macos-latest"));
        assert!(!yaml.contains("persist-credentials: true"));
    }

    #[test]
    fn runner_scoped_worker_path_is_used_only_inside_job_steps() {
        let workflow = generate_workflow(&fixture_source_config());
        let yaml = workflow.yaml();
        let (header, _) = yaml.split_once("\njobs:\n").unwrap();

        assert!(!header.contains("runner.temp"));
        assert!(!yaml.contains("RUSTFERRY_WORKER_PATH"));
        assert!(yaml.contains("$RUNNER_TEMP/rustferry-worker-runtime/ferry-worker-macos"));
    }

    #[test]
    fn manual_dispatch_is_not_advertised_without_a_bound_manifest() {
        let yaml = generate_workflow(&fixture_config());

        assert!(!yaml.yaml().contains("workflow_dispatch:"));
        assert!(yaml.yaml().contains("push:"));
    }

    #[test]
    fn rejects_yaml_shell_expression_and_ref_injection() {
        assert!(WorkflowFileName::new("good.yml\npull_request_target:").is_err());
        assert!(ProtectedEnvironment::new("prod'\nsecrets: inherit").is_err());
        assert!(SecretName::new("CERTIFICATE }}; echo owned").is_err());
        assert!(TrustedSourceRef::new("refs/pull/1/merge").is_err());
        assert!(TrustedSourceRef::new("refs/heads/main/**").is_err());
        assert!(TemporaryBranchNamespace::new("rustferry/jobs/**").is_err());
        assert!(DeveloperDirectory::new("/Applications/Xcode.app/../Secrets").is_err());
        assert!(
            WorkerDistribution::new("https://example.com/worker", WORKER_SHA256, "0.1.0").is_err()
        );
    }

    #[test]
    fn rejects_duplicate_secrets_and_overlapping_refs() {
        let repeated = SecretName::new("RUSTFERRY_CERTIFICATE").unwrap();
        assert_eq!(
            SigningSecretNames::new(
                repeated.clone(),
                repeated,
                SecretName::new("RUSTFERRY_PROFILE").unwrap(),
            ),
            Err(WorkflowConfigError::DuplicateSecretName)
        );

        let config = WorkflowConfig::new(
            WorkflowFileName::new("iphone.yml").unwrap(),
            ProtectedEnvironment::new("signing").unwrap(),
            SigningSecretNames::goal3_defaults(),
            WorkerDistribution::new(
                "https://github.com/ShiroKSH/rustferry/releases/download/v0.1.0/ferry-worker-macos",
                WORKER_SHA256,
                "0.1.0",
            )
            .unwrap(),
            fixture_public_source(),
            TrustedSourceRef::new("refs/heads/rustferry/goal3/builds/forbidden").unwrap(),
            TemporaryBranchNamespace::new("rustferry/goal3/builds").unwrap(),
        );
        assert_eq!(config, Err(WorkflowConfigError::RefNamespaceOverlap));

        let sibling = WorkflowConfig::new(
            WorkflowFileName::new("iphone.yml").unwrap(),
            ProtectedEnvironment::new("signing").unwrap(),
            SigningSecretNames::goal3_defaults(),
            WorkerDistribution::new(
                "https://github.com/ShiroKSH/rustferry/releases/download/v0.1.0/ferry-worker-macos",
                WORKER_SHA256,
                "0.1.0",
            )
            .unwrap(),
            fixture_public_source(),
            TrustedSourceRef::new("refs/heads/rustferry/goal3/builds-next").unwrap(),
            TemporaryBranchNamespace::new("rustferry/goal3/builds").unwrap(),
        );
        assert!(sibling.is_ok());
    }

    #[test]
    fn target_profile_secret_names_are_static_deterministic_and_exact() {
        let targets = vec![
            signing_target(
                "RuntimeBridge",
                "org.rustferry.runtime-bridge",
                SigningTargetKind::Framework,
            ),
            signing_target(
                "WeatherWidget",
                "com.example.weather.widget",
                SigningTargetKind::Extension,
            ),
            signing_target(
                "Weather",
                "com.example.weather",
                SigningTargetKind::Application,
            ),
            signing_target(
                "LiveActivity",
                "com.example.weather.liveactivity",
                SigningTargetKind::Extension,
            ),
        ];
        let names = SigningSecretNames::for_targets(&targets).expect("profile names");
        let reordered_targets = targets.iter().rev().cloned().collect::<Vec<_>>();
        let reordered =
            SigningSecretNames::for_targets(&reordered_targets).expect("reordered profile names");

        assert_eq!(names, reordered);
        assert!(names.matches_target_graph(&reordered_targets));
        assert_eq!(names.profile_names().count(), MAX_SIGNING_PROFILES);
        assert_eq!(
            names.profile_for_target("Weather").map(SecretName::as_str),
            Some(GOAL3_APPLICATION_PROFILE_SECRET)
        );
        assert_eq!(
            names
                .profile_for_target("WeatherWidget")
                .map(SecretName::as_str),
            Some("RUSTFERRY_GOAL3_IOS_PROFILE_3FAD627B2731B5773D3929E36B01CA69")
        );
        assert!(names.profile_for_target("RuntimeBridge").is_none());
        assert_eq!(names.all_names().collect::<BTreeSet<_>>().len(), 5);

        let mut app_bundle_drift = targets.clone();
        app_bundle_drift
            .iter_mut()
            .find(|target| target.name == "Weather")
            .expect("application target")
            .bundle_identifier =
            BundleIdentifier::new("com.example.weather.renamed").expect("drifted app bundle");
        assert!(!names.matches_target_graph(&app_bundle_drift));

        let mut extension_bundle_drift = targets.clone();
        extension_bundle_drift
            .iter_mut()
            .find(|target| target.name == "WeatherWidget")
            .expect("extension target")
            .bundle_identifier = BundleIdentifier::new("com.example.weather.renamed-widget")
            .expect("drifted extension bundle");
        assert!(!names.matches_target_graph(&extension_bundle_drift));

        let mut extension_name_drift = targets.clone();
        extension_name_drift
            .iter_mut()
            .find(|target| target.name == "WeatherWidget")
            .expect("extension target")
            .name = "RenamedWidget".to_owned();
        assert!(!names.matches_target_graph(&extension_name_drift));

        let omitted_framework = targets
            .iter()
            .filter(|target| target.name != "RuntimeBridge")
            .cloned()
            .collect::<Vec<_>>();
        assert!(!names.matches_target_graph(&omitted_framework));

        let mut extra_framework = targets.clone();
        extra_framework.push(signing_target(
            "SupportKit",
            "org.rustferry.support-kit",
            SigningTargetKind::Framework,
        ));
        assert!(!names.matches_target_graph(&extra_framework));
    }

    #[test]
    fn target_profile_secret_names_reject_ambiguous_or_oversized_graphs() {
        let app = signing_target("App", "com.example.app", SigningTargetKind::Application);
        let extension = signing_target(
            "Widget",
            "com.example.app.widget",
            SigningTargetKind::Extension,
        );
        let duplicate_name = signing_target(
            "Widget",
            "com.example.app.liveactivity",
            SigningTargetKind::Extension,
        );
        assert_eq!(
            SigningSecretNames::for_targets(std::slice::from_ref(&extension)),
            Err(WorkflowConfigError::InvalidSigningTargets)
        );
        assert_eq!(
            SigningSecretNames::for_targets(&[app.clone(), app.clone()]),
            Err(WorkflowConfigError::InvalidSigningTargets)
        );
        assert_eq!(
            SigningSecretNames::for_targets(&[app.clone(), extension.clone(), duplicate_name]),
            Err(WorkflowConfigError::InvalidSigningTargets)
        );
        assert_eq!(
            SigningSecretNames::for_targets(&[
                app,
                extension,
                signing_target(
                    "LiveActivity",
                    "com.example.app.liveactivity",
                    SigningTargetKind::Extension,
                ),
                signing_target(
                    "ShareExtension",
                    "com.example.app.share",
                    SigningTargetKind::Extension,
                ),
            ]),
            Err(WorkflowConfigError::TooManySigningProfiles {
                maximum: MAX_SIGNING_PROFILES,
            })
        );
    }

    #[test]
    fn temporary_ref_prefix_has_one_operation_separator() {
        let namespace = TemporaryBranchNamespace::new("rustferry/goal3/builds").unwrap();

        assert_eq!(
            format!("{}/operation-1", namespace.full_ref_prefix()),
            "refs/heads/rustferry/goal3/builds/operation-1"
        );
    }

    #[test]
    fn errors_do_not_echo_rejected_values() {
        let canary = "CERTIFICATE }} ${{ secrets.VALUE }}";
        let error = SecretName::new(canary).unwrap_err().to_string();

        assert!(!error.contains(canary));
        assert!(!error.contains("secrets.VALUE"));
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }
}
