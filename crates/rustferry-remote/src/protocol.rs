use std::{collections::BTreeSet, fmt};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{
    artifact::{
        ArtifactKind, ArtifactManifest, IosDeviceProductExpectation, IpaExpectation,
        UnsignedNestedBundleKind,
    },
    error::{RemoteBuildError, RemoteBuildResult},
    signing::{SigningMode, SigningPlan, SigningTargetKind},
    source::{SourceLimits, SourceManifest, SourceMode, validate_source_manifest},
};

/// Rust target used for physical iPhone builds.
pub const IOS_DEVICE_RUST_TARGET: &str = "aarch64-apple-ios";

/// Xcode SDK used for physical iPhone builds.
pub const IOS_DEVICE_SDK: &str = "iphoneos";

/// Largest single NDJSON event accepted by the decoder.
pub const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;

/// Current Ferry Remote Build Protocol version.
pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Required Ferry Remote Build Protocol v1 event names.
pub const REMOTE_BUILD_EVENT_TYPES: &[&str] = &[
    "operation_started",
    "job_created",
    "job_queued",
    "worker_assigned",
    "source_prepared",
    "source_upload_started",
    "source_upload_progress",
    "source_verified",
    "phase_started",
    "progress",
    "command_started",
    "diagnostic",
    "signing_started",
    "artifact_created",
    "artifact_validated",
    "artifact_upload_started",
    "artifact_download_started",
    "artifact_download_progress",
    "artifact_downloaded",
    "warning",
    "cleanup_started",
    "cleanup_finished",
    "operation_finished",
    "operation_cancelled",
];

/// Semantic version of the remote-build wire protocol.
///
/// Peers with the same nonzero major version are compatible. A handshake selects the lower minor
/// version. A future pre-1 protocol must match both components exactly.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct ProtocolVersion {
    /// Breaking-change version.
    pub major: u16,
    /// Backward-compatible feature version.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Construct a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Whether two protocol versions can exchange v1 envelopes.
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && (self.major != 0 || self.minor == other.minor)
    }

    /// Select the common version or return a typed incompatibility error.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::IncompatibleProtocolVersion`] for different major versions.
    pub fn negotiate(self, other: Self) -> RemoteBuildResult<Self> {
        if self.is_compatible_with(other) {
            Ok(Self::new(self.major, self.minor.min(other.minor)))
        } else {
            Err(RemoteBuildError::IncompatibleProtocolVersion {
                supported: self,
                received: other,
            })
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

/// Optimization profile requested from the remote worker.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    /// Fast development build.
    Debug,
    /// Optimized build.
    Release,
}

/// Physical-iPhone artifact type requested or advertised by a provider.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IosArtifactType {
    /// Signed installable iOS application archive.
    Ipa,
    /// Xcode archive retained for inspection or later export.
    Xcarchive,
    /// Unarchived application bundle.
    AppBundle,
    /// Compressed debug symbols for the main application executable.
    Dsym,
    /// Sanitized signing validation report.
    SigningReport,
    /// Sanitized provisioning validation report.
    ProvisioningReport,
}

impl fmt::Display for IosArtifactType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ipa => "ipa",
            Self::Xcarchive => "xcarchive",
            Self::AppBundle => "app_bundle",
            Self::Dsym => "dsym",
            Self::SigningReport => "signing_report",
            Self::ProvisioningReport => "provisioning_report",
        };
        formatter.write_str(name)
    }
}

impl IosArtifactType {
    /// Return the manifest kind that must represent this requested artifact.
    #[must_use]
    pub const fn artifact_kind(self) -> ArtifactKind {
        match self {
            Self::Ipa => ArtifactKind::Ipa,
            Self::Xcarchive => ArtifactKind::Xcarchive,
            Self::AppBundle => ArtifactKind::App,
            Self::Dsym => ArtifactKind::Dsym,
            Self::SigningReport => ArtifactKind::SigningReport,
            Self::ProvisioningReport => ArtifactKind::ValidationReport,
        }
    }
}

/// Explicit interpretation of a path carried by the wire protocol.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolPathSemantics {
    /// Path relative to the submitted `RustFerry` project root.
    ProjectRelative,
    /// Path relative to the worker's isolated job root.
    WorkerRelative,
    /// Absolute path on the client that submitted the request.
    ClientAbsolute,
    /// Provider-owned URI with no embedded credentials.
    ProviderUri,
}

/// Path string paired with explicit machine and root semantics.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolPath {
    /// How the path must be resolved.
    pub semantics: ProtocolPathSemantics,
    /// UTF-8 path or URI text.
    pub value: String,
}

impl ProtocolPath {
    /// Construct and validate a protocol path.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for unsafe or inconsistent path text.
    pub fn new(
        semantics: ProtocolPathSemantics,
        value: impl Into<String>,
    ) -> RemoteBuildResult<Self> {
        let path = Self {
            semantics,
            value: value.into(),
        };
        path.validate()?;
        Ok(path)
    }

    /// Validate lexical path safety without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for traversal, credentials, or incorrect semantics.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        validate_safe_text("path", &self.value, 4096)?;
        match self.semantics {
            ProtocolPathSemantics::ProjectRelative | ProtocolPathSemantics::WorkerRelative => {
                if is_absolute_path_text(&self.value) {
                    return Err(RemoteBuildError::InvalidIdentifier {
                        field: "path",
                        reason: "relative path must not be absolute",
                    });
                }
                if self
                    .value
                    .split(['/', '\\'])
                    .any(|component| component.is_empty() || component == "." || component == "..")
                {
                    return Err(RemoteBuildError::InvalidIdentifier {
                        field: "path",
                        reason: "relative path contains an empty, current, or parent component",
                    });
                }
            }
            ProtocolPathSemantics::ClientAbsolute => {
                if !is_absolute_path_text(&self.value) {
                    return Err(RemoteBuildError::InvalidIdentifier {
                        field: "path",
                        reason: "client path must be absolute",
                    });
                }
            }
            ProtocolPathSemantics::ProviderUri => {
                let uri = url::Url::parse(&self.value).map_err(|_| {
                    RemoteBuildError::InvalidIdentifier {
                        field: "path",
                        reason: "provider URI is invalid",
                    }
                })?;
                if !uri.username().is_empty() || uri.password().is_some() {
                    return Err(RemoteBuildError::InvalidIdentifier {
                        field: "path",
                        reason: "provider URI must not contain credentials",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Lifecycle state of one provider job.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Provider accepted the request and allocated an identifier.
    Created,
    /// Job awaits a worker.
    Queued,
    /// Worker is preparing or building the project.
    Running,
    /// Cancellation was accepted and cleanup is pending.
    Cancelling,
    /// Build completed successfully.
    Succeeded,
    /// Build failed.
    Failed,
    /// Build stopped after cancellation.
    Cancelled,
    /// Provider is deleting remote job material.
    Cleaning,
    /// Required cleanup completed.
    Cleaned,
    /// Cleanup was attempted but did not complete.
    CleanupFailed,
}

impl JobState {
    /// Whether a direct state transition is valid.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Created,
                Self::Queued | Self::Running | Self::Cancelling | Self::Cancelled | Self::Failed
            ) | (
                Self::Queued,
                Self::Running | Self::Cancelling | Self::Cancelled | Self::Failed
            ) | (
                Self::Running,
                Self::Succeeded | Self::Failed | Self::Cancelling | Self::Cancelled
            ) | (Self::Cancelling, Self::Cancelled | Self::Failed)
                | (
                    Self::Succeeded | Self::Failed | Self::Cancelled,
                    Self::Cleaning
                )
                | (Self::Cleaning, Self::Cleaned | Self::CleanupFailed)
        )
    }

    /// Apply a checked state transition.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::InvalidJobTransition`] for a forbidden transition.
    pub fn transition_to(self, next: Self) -> RemoteBuildResult<Self> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(RemoteBuildError::InvalidJobTransition {
                from: self,
                to: next,
            })
        }
    }

    /// Whether the build phase has completed, before optional cleanup.
    pub const fn is_build_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    /// Whether no further lifecycle transition is possible.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Cleaned | Self::CleanupFailed)
    }
}

/// Declarative request for an official physical-iPhone build.
///
/// The request intentionally contains no executable, argument, environment, or secret-value
/// fields. Workers derive their fixed command plans from these validated inputs.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct IosDeviceBuildRequest {
    /// Requested wire-protocol version.
    pub protocol_version: ProtocolVersion,
    /// Caller-owned operation identifier copied into every event.
    pub operation_id: String,
    /// Human-readable product name.
    pub product_name: String,
    /// Exact Apple application bundle identifier.
    pub bundle_identifier: String,
    /// Minimum supported iOS version.
    pub minimum_ios_version: String,
    /// Client-derived product identity used for independent output validation.
    pub product: IosDeviceProductExpectation,
    /// Rust/Xcode optimization profile.
    pub profile: BuildProfile,
    /// How the provider obtains the source.
    pub source_mode: SourceMode,
    /// Normalized HTTPS GitHub repository URL in Git mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repository: Option<String>,
    /// Exact lowercase 40-hex commit SHA in Git mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    /// Required deterministic integrity and shape manifest for either source mode.
    pub source: SourceManifest,
    /// Complete declarative signing plan containing opaque references, never secret bytes.
    pub signing: SigningPlan,
    /// Requested output kinds in deterministic order.
    pub requested_artifacts: BTreeSet<IosArtifactType>,
}

impl IosDeviceBuildRequest {
    /// Validate protocol and identifier fields before provider submission.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatible versions, unsafe identifiers, ambiguous Git input,
    /// invalid source manifests, or missing artifact requests.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_safe_text("product_name", &self.product_name, 255)?;
        validate_bundle_identifier(&self.bundle_identifier)?;
        validate_ios_version(&self.minimum_ios_version)?;
        validate_product_expectation(&self.product, &self.bundle_identifier, &self.signing)?;
        validate_source_manifest(&self.source, SourceLimits::default()).map_err(|error| {
            RemoteBuildError::InvalidSourceManifest {
                message: error.to_string(),
            }
        })?;
        self.signing
            .validate()
            .map_err(|_| RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "signing plan is invalid",
            })?;
        let application_bundle_identifier = self
            .signing
            .targets
            .iter()
            .find(|target| target.kind == crate::signing::SigningTargetKind::Application)
            .map(|target| target.bundle_identifier.as_str());
        if application_bundle_identifier != Some(self.bundle_identifier.as_str()) {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "signing plan application bundle identifier does not match request",
            });
        }
        validate_requested_artifact_selection(self.signing.mode, &self.requested_artifacts)?;
        match self.source_mode {
            SourceMode::Git => {
                let repository = self.source_repository.as_deref().ok_or(
                    RemoteBuildError::InvalidEventPayload {
                        event: "ios_device_build_request",
                        reason: "Git source requires a normalized HTTPS GitHub repository URL",
                    },
                )?;
                let revision = self.source_revision.as_deref().ok_or(
                    RemoteBuildError::InvalidEventPayload {
                        event: "ios_device_build_request",
                        reason: "Git source requires an exact commit SHA",
                    },
                )?;
                validate_github_repository(repository)?;
                validate_git_revision(revision)?;
            }
            SourceMode::Snapshot => {
                if self.source_repository.is_some() || self.source_revision.is_some() {
                    return Err(RemoteBuildError::InvalidEventPayload {
                        event: "ios_device_build_request",
                        reason: "snapshot source forbids repository and revision fields",
                    });
                }
            }
        }
        if self.requested_artifacts.is_empty() {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "at least one artifact type is required",
            });
        }
        Ok(())
    }

    /// Derive a complete client-side IPA expectation without worker-provided metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed request-validation error when any product or signing field is invalid.
    pub fn ipa_expectation(&self) -> RemoteBuildResult<IpaExpectation> {
        self.validate()?;
        Ok(IpaExpectation {
            app_directory_name: self.product.app_directory_name.clone(),
            bundle_identifier: self.bundle_identifier.clone(),
            executable: self.product.executable.clone(),
            app_version: Some(self.product.app_version.clone()),
            build_number: Some(self.product.build_number.clone()),
            minimum_os: self.minimum_ios_version.clone(),
            nested_bundles: self.product.nested_bundles.clone(),
            provisioning_required: self.signing.mode.is_signed(),
        })
    }
}

fn validate_requested_artifact_selection(
    signing_mode: SigningMode,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> RemoteBuildResult<()> {
    if signing_mode == SigningMode::UnsignedCompileOnly
        && requested_artifacts.contains(&IosArtifactType::Ipa)
    {
        return Err(RemoteBuildError::InvalidEventPayload {
            event: "ios_device_build_request",
            reason: "unsigned compile-only mode cannot request an installable IPA",
        });
    }
    if signing_mode.is_signed() && !requested_artifacts.contains(&IosArtifactType::Ipa) {
        return Err(RemoteBuildError::InvalidEventPayload {
            event: "ios_device_build_request",
            reason: "signed builds must request the installable IPA",
        });
    }
    if signing_mode.is_signed() && !requested_artifacts.contains(&IosArtifactType::SigningReport) {
        return Err(RemoteBuildError::InvalidEventPayload {
            event: "ios_device_build_request",
            reason: "signed builds must request the signing report",
        });
    }
    Ok(())
}

/// Serialize one validated iPhone build request using the protocol's deterministic field order.
///
/// Maps and sets nested in the request use ordered representations. Keeping this function in the
/// protocol crate prevents providers and workers from hashing subtly different request encodings.
///
/// # Errors
///
/// Returns a typed validation or serialization failure.
pub fn canonical_request_bytes(request: &IosDeviceBuildRequest) -> RemoteBuildResult<Vec<u8>> {
    request.validate()?;
    serde_json::to_vec(request).map_err(|error| RemoteBuildError::Serialization {
        message: error.to_string(),
    })
}

/// Return lowercase SHA-256 of [`canonical_request_bytes`].
///
/// # Errors
///
/// Returns the same validation or serialization failure as [`canonical_request_bytes`].
pub fn canonical_request_sha256(request: &IosDeviceBuildRequest) -> RemoteBuildResult<String> {
    Ok(hex::encode(Sha256::digest(canonical_request_bytes(
        request,
    )?)))
}

/// Return the version-1 semantic retry SHA-256 for one validated request.
///
/// The retry identity deliberately excludes only the caller-owned operation identifier. A retry
/// therefore receives a fresh wire-request hash while remaining cryptographically bound to the
/// same source, product, target, profile, signing plan, and artifact selection.
///
/// # Errors
///
/// Returns the same validation or serialization failure as [`canonical_request_bytes`].
pub fn canonical_retry_template_sha256_v1(
    request: &IosDeviceBuildRequest,
) -> RemoteBuildResult<String> {
    const DOMAIN: &[u8] = b"rustferry-retry-template-v1\0";
    const OPERATION_ID_PLACEHOLDER: &str = "semantic-retry-template-v1";

    request.validate()?;
    let mut template = request.clone();
    OPERATION_ID_PLACEHOLDER.clone_into(&mut template.operation_id);
    let bytes = canonical_request_bytes(&template)?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

/// Provider result after a physical-iPhone build reaches a build-terminal state.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct IosDeviceBuildResult {
    /// Negotiated wire-protocol version.
    pub protocol_version: ProtocolVersion,
    /// Operation identifier from the request.
    pub operation_id: String,
    /// Provider-owned stable job identifier.
    pub job_id: String,
    /// Terminal build state.
    pub state: JobState,
    /// Independently verifiable artifact manifests.
    pub artifacts: Vec<ArtifactManifest>,
    /// Cleanup proof when cleanup already ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupConfirmation>,
}

impl IosDeviceBuildResult {
    /// Validate result identity and terminal-state invariants.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatible versions, invalid IDs, nonterminal states, or a
    /// successful build without artifacts.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        if !self.state.is_build_terminal() && !self.state.is_terminal() {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_result",
                reason: "result state is not terminal",
            });
        }
        if self.state == JobState::Succeeded && self.artifacts.is_empty() {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_result",
                reason: "successful result has no artifact manifest",
            });
        }
        Ok(())
    }
}

/// Proof that provider-owned job material was removed or deliberately retained.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CleanupConfirmation {
    /// Stable job identifier.
    pub job_id: String,
    /// Milliseconds since Unix epoch in UTC.
    pub completed_at_ms: u64,
    /// Whether the isolated source/build workspace was removed.
    pub workspace_removed: bool,
    /// Whether decoded signing material and temporary keychains were removed.
    pub signing_material_removed: bool,
    /// Whether provider retention policy deliberately kept artifact bytes.
    pub artifacts_retained: bool,
}

/// Normalized diagnostic severity.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational message.
    Information,
    /// Non-fatal warning.
    Warning,
    /// Build-blocking error.
    Error,
}

/// Sanitized, optionally file-bound worker diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RemoteDiagnostic {
    /// Stable diagnostic category.
    pub code: String,
    /// Severity consumed by CLI and IDE adapters.
    pub severity: DiagnosticSeverity,
    /// Sanitized UTF-8 summary.
    pub message: String,
    /// Optional concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Optional path with explicit resolution semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<ProtocolPath>,
    /// Optional one-based source line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Optional one-based source column.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Sanitized error embedded in an operation-finished event.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RemoteErrorInfo {
    /// Stable namespaced error code.
    pub code: String,
    /// Safe error summary.
    pub message: String,
    /// Optional recovery action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Whether retrying may succeed without changing the request.
    pub retryable: bool,
}

/// Typed Ferry Remote Build Protocol v1 event payload.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RemoteBuildEventKind {
    /// Operation boundary opened.
    OperationStarted {
        /// Stable command name.
        command: String,
    },
    /// Provider allocated a job.
    JobCreated {
        /// Initial job state; must be `created`.
        state: JobState,
    },
    /// Job entered the provider queue.
    JobQueued {
        /// One-based queue position when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        position: Option<u64>,
    },
    /// A concrete worker accepted the job.
    WorkerAssigned {
        /// Stable, non-secret worker identifier.
        worker_id: String,
    },
    /// Source manifest was converted into a bounded upload.
    SourcePrepared {
        /// Included file count.
        file_count: u64,
        /// Total uncompressed source bytes.
        total_bytes: u64,
    },
    /// Source upload opened.
    SourceUploadStarted {
        /// Expected upload byte count.
        total_bytes: u64,
    },
    /// Source upload advanced.
    SourceUploadProgress {
        /// Uploaded byte count.
        uploaded_bytes: u64,
        /// Expected upload byte count.
        total_bytes: u64,
    },
    /// Worker verified the exact submitted source.
    SourceVerified {
        /// Lowercase SHA-256 digest of the source bundle or Git manifest.
        sha256: String,
    },
    /// Named build phase opened.
    PhaseStarted {
        /// Optional safe UI text.
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Bounded progress update.
    Progress {
        /// Human-readable safe progress summary.
        message: String,
        /// Completed unit count.
        #[serde(skip_serializing_if = "Option::is_none")]
        current: Option<u64>,
        /// Total unit count.
        #[serde(skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    /// Sanitized external-tool boundary.
    CommandStarted {
        /// Executable name, never a shell command string.
        tool: String,
        /// Tokenized arguments after provider redaction.
        arguments: Vec<String>,
    },
    /// Structured compiler, signing, or validation diagnostic.
    Diagnostic {
        /// Diagnostic payload.
        diagnostic: RemoteDiagnostic,
    },
    /// Signing phase opened without exposing secret values.
    SigningStarted {
        /// Selected signing mode.
        mode: SigningMode,
    },
    /// Worker created a candidate artifact.
    ArtifactCreated {
        /// Stable artifact identifier.
        artifact_id: String,
        /// Candidate artifact type.
        artifact_type: IosArtifactType,
    },
    /// Worker independently validated an artifact.
    ArtifactValidated {
        /// Full integrity and provenance manifest.
        artifact: ArtifactManifest,
    },
    /// Provider artifact upload opened.
    ArtifactUploadStarted {
        /// Stable artifact identifier.
        artifact_id: String,
        /// Expected upload byte count.
        total_bytes: u64,
    },
    /// Client artifact download opened.
    ArtifactDownloadStarted {
        /// Stable artifact identifier.
        artifact_id: String,
        /// Expected download byte count.
        total_bytes: u64,
    },
    /// Client artifact download advanced.
    ArtifactDownloadProgress {
        /// Stable artifact identifier.
        artifact_id: String,
        /// Downloaded byte count.
        downloaded_bytes: u64,
        /// Expected download byte count.
        total_bytes: u64,
    },
    /// Client downloaded and hash-verified an artifact.
    ArtifactDownloaded {
        /// Verified artifact manifest.
        artifact: ArtifactManifest,
        /// Absolute destination on the client.
        local_path: ProtocolPath,
    },
    /// Non-fatal provider warning.
    Warning {
        /// Stable namespaced warning code.
        code: String,
        /// Sanitized summary.
        message: String,
        /// Optional concrete remediation.
        #[serde(skip_serializing_if = "Option::is_none")]
        help: Option<String>,
    },
    /// Provider cleanup opened.
    CleanupStarted,
    /// Provider cleanup completed.
    CleanupFinished {
        /// Cleanup proof.
        confirmation: CleanupConfirmation,
    },
    /// Operation completed, including typed failure.
    OperationFinished {
        /// Whether every required phase succeeded.
        success: bool,
        /// Monotonic operation duration.
        duration_ms: u64,
        /// Build result when this was a build operation.
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<IosDeviceBuildResult>,
        /// Typed failure when `success` is false.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RemoteErrorInfo>,
    },
    /// Operation stopped after cancellation.
    OperationCancelled {
        /// Stable cancellation reason.
        reason: String,
        /// Monotonic operation duration.
        duration_ms: u64,
    },
    /// A same-major future event ignored by this reader.
    #[serde(other)]
    Unknown,
}

impl RemoteBuildEventKind {
    /// Stable serialized event name.
    pub const fn event_name(&self) -> &'static str {
        match self {
            Self::OperationStarted { .. } => "operation_started",
            Self::JobCreated { .. } => "job_created",
            Self::JobQueued { .. } => "job_queued",
            Self::WorkerAssigned { .. } => "worker_assigned",
            Self::SourcePrepared { .. } => "source_prepared",
            Self::SourceUploadStarted { .. } => "source_upload_started",
            Self::SourceUploadProgress { .. } => "source_upload_progress",
            Self::SourceVerified { .. } => "source_verified",
            Self::PhaseStarted { .. } => "phase_started",
            Self::Progress { .. } => "progress",
            Self::CommandStarted { .. } => "command_started",
            Self::Diagnostic { .. } => "diagnostic",
            Self::SigningStarted { .. } => "signing_started",
            Self::ArtifactCreated { .. } => "artifact_created",
            Self::ArtifactValidated { .. } => "artifact_validated",
            Self::ArtifactUploadStarted { .. } => "artifact_upload_started",
            Self::ArtifactDownloadStarted { .. } => "artifact_download_started",
            Self::ArtifactDownloadProgress { .. } => "artifact_download_progress",
            Self::ArtifactDownloaded { .. } => "artifact_downloaded",
            Self::Warning { .. } => "warning",
            Self::CleanupStarted => "cleanup_started",
            Self::CleanupFinished { .. } => "cleanup_finished",
            Self::OperationFinished { .. } => "operation_finished",
            Self::OperationCancelled { .. } => "operation_cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// One self-contained NDJSON event envelope.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RemoteBuildEvent {
    /// Wire-protocol version.
    pub protocol_version: ProtocolVersion,
    /// Caller-owned operation identifier.
    pub operation_id: String,
    /// Provider-owned job identifier.
    pub job_id: String,
    /// Milliseconds since Unix epoch in UTC.
    pub timestamp_ms: u64,
    /// Stable provider identifier.
    pub provider: String,
    /// Stable build-phase identifier.
    pub phase: String,
    /// Strictly increasing event sequence within one job.
    pub sequence: u64,
    /// Typed event-specific fields.
    #[serde(flatten)]
    pub kind: RemoteBuildEventKind,
}

impl RemoteBuildEvent {
    /// Construct and validate an event envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error when envelope or payload invariants fail.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: impl Into<String>,
        job_id: impl Into<String>,
        timestamp_ms: u64,
        provider: impl Into<String>,
        phase: impl Into<String>,
        sequence: u64,
        kind: RemoteBuildEventKind,
    ) -> RemoteBuildResult<Self> {
        let event = Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: operation_id.into(),
            job_id: job_id.into(),
            timestamp_ms,
            provider: provider.into(),
            phase: phase.into(),
            sequence,
            kind,
        };
        event.validate()?;
        Ok(event)
    }

    /// Encode one compact JSON object followed by a newline.
    ///
    /// # Errors
    ///
    /// Returns a typed validation or serialization error.
    pub fn encode_line(&self) -> RemoteBuildResult<String> {
        self.validate()?;
        let mut encoded =
            serde_json::to_string(self).map_err(|error| RemoteBuildError::Serialization {
                message: error.to_string(),
            })?;
        encoded.push('\n');
        Ok(encoded)
    }

    /// Decode exactly one UTF-8 JSON object, tolerating trailing whitespace.
    ///
    /// # Errors
    ///
    /// Returns a typed size, syntax, truncation, version, or validation error.
    pub fn decode_line(encoded: &str) -> RemoteBuildResult<Self> {
        if encoded.len() > MAX_EVENT_LINE_BYTES {
            return Err(RemoteBuildError::EventTooLarge {
                bytes: encoded.len(),
                maximum: MAX_EVENT_LINE_BYTES,
            });
        }
        let event = serde_json::from_str::<Self>(encoded).map_err(|error| {
            if error.is_eof() {
                RemoteBuildError::TruncatedEvent
            } else {
                RemoteBuildError::MalformedEvent {
                    message: error.to_string(),
                }
            }
        })?;
        event.validate()?;
        Ok(event)
    }

    /// Decode one event from untrusted bytes and reject non-UTF-8 input.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::InvalidUtf8`] or any error from [`Self::decode_line`].
    pub fn decode_line_bytes(encoded: &[u8]) -> RemoteBuildResult<Self> {
        let encoded = std::str::from_utf8(encoded).map_err(|_| RemoteBuildError::InvalidUtf8)?;
        Self::decode_line(encoded)
    }

    /// Validate envelope, progress, path, and terminal-event invariants.
    ///
    /// # Errors
    ///
    /// Returns a typed version, identifier, path, payload, or serialization error.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        validate_identifier("provider", &self.provider)?;
        validate_identifier("phase", &self.phase)?;

        match &self.kind {
            RemoteBuildEventKind::JobCreated { state } if *state != JobState::Created => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "job_created",
                    reason: "initial state must be created",
                });
            }
            RemoteBuildEventKind::SourceUploadProgress {
                uploaded_bytes,
                total_bytes,
            } if uploaded_bytes > total_bytes => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "source_upload_progress",
                    reason: "uploaded bytes exceed total bytes",
                });
            }
            RemoteBuildEventKind::Progress {
                current: Some(current),
                total: Some(total),
                ..
            } if current > total => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "progress",
                    reason: "completed units exceed total units",
                });
            }
            RemoteBuildEventKind::ArtifactDownloadProgress {
                downloaded_bytes,
                total_bytes,
                ..
            } if downloaded_bytes > total_bytes => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "artifact_download_progress",
                    reason: "downloaded bytes exceed total bytes",
                });
            }
            RemoteBuildEventKind::ArtifactDownloaded { local_path, .. } => {
                local_path.validate()?;
                if local_path.semantics != ProtocolPathSemantics::ClientAbsolute {
                    return Err(RemoteBuildError::InvalidEventPayload {
                        event: "artifact_downloaded",
                        reason: "download destination must be client_absolute",
                    });
                }
            }
            RemoteBuildEventKind::Diagnostic { diagnostic } => {
                if let Some(path) = &diagnostic.path {
                    path.validate()?;
                }
            }
            RemoteBuildEventKind::OperationFinished {
                success: true,
                error: Some(_),
                ..
            } => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "operation_finished",
                    reason: "successful operation must not contain an error",
                });
            }
            RemoteBuildEventKind::OperationFinished {
                success: false,
                error: None,
                ..
            } => {
                return Err(RemoteBuildError::InvalidEventPayload {
                    event: "operation_finished",
                    reason: "failed operation requires a typed error",
                });
            }
            _ => {}
        }

        let value =
            serde_json::to_value(self).map_err(|error| RemoteBuildError::Serialization {
                message: error.to_string(),
            })?;
        validate_no_terminal_escape(&value)?;
        Ok(())
    }
}

pub(crate) fn validate_identifier(field: &'static str, value: &str) -> RemoteBuildResult<()> {
    if value.is_empty() {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value is empty",
        });
    }
    if value.len() > 160 {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value exceeds 160 bytes",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value contains unsupported characters",
        });
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> RemoteBuildResult<()> {
    if value.is_empty() {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value is empty",
        });
    }
    if value.len() > maximum_bytes {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value exceeds its protocol limit",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value contains control characters",
        });
    }
    Ok(())
}

fn validate_bundle_identifier(value: &str) -> RemoteBuildResult<()> {
    validate_safe_text("bundle_identifier", value, 255)?;
    let mut segments = value.split('.');
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && !segment.starts_with('-')
            && !segment.ends_with('-')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    let first = segments.next();
    let second = segments.next();
    if first.is_none_or(|segment| !valid_segment(segment))
        || second.is_none_or(|segment| !valid_segment(segment))
        || segments.any(|segment| !valid_segment(segment))
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "bundle_identifier",
            reason: "value must contain at least two valid dot-separated segments",
        });
    }
    Ok(())
}

fn validate_ios_version(value: &str) -> RemoteBuildResult<()> {
    validate_safe_text("minimum_ios_version", value, 32)?;
    let components = value.split('.').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 3
        || components.iter().any(|component| {
            component.is_empty()
                || (component.len() > 1 && component.starts_with('0'))
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || component.parse::<u16>().is_err()
        })
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "minimum_ios_version",
            reason: "value must contain one to three canonical numeric components",
        });
    }
    Ok(())
}

fn validate_product_expectation(
    product: &IosDeviceProductExpectation,
    main_bundle_identifier: &str,
    signing: &SigningPlan,
) -> RemoteBuildResult<()> {
    validate_portable_component("app_directory_name", &product.app_directory_name)?;
    if !has_exact_extension(&product.app_directory_name, "app") {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "app_directory_name",
            reason: "value must end with .app",
        });
    }
    validate_portable_component("executable", &product.executable)?;
    validate_bundle_version("app_version", &product.app_version)?;
    validate_bundle_version("build_number", &product.build_number)?;
    if product.nested_bundles.len() > 512 {
        return Err(RemoteBuildError::InvalidEventPayload {
            event: "ios_device_build_request",
            reason: "product contains too many nested bundles",
        });
    }

    let mut paths = BTreeSet::new();
    let mut portable_paths = BTreeSet::new();
    let mut bundle_identifiers = BTreeSet::from([main_bundle_identifier.to_owned()]);
    let mut product_targets = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for nested in &product.nested_bundles {
        if previous_path.is_some_and(|previous| previous >= nested.relative_path.as_str()) {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "nested product bundles must be strictly sorted by path",
            });
        }
        previous_path = Some(&nested.relative_path);
        validate_nested_bundle_path(&nested.relative_path, nested.kind)?;
        validate_portable_component("nested_executable", &nested.executable)?;
        validate_bundle_identifier(&nested.bundle_identifier)?;
        if !paths.insert(nested.relative_path.as_str())
            || !portable_paths.insert(portable_name_key(&nested.relative_path))
            || !bundle_identifiers.insert(nested.bundle_identifier.clone())
        {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "ios_device_build_request",
                reason: "nested product bundles contain duplicate or portable-colliding identities",
            });
        }
        let signing_kind = match nested.kind {
            UnsignedNestedBundleKind::AppExtension => SigningTargetKind::Extension,
            UnsignedNestedBundleKind::Framework => SigningTargetKind::Framework,
        };
        product_targets.insert((nested.bundle_identifier.as_str(), signing_kind));
    }

    let signing_targets = signing
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.kind,
                SigningTargetKind::Extension | SigningTargetKind::Framework
            )
        })
        .map(|target| (target.bundle_identifier.as_str(), target.kind))
        .collect::<BTreeSet<_>>();
    if product_targets != signing_targets {
        return Err(RemoteBuildError::InvalidEventPayload {
            event: "ios_device_build_request",
            reason: "product nested bundle graph does not match signing targets",
        });
    }
    Ok(())
}

fn validate_portable_component(field: &'static str, value: &str) -> RemoteBuildResult<()> {
    validate_safe_text(field, value, 255)?;
    if matches!(value, "." | "..")
        || value.contains(['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'])
        || value.ends_with(['.', ' '])
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value is not a portable filename component",
        });
    }
    let basename = value
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
    if reserved {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value is reserved on a supported client filesystem",
        });
    }
    Ok(())
}

fn validate_nested_bundle_path(
    path: &str,
    kind: UnsignedNestedBundleKind,
) -> RemoteBuildResult<()> {
    validate_safe_text("nested_bundle_path", path, 1024)?;
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() != 2 {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "nested_bundle_path",
            reason: "value must be directly below PlugIns or Frameworks",
        });
    }
    validate_portable_component("nested_bundle_directory", components[1])?;
    let valid = match kind {
        UnsignedNestedBundleKind::AppExtension => {
            components[0] == "PlugIns" && has_exact_extension(components[1], "appex")
        }
        UnsignedNestedBundleKind::Framework => {
            components[0] == "Frameworks" && has_exact_extension(components[1], "framework")
        }
    };
    if !valid {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "nested_bundle_path",
            reason: "value does not match its nested bundle kind",
        });
    }
    Ok(())
}

fn validate_bundle_version(field: &'static str, value: &str) -> RemoteBuildResult<()> {
    validate_safe_text(field, value, 64)?;
    let components = value.split('.').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 3
        || components.iter().any(|component| {
            component.is_empty()
                || (component.len() > 1 && component.starts_with('0'))
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || component.parse::<u32>().is_err()
        })
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field,
            reason: "value must contain one to three canonical numeric components",
        });
    }
    Ok(())
}

fn portable_name_key(value: &str) -> String {
    value.nfkc().flat_map(char::to_lowercase).collect()
}

fn has_exact_extension(value: &str, expected: &str) -> bool {
    value
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension == expected)
}

fn validate_github_repository(value: &str) -> RemoteBuildResult<()> {
    validate_safe_text("source_repository", value, 2048)?;
    let repository = url::Url::parse(value).map_err(|_| RemoteBuildError::InvalidIdentifier {
        field: "source_repository",
        reason: "value is not a valid URL",
    })?;
    if repository.scheme() != "https"
        || repository.host_str() != Some("github.com")
        || repository.port().is_some()
        || !repository.username().is_empty()
        || repository.password().is_some()
        || repository.query().is_some()
        || repository.fragment().is_some()
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "source_repository",
            reason: "value must be a credential-free HTTPS GitHub repository URL",
        });
    }

    let segments = repository
        .path_segments()
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    if segments.len() != 2 || !segments.iter().copied().all(is_github_name) {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "source_repository",
            reason: "value must contain exactly one GitHub owner and repository",
        });
    }
    let canonical = format!("https://github.com/{}/{}", segments[0], segments[1]);
    if value != canonical {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "source_repository",
            reason: "value is not normalized",
        });
    }
    Ok(())
}

fn is_github_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_git_revision(value: &str) -> RemoteBuildResult<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RemoteBuildError::InvalidIdentifier {
            field: "source_revision",
            reason: "value must be an exact lowercase 40-hex commit SHA",
        });
    }
    Ok(())
}

fn validate_no_terminal_escape(value: &Value) -> RemoteBuildResult<()> {
    match value {
        Value::String(text) if text.contains('\u{1b}') => {
            Err(RemoteBuildError::UnsafeEventText { field: "event" })
        }
        Value::Array(values) => {
            for value in values {
                validate_no_terminal_escape(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_no_terminal_escape(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_absolute_path_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('/')
        || value.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_artifact_selection_requires_ipa_and_signing_report() {
        let valid = BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport]);
        assert!(
            validate_requested_artifact_selection(SigningMode::ManualDevelopment, &valid).is_ok()
        );

        for (requested, expected_reason) in [
            (
                BTreeSet::from([IosArtifactType::SigningReport]),
                "signed builds must request the installable IPA",
            ),
            (
                BTreeSet::from([IosArtifactType::Ipa]),
                "signed builds must request the signing report",
            ),
        ] {
            assert!(matches!(
                validate_requested_artifact_selection(
                    SigningMode::ManualDevelopment,
                    &requested
                ),
                Err(RemoteBuildError::InvalidEventPayload { reason, .. })
                    if reason == expected_reason
            ));
        }
    }
}
