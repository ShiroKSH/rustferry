use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    artifact::ArtifactManifest,
    cancellation::CancellationToken,
    error::{RemoteBuildError, RemoteBuildResult},
    protocol::{
        CURRENT_PROTOCOL_VERSION, CleanupConfirmation, IosArtifactType, IosDeviceBuildRequest,
        JobState, ProtocolPath, ProtocolPathSemantics, ProtocolVersion, RemoteBuildEvent,
        validate_identifier,
    },
    signing::SigningMode,
    source::SourceMode,
};

/// Boxed, runtime-neutral future returned by provider trait methods.
pub type ProviderFuture<'a, T> = Pin<Box<dyn Future<Output = RemoteBuildResult<T>> + Send + 'a>>;

/// One typed feature that a caller may require from a provider.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "feature", content = "value")]
pub enum ProviderFeature {
    /// Exact source transport.
    SourceMode(SourceMode),
    /// Physical-iPhone compilation and packaging.
    IosDeviceBuild,
    /// iOS Simulator compilation.
    IosSimulatorBuild,
    /// Exact signing strategy.
    SigningMode(SigningMode),
    /// Apple Personal Team provisioning.
    PersonalTeam,
    /// Incremental job-event retrieval.
    LiveEvents,
    /// Live application or build-log events.
    LiveLogs,
    /// Remote job cancellation.
    Cancellation,
    /// Exact artifact format.
    ArtifactType(IosArtifactType),
    /// Provider-side build cache.
    Cache,
    /// Artifact manifest enumeration.
    ArtifactListing,
    /// Verified artifact download.
    ArtifactDownload,
    /// Explicit remote-workspace cleanup.
    Cleanup,
    /// Access to a physical iPhone attached to the worker.
    PhysicalDeviceAccess,
}

impl fmt::Display for ProviderFeature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMode(mode) => write!(formatter, "source mode `{mode:?}`"),
            Self::IosDeviceBuild => formatter.write_str("physical-iPhone builds"),
            Self::IosSimulatorBuild => formatter.write_str("iOS Simulator builds"),
            Self::SigningMode(mode) => write!(formatter, "signing mode `{mode:?}`"),
            Self::PersonalTeam => formatter.write_str("Apple Personal Team signing"),
            Self::LiveEvents => formatter.write_str("live build events"),
            Self::LiveLogs => formatter.write_str("live logs"),
            Self::Cancellation => formatter.write_str("job cancellation"),
            Self::ArtifactType(kind) => write!(formatter, "artifact type `{kind}`"),
            Self::Cache => formatter.write_str("provider build cache"),
            Self::ArtifactListing => formatter.write_str("artifact listing"),
            Self::ArtifactDownload => formatter.write_str("artifact download"),
            Self::Cleanup => formatter.write_str("remote cleanup"),
            Self::PhysicalDeviceAccess => formatter.write_str("physical-device access"),
        }
    }
}

/// Deterministic capability inventory returned during handshake and doctor.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderCapabilities {
    /// Supported exact source modes.
    pub source_modes: BTreeSet<SourceMode>,
    /// Whether physical-iPhone builds are implemented.
    pub ios_device_build: bool,
    /// Whether iOS Simulator builds are implemented.
    pub ios_simulator_build: bool,
    /// Supported signing strategies.
    pub signing_modes: BTreeSet<SigningMode>,
    /// Whether Apple Personal Team provisioning is supported.
    pub personal_team: bool,
    /// Whether callers can retrieve incremental events.
    pub live_events: bool,
    /// Whether the provider exposes live log events.
    pub live_logs: bool,
    /// Whether the provider can cancel an active job.
    pub cancellation: bool,
    /// Artifact types the provider can return.
    pub artifact_types: BTreeSet<IosArtifactType>,
    /// Whether provider-side compilation caches are enabled.
    pub cache: bool,
    /// Maximum accepted source bytes, or no provider-advertised limit.
    pub max_source_bytes: Option<u64>,
    /// Artifact retention window in seconds, or provider-defined retention.
    pub retention_seconds: Option<u64>,
    /// Whether artifact manifests can be enumerated after a job.
    pub artifact_listing: bool,
    /// Whether verified artifact download is implemented.
    pub artifact_download: bool,
    /// Whether explicit job cleanup is implemented.
    pub cleanup: bool,
    /// Whether a worker may access an attached physical device.
    pub physical_device_access: bool,
}

impl ProviderCapabilities {
    /// Whether this inventory satisfies one exact feature.
    pub fn supports(&self, feature: &ProviderFeature) -> bool {
        match feature {
            ProviderFeature::SourceMode(mode) => self.source_modes.contains(mode),
            ProviderFeature::IosDeviceBuild => self.ios_device_build,
            ProviderFeature::IosSimulatorBuild => self.ios_simulator_build,
            ProviderFeature::SigningMode(mode) => self.signing_modes.contains(mode),
            ProviderFeature::PersonalTeam => self.personal_team,
            ProviderFeature::LiveEvents => self.live_events,
            ProviderFeature::LiveLogs => self.live_logs,
            ProviderFeature::Cancellation => self.cancellation,
            ProviderFeature::ArtifactType(kind) => self.artifact_types.contains(kind),
            ProviderFeature::Cache => self.cache,
            ProviderFeature::ArtifactListing => self.artifact_listing,
            ProviderFeature::ArtifactDownload => self.artifact_download,
            ProviderFeature::Cleanup => self.cleanup,
            ProviderFeature::PhysicalDeviceAccess => self.physical_device_access,
        }
    }

    /// Return a typed error when a provider lacks one required feature.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::UnsupportedCapability`] when the feature is absent.
    pub fn require(
        &self,
        provider: impl Into<String>,
        feature: ProviderFeature,
    ) -> RemoteBuildResult<()> {
        if self.supports(&feature) {
            Ok(())
        } else {
            Err(RemoteBuildError::UnsupportedCapability {
                provider: provider.into(),
                feature,
            })
        }
    }
}

/// Versioned client handshake request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HandshakeRequest {
    /// Highest protocol version supported by the client.
    pub protocol_version: ProtocolVersion,
    /// `RustFerry` client semantic version.
    pub client_version: Version,
    /// Features required before the client may submit a job.
    pub required_features: Vec<ProviderFeature>,
}

impl HandshakeRequest {
    /// Validate protocol compatibility with this client library.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::IncompatibleProtocolVersion`] for another major version.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        CURRENT_PROTOCOL_VERSION
            .negotiate(self.protocol_version)
            .map(|_| ())
    }
}

/// Versioned worker handshake response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HandshakeResponse {
    /// Negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// `RustFerry` worker semantic version.
    pub worker_version: Version,
    /// Stable provider identifier.
    pub provider: String,
    /// Stable, non-secret worker identifier.
    pub worker_id: String,
    /// Capabilities active for this worker and provider configuration.
    pub capabilities: ProviderCapabilities,
}

impl HandshakeResponse {
    /// Build a response using the highest compatible protocol version.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatible versions, unsafe IDs, or missing capabilities.
    pub fn negotiate(
        request: &HandshakeRequest,
        provider: impl Into<String>,
        worker_id: impl Into<String>,
        worker_version: Version,
        capabilities: ProviderCapabilities,
    ) -> RemoteBuildResult<Self> {
        let protocol_version = CURRENT_PROTOCOL_VERSION.negotiate(request.protocol_version)?;
        let response = Self {
            protocol_version,
            worker_version,
            provider: provider.into(),
            worker_id: worker_id.into(),
            capabilities,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Validate identity, version, and required capabilities against a request.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatible versions, unsafe IDs, or missing capabilities.
    pub fn validate_for(&self, request: &HandshakeRequest) -> RemoteBuildResult<()> {
        request.validate()?;
        request
            .protocol_version
            .negotiate(self.protocol_version)
            .map(|_| ())?;
        validate_identifier("provider", &self.provider)?;
        validate_identifier("worker_id", &self.worker_id)?;
        for feature in &request.required_features {
            self.capabilities
                .require(self.provider.clone(), feature.clone())?;
        }
        Ok(())
    }
}

/// Versioned provider readiness request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderDoctorRequest {
    /// Negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// Caller-owned operation identifier.
    pub operation_id: String,
    /// Whether signing prerequisites must be checked.
    pub require_signing: bool,
}

/// Result status of one provider doctor check.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCheckStatus {
    /// Check passed.
    Ready,
    /// Optional feature is degraded.
    Warning,
    /// Required feature is unavailable.
    Error,
}

/// One safe provider doctor check.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderCheck {
    /// Stable check identifier.
    pub code: String,
    /// Check result.
    pub status: ProviderCheckStatus,
    /// Sanitized human summary.
    pub message: String,
    /// Optional concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

/// Provider readiness and capability report.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderDoctorReport {
    /// Negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// Stable provider identifier.
    pub provider: String,
    /// Whether every required check passed.
    pub ready: bool,
    /// Deterministically ordered checks.
    pub checks: Vec<ProviderCheck>,
    /// Capabilities available under the checked configuration.
    pub capabilities: ProviderCapabilities,
}

/// Provider response after accepting a build request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct JobHandle {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Initial provider state.
    pub state: JobState,
    /// Milliseconds since Unix epoch in UTC.
    pub created_at_ms: u64,
}

/// Request for an ordered page of job events.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EventRequest {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Last sequence already consumed, or none for the first page.
    pub after_sequence: Option<u64>,
    /// Maximum events to return; must be between 1 and 1000.
    pub limit: u32,
}

impl EventRequest {
    /// Validate identifier and page bound.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an invalid job ID or page limit.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        validate_identifier("job_id", &self.job_id)?;
        if !(1..=1000).contains(&self.limit) {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "event_request",
                reason: "limit must be between 1 and 1000",
            });
        }
        Ok(())
    }
}

/// Ordered provider event page.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct EventPage {
    /// Stable provider job identifier.
    pub job_id: String,
    /// State observed with this page.
    pub state: JobState,
    /// Strictly ordered events.
    pub events: Vec<RemoteBuildEvent>,
    /// Sequence to use for the next page, when more data may arrive.
    pub next_sequence: Option<u64>,
    /// Whether the provider has no further events for this job.
    pub complete: bool,
}

/// Request to cancel an active provider job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CancellationRequest {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Safe, stable cancellation reason.
    pub reason: String,
}

/// Provider acknowledgement of a cancellation request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CancellationAck {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Whether this request initiated cancellation.
    pub accepted: bool,
    /// State observed after handling the request.
    pub state: JobState,
}

/// Request to enumerate artifact manifests for one job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactListRequest {
    /// Stable provider job identifier.
    pub job_id: String,
}

/// Request to download one artifact to an explicit client path.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactDownloadRequest {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Stable artifact identifier from its manifest.
    pub artifact_id: String,
    /// Absolute client destination. Providers must not reinterpret it as a worker path.
    pub destination: ProtocolPath,
}

impl ArtifactDownloadRequest {
    /// Validate identifiers and destination semantics.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for invalid IDs or a non-client destination.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        validate_identifier("job_id", &self.job_id)?;
        validate_identifier("artifact_id", &self.artifact_id)?;
        self.destination.validate()?;
        if self.destination.semantics != ProtocolPathSemantics::ClientAbsolute {
            return Err(RemoteBuildError::InvalidEventPayload {
                event: "artifact_download_request",
                reason: "destination must be client_absolute",
            });
        }
        Ok(())
    }
}

/// Verified result of one provider artifact download.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactDownloadResult {
    /// Verified manifest supplied by the worker.
    pub manifest: ArtifactManifest,
    /// Absolute client path containing verified bytes.
    pub local_path: ProtocolPath,
    /// Canonical, secret-free identity captured from the retained published file object.
    pub local_file_identity: String,
}

/// Request to remove provider-owned material for one job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CleanupRequest {
    /// Stable provider job identifier.
    pub job_id: String,
    /// Whether retained artifact bytes should also be removed.
    pub remove_artifacts: bool,
}

/// Object-safe asynchronous provider interface without a required executor or runtime.
///
/// Implementations return boxed futures and must not report success until the corresponding
/// provider operation is confirmed. Optional methods return `unsupported_capability` by default.
pub trait BuildProvider: Send + Sync {
    /// Stable provider identifier used in events and errors.
    fn id(&self) -> &str;

    /// Capabilities active for this provider configuration.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Negotiate protocol and worker compatibility.
    fn handshake(
        &self,
        request: HandshakeRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, HandshakeResponse>;

    /// Inspect provider, worker, and optional signing readiness.
    fn doctor(
        &self,
        request: ProviderDoctorRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ProviderDoctorReport>;

    /// Submit one declarative physical-iPhone build.
    fn submit(
        &self,
        request: IosDeviceBuildRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, JobHandle>;

    /// Retrieve a bounded ordered page of events.
    fn events(
        &self,
        request: EventRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, EventPage>;

    /// Request cancellation of an active job.
    fn cancel(
        &self,
        _request: CancellationRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, CancellationAck> {
        let result = cancellation.check().and_then(|()| {
            self.capabilities()
                .require(self.id().to_owned(), ProviderFeature::Cancellation)
                .and_then(|()| {
                    Err(RemoteBuildError::UnsupportedCapability {
                        provider: self.id().to_owned(),
                        feature: ProviderFeature::Cancellation,
                    })
                })
        });
        Box::pin(async move { result })
    }

    /// List verified artifact manifests for a job.
    fn list_artifacts(
        &self,
        _request: ArtifactListRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, Vec<ArtifactManifest>> {
        let result = cancellation.check().and_then(|()| {
            Err(RemoteBuildError::UnsupportedCapability {
                provider: self.id().to_owned(),
                feature: ProviderFeature::ArtifactListing,
            })
        });
        Box::pin(async move { result })
    }

    /// Download and independently verify one artifact.
    fn download_artifact(
        &self,
        _request: ArtifactDownloadRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ArtifactDownloadResult> {
        let result = cancellation.check().and_then(|()| {
            Err(RemoteBuildError::UnsupportedCapability {
                provider: self.id().to_owned(),
                feature: ProviderFeature::ArtifactDownload,
            })
        });
        Box::pin(async move { result })
    }

    /// Delete provider-owned workspace, signing material, and optional retained artifacts.
    fn cleanup(
        &self,
        _request: CleanupRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, CleanupConfirmation> {
        let result = cancellation.check().and_then(|()| {
            Err(RemoteBuildError::UnsupportedCapability {
                provider: self.id().to_owned(),
                feature: ProviderFeature::Cleanup,
            })
        });
        Box::pin(async move { result })
    }
}
