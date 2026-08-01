//! Cross-platform contracts for `RustFerry` remote Apple builds.
//!
//! This crate contains data and provider boundaries only. Provider implementations own
//! networking and process execution; callers choose the async runtime, if any.

#![forbid(unsafe_code)]

/// Artifact manifests and independent artifact validation.
pub mod artifact;
/// Runtime-neutral cooperative cancellation.
pub mod cancellation;
/// Typed protocol and provider failures.
pub mod error;
/// Public compile-to-sign handoff evidence.
pub mod handoff;
/// Ferry Remote Build Protocol v1 data and NDJSON events.
pub mod protocol;
/// Runtime-neutral asynchronous build-provider boundary.
pub mod provider;
/// Chunk-safe secret redaction.
pub mod redaction;
/// Checked-in JSON Schema generation.
pub mod schema;
/// Non-serializable secret values and serializable opaque references.
pub mod secret;
/// Apple signing plans and validation models.
pub mod signing;
/// Deterministic Git and snapshot source manifests.
pub mod source;

pub use artifact::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ApplePlatform, AppleToolchainEvidence, ArtifactError,
    ArtifactKind, ArtifactManifest, ArtifactRecord, ArtifactSigningEvidence, CleanupStatus,
    IosDeviceProductExpectation, IpaExpectation, IpaInspection, MachOSliceEvidence,
    UnsignedAppInspection, UnsignedNestedBundleExpectation, UnsignedNestedBundleKind,
    UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection, ValidationLevel, inspect_ipa,
    inspect_physical_iphone_macho, inspect_unsigned_app_bundle, inspect_unsigned_xcarchive,
    verify_downloaded_file,
};
pub use cancellation::CancellationToken;
pub use error::{RemoteBuildError, RemoteBuildResult};
pub use handoff::{
    COMPILE_HANDOFF_SCHEMA_VERSION, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CompileHandoff,
    CompilePhaseEvidence, CompileToolchainEvidence, SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
    SealedUnsignedArchive,
};
pub use protocol::{
    BuildProfile, CURRENT_PROTOCOL_VERSION, CleanupConfirmation, DiagnosticSeverity,
    IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK, IosArtifactType, IosDeviceBuildRequest,
    IosDeviceBuildResult, JobState, ProtocolPath, ProtocolPathSemantics, ProtocolVersion,
    REMOTE_BUILD_EVENT_TYPES, RemoteBuildEvent, RemoteBuildEventKind, RemoteDiagnostic,
    RemoteErrorInfo, canonical_request_bytes, canonical_request_sha256,
};
pub use provider::{
    ArtifactDownloadRequest, ArtifactDownloadResult, ArtifactListRequest, BuildProvider,
    CancellationAck, CancellationRequest, CleanupRequest, EventPage, EventRequest,
    HandshakeRequest, HandshakeResponse, JobHandle, ProviderCapabilities, ProviderCheck,
    ProviderCheckStatus, ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature,
    ProviderFuture,
};
pub use redaction::{
    CommandOutputRedactor, OutputStream, REDACTION_MARKER, RedactionError, SecretRedactor,
    StreamingRedactor,
};
pub use schema::{RemoteProtocolV1Document, protocol_v1_schema_json};
pub use secret::{Secret, SecretBytes, SecretReference, SecretReferenceError, SecretReferenceKind};
pub use signing::{
    BundleIdentifier, DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan,
    EntitlementSet, EntitlementValueError, ProvisioningPlan, ProvisioningPlatform,
    ProvisioningProfile, ProvisioningProfileType, SigningCertificate, SigningIdentity, SigningMode,
    SigningPlan, SigningPrivateKeyReference, SigningReference, SigningStatus, SigningTarget,
    SigningTargetKind, SigningValidationError, SigningValidationErrors, SigningValidationReport,
    ValidationComponent, ValidationStatus,
};
pub use source::{
    IgnoreRuleReason, PlannedSourceFile, PortablePathReason, SourceArchive, SourceArchiveLimits,
    SourceBundlePlan, SourceBundleRequest, SourceError, SourceLimitKind, SourceLimits,
    SourceManifest, SourceManifestEntry, SourceMode, create_source_bundle_archive,
    plan_source_bundle, validate_source_manifest, verify_and_extract_source_bundle,
    verify_materialized_bundle, verify_source_bundle_plan, verify_source_manifest,
};
