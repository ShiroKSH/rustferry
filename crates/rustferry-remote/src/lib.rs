//! Cross-platform contracts for `RustFerry` remote Apple builds.
//!
//! This crate contains data and provider boundaries only. Provider implementations own
//! networking and process execution; callers choose the async runtime, if any.

#![forbid(unsafe_code)]

/// Artifact manifests and independent artifact validation.
pub mod artifact;
/// Runtime-neutral cooperative cancellation.
pub mod cancellation;
/// Length-framed binary transport for large worker source and artifact payloads.
pub mod data_plane;
/// Typed protocol and provider failures.
pub mod error;
/// Public compile-to-sign handoff evidence.
pub mod handoff;
/// Bounded parsing and target validation for decoded Apple provisioning profiles.
pub mod profile;
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
/// Strict control messages for one framed SSH snapshot-build session.
pub mod snapshot_session;
/// Deterministic Git and snapshot source manifests.
pub mod source;
/// Strict, bounded envelopes for one-request worker stdio control planes.
pub mod stdio;

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
pub use data_plane::{
    MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES, MAX_WORKER_DATA_PLANE_CONTROL_BYTES,
    MAX_WORKER_DATA_PLANE_REQUEST_BYTES, MAX_WORKER_DATA_PLANE_RESULT_BYTES,
    MAX_WORKER_DATA_PLANE_SOURCE_BYTES, WORKER_DATA_PLANE_HEADER_BYTES,
    WORKER_DATA_PLANE_SCHEMA_VERSION, WorkerDataPlaneFrameError, WorkerDataPlaneFrameHeader,
    WorkerDataPlaneFrameKind, WorkerDataPlaneSequence, copy_worker_data_plane_payload,
    read_worker_data_plane_header, read_worker_data_plane_payload, write_worker_data_plane_frame,
    write_worker_data_plane_header, write_worker_data_plane_stream,
};
pub use error::{RemoteBuildError, RemoteBuildResult};
pub use handoff::{
    COMPILE_HANDOFF_SCHEMA_VERSION, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CompileHandoff,
    CompilePhaseEvidence, CompileToolchainEvidence, SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
    SealedUnsignedArchive,
};
pub use profile::{
    MAX_DECODED_PROFILE_BYTES, ProfileField, ProfileValidationErrors, ProfileValidationIssue,
    ProfileValidationRequest, ProvisioningProfileParseError, ValidatedProvisioningProfile,
    parse_decoded_provisioning_profile, parse_provisioning_profile_value,
    validate_profile_for_target,
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
pub use snapshot_session::{
    MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES, SNAPSHOT_SESSION_SCHEMA_VERSION,
    SnapshotArtifactDescriptor, SnapshotArtifactReceipt, SnapshotBuildComplete,
    SnapshotBuildParameters, SnapshotBuildStart, SnapshotJobAccepted, SnapshotSessionError,
};
pub use source::{
    IgnoreRuleReason, MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES, PlannedSourceFile, PortablePathReason,
    SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION, SourceArchive, SourceArchiveLimits,
    SourceBundleDescriptor, SourceBundlePlan, SourceBundleRequest, SourceError, SourceLimitKind,
    SourceLimits, SourceManifest, SourceManifestEntry, SourceMode, create_source_bundle_archive,
    plan_source_bundle, validate_source_manifest, verify_and_extract_source_bundle,
    verify_materialized_bundle, verify_source_bundle_plan, verify_source_manifest,
    write_source_bundle_descriptor_file,
};
pub use stdio::{
    MAX_WORKER_STDIO_REQUEST_BYTES, MAX_WORKER_STDIO_RESPONSE_BYTES, WORKER_STDIO_SCHEMA_VERSION,
    WorkerStdioCodecError, WorkerStdioErrorResponse, WorkerStdioRequest,
    WorkerStdioRequestEnvelope, WorkerStdioResponse, WorkerStdioResponseEnvelope,
    decode_worker_stdio_request, decode_worker_stdio_response, encode_worker_stdio_request,
    encode_worker_stdio_response,
};
