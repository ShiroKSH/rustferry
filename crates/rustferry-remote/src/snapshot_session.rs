//! Strict control messages for one framed SSH snapshot-build session.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CURRENT_PROTOCOL_VERSION, CompilePhaseEvidence,
    IosArtifactType, IosDeviceBuildRequest, IosDeviceProductExpectation, JobHandle, JobState,
    ProtocolPath, ProtocolPathSemantics, ProtocolVersion, RemoteBuildError, RemoteBuildResult,
    SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SigningMode, SigningPlan, SourceArchive,
    SourceArchiveLimits, SourceBundleDescriptor, SourceLimits, SourceMode,
    artifact::ArtifactKind,
    artifact::ArtifactRecord,
    data_plane::{MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES, MAX_WORKER_DATA_PLANE_SOURCE_BYTES},
    protocol::{BuildProfile, CleanupConfirmation, IOS_DEVICE_RUST_TARGET, validate_identifier},
    source::validate_source_manifest,
};

/// Current schema for snapshot-session control messages.
pub const SNAPSHOT_SESSION_SCHEMA_VERSION: u32 = 1;
/// Maximum source-descriptor JSON size accepted by the interactive snapshot session.
pub const MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES: u64 = 8 * 1024 * 1024;

const MAX_PUBLIC_ERROR_CODE_BYTES: usize = 96;
const MAX_PUBLIC_ERROR_MESSAGE_BYTES: usize = 512;
const MAX_PUBLIC_VERSION_BYTES: usize = 128;
const MAX_PUBLIC_TOOLCHAIN_TEXT_BYTES: usize = 512;
const MAX_ARTIFACT_FILE_NAME_BYTES: usize = 255;
const MAX_MEDIA_TYPE_BYTES: usize = 128;

/// Compact build fields sent before the separately framed source descriptor.
///
/// This deliberately excludes `source`, `source_mode`, `source_repository`, and
/// `source_revision`. The worker reconstructs the complete request only after
/// validating the separately transported [`SourceBundleDescriptor`].
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBuildParameters {
    /// Requested Ferry Remote Build Protocol version.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Caller-owned operation identifier.
    pub operation_id: String,
    /// Human-readable product name.
    pub product_name: String,
    /// Exact Apple application bundle identifier.
    pub bundle_identifier: String,
    /// Minimum supported iOS version.
    pub minimum_ios_version: String,
    /// Client-derived product identity.
    pub product: IosDeviceProductExpectation,
    /// Rust/Xcode optimization profile.
    pub profile: BuildProfile,
    /// Unsigned compile-only plan.
    pub signing: SigningPlan,
    /// Exact requested artifact set; snapshot session v1 accepts only `xcarchive`.
    pub requested_artifacts: BTreeSet<IosArtifactType>,
}

impl SnapshotBuildParameters {
    /// Convert one complete request into compact snapshot-session parameters.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request, non-snapshot source, signed build, or any
    /// artifact set other than exactly one unsigned Xcode archive.
    pub fn from_request(request: &IosDeviceBuildRequest) -> RemoteBuildResult<Self> {
        request.validate()?;
        if request.source_mode != SourceMode::Snapshot {
            return Err(invalid(
                "snapshot_build_parameters",
                "snapshot session requires snapshot source mode",
            ));
        }
        require_unsigned_xcarchive(&request.signing, &request.requested_artifacts)?;
        let parameters = Self {
            protocol_version: request.protocol_version,
            operation_id: request.operation_id.clone(),
            product_name: request.product_name.clone(),
            bundle_identifier: request.bundle_identifier.clone(),
            minimum_ios_version: request.minimum_ios_version.clone(),
            product: request.product.clone(),
            profile: request.profile,
            signing: request.signing.clone(),
            requested_artifacts: request.requested_artifacts.clone(),
        };
        parameters.validate_shape()?;
        Ok(parameters)
    }

    /// Reconstruct and fully validate a request using one separately received descriptor.
    ///
    /// # Errors
    ///
    /// Rejects malformed descriptor metadata, invalid compact fields, or any
    /// complete request that violates the physical-iPhone build contract.
    pub fn reconstruct_request(
        &self,
        descriptor: &SourceBundleDescriptor,
        limits: SourceArchiveLimits,
    ) -> RemoteBuildResult<IosDeviceBuildRequest> {
        self.validate_shape()?;
        descriptor.validate(limits).map_err(|_| {
            invalid(
                "snapshot_build_parameters",
                "source bundle descriptor is invalid",
            )
        })?;
        let request = IosDeviceBuildRequest {
            protocol_version: self.protocol_version,
            operation_id: self.operation_id.clone(),
            product_name: self.product_name.clone(),
            bundle_identifier: self.bundle_identifier.clone(),
            minimum_ios_version: self.minimum_ios_version.clone(),
            product: self.product.clone(),
            profile: self.profile,
            source_mode: SourceMode::Snapshot,
            source_repository: None,
            source_revision: None,
            source: descriptor.manifest.clone(),
            signing: self.signing.clone(),
            requested_artifacts: self.requested_artifacts.clone(),
        };
        request.validate()?;
        require_unsigned_xcarchive(&request.signing, &request.requested_artifacts)?;
        Ok(request)
    }

    fn validate_shape(&self) -> RemoteBuildResult<()> {
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_public_text(&self.product_name, 255, "snapshot_build_parameters")?;
        validate_bundle_identifier(&self.bundle_identifier)?;
        validate_ios_version(&self.minimum_ios_version)?;
        validate_portable_component(&self.product.app_directory_name)?;
        validate_portable_component(&self.product.executable)?;
        self.signing.validate().map_err(|_| {
            invalid(
                "snapshot_build_parameters",
                "unsigned signing plan is invalid",
            )
        })?;
        require_unsigned_xcarchive(&self.signing, &self.requested_artifacts)
    }
}

impl TryFrom<&IosDeviceBuildRequest> for SnapshotBuildParameters {
    type Error = RemoteBuildError;

    fn try_from(request: &IosDeviceBuildRequest) -> Result<Self, Self::Error> {
        Self::from_request(request)
    }
}

/// Initial control frame for one snapshot-build session.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBuildStart {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Compact request fields.
    pub parameters: SnapshotBuildParameters,
    /// Exact separately framed descriptor byte length.
    pub source_descriptor_size: u64,
    /// SHA-256 of the exact separately framed descriptor JSON bytes.
    pub source_descriptor_sha256: String,
    /// Exact separately framed deterministic ZIP size and SHA-256.
    pub source_archive: SourceArchive,
}

impl SnapshotBuildStart {
    /// Construct one bounded source-transfer declaration.
    ///
    /// # Errors
    ///
    /// Rejects invalid compact parameters, empty/oversized transfers, or malformed hashes.
    pub fn new(
        parameters: SnapshotBuildParameters,
        source_descriptor_size: u64,
        source_descriptor_sha256: impl Into<String>,
        source_archive: SourceArchive,
    ) -> RemoteBuildResult<Self> {
        let start = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            parameters,
            source_descriptor_size,
            source_descriptor_sha256: source_descriptor_sha256.into(),
            source_archive,
        };
        start.validate()?;
        Ok(start)
    }

    /// Validate the bounded transfer declaration before reading large payloads.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, invalid parameters, size overflow, or malformed hashes.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_build_start")?;
        self.parameters.validate_shape()?;
        if self.source_descriptor_size == 0
            || self.source_descriptor_size > MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES
        {
            return Err(invalid(
                "snapshot_build_start",
                "source descriptor size is outside the fixed limit",
            ));
        }
        validate_sha256(&self.source_descriptor_sha256, "snapshot_build_start")?;
        validate_transfer_archive(
            &self.source_archive,
            MAX_WORKER_DATA_PLANE_SOURCE_BYTES,
            "snapshot_build_start",
        )
    }

    /// Bind the received descriptor to the declared archive and reconstruct the full request.
    ///
    /// # Errors
    ///
    /// Rejects descriptor/archive substitution or any invalid reconstructed request.
    pub fn reconstruct_request(
        &self,
        descriptor: &SourceBundleDescriptor,
        limits: SourceArchiveLimits,
    ) -> RemoteBuildResult<IosDeviceBuildRequest> {
        self.validate()?;
        descriptor.validate(limits).map_err(|_| {
            invalid(
                "snapshot_build_start",
                "source bundle descriptor is invalid",
            )
        })?;
        if descriptor.archive != self.source_archive {
            return Err(invalid(
                "snapshot_build_start",
                "source archive declaration does not match the descriptor",
            ));
        }
        self.parameters.reconstruct_request(descriptor, limits)
    }
}

/// Worker acknowledgement after allocating one snapshot job.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotJobAccepted {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Negotiated Ferry Remote Build Protocol version.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Operation identifier copied from the build start.
    pub operation_id: String,
    /// Provider-owned job identifier.
    pub job_id: String,
    /// Initial state; always `created`.
    pub state: JobState,
    /// Milliseconds since Unix epoch in UTC.
    pub created_at_ms: u64,
}

impl SnapshotJobAccepted {
    /// Construct one initial job acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects unsafe operation or job identifiers.
    pub fn new(
        operation_id: impl Into<String>,
        job_id: impl Into<String>,
        created_at_ms: u64,
    ) -> RemoteBuildResult<Self> {
        let accepted = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: operation_id.into(),
            job_id: job_id.into(),
            state: JobState::Created,
            created_at_ms,
        };
        accepted.validate()?;
        Ok(accepted)
    }

    /// Validate schema, protocol, identity, and initial-state invariants.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, unsafe identifiers, or a non-created state.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_job_accepted")?;
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        if self.state != JobState::Created {
            return Err(invalid(
                "snapshot_job_accepted",
                "accepted job state must be created",
            ));
        }
        Ok(())
    }

    /// Convert the acknowledgement into the provider-neutral job handle.
    #[must_use]
    pub fn job_handle(&self) -> JobHandle {
        JobHandle {
            job_id: self.job_id.clone(),
            state: self.state,
            created_at_ms: self.created_at_ms,
        }
    }
}

/// Exact unsigned archive record and compile evidence preceding artifact bytes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArtifactDescriptor {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Negotiated Ferry Remote Build Protocol version.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Operation identifier from the submitted request.
    pub operation_id: String,
    /// Provider-owned job identifier.
    pub job_id: String,
    /// Exact returned file name, size, and SHA-256.
    pub artifact: ArtifactRecord,
    /// Credential-free physical-iPhone compile evidence.
    pub compile: CompilePhaseEvidence,
}

impl SnapshotArtifactDescriptor {
    /// Construct an artifact descriptor bound to compile evidence.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identity, malformed evidence, or artifact/evidence mismatch.
    pub fn new(
        operation_id: impl Into<String>,
        artifact: ArtifactRecord,
        compile: CompilePhaseEvidence,
    ) -> RemoteBuildResult<Self> {
        let descriptor = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: operation_id.into(),
            job_id: compile.job_id.clone(),
            artifact,
            compile,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validate exact unsigned-XCArchive artifact and public compile evidence.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, unsafe public text, invalid hashes, oversized
    /// artifacts, or evidence that does not bind the returned file.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_artifact_descriptor")?;
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        validate_artifact_record(&self.artifact)?;
        validate_compile_evidence(&self.compile)?;
        if self.compile.job_id != self.job_id
            || self.compile.sealed_archive.transport.size != self.artifact.size
            || self.compile.sealed_archive.transport.sha256 != self.artifact.sha256
        {
            return Err(invalid(
                "snapshot_artifact_descriptor",
                "artifact record does not match compile evidence",
            ));
        }
        Ok(())
    }
}

/// Client acknowledgement after exact artifact bytes are safely verified.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArtifactReceipt {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Negotiated Ferry Remote Build Protocol version.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Operation identifier from the submitted request.
    pub operation_id: String,
    /// Provider-owned job identifier.
    pub job_id: String,
    /// Exact artifact identifier.
    pub artifact_id: String,
    /// Verified local byte length.
    pub size: u64,
    /// Verified local lowercase SHA-256.
    pub sha256: String,
    /// Absolute create-only client destination containing the verified bytes.
    pub local_path: ProtocolPath,
}

impl SnapshotArtifactReceipt {
    /// Construct a receipt from a validated descriptor and client path.
    ///
    /// # Errors
    ///
    /// Rejects invalid descriptor evidence or a non-client-absolute destination.
    pub fn new(
        descriptor: &SnapshotArtifactDescriptor,
        local_path: ProtocolPath,
    ) -> RemoteBuildResult<Self> {
        descriptor.validate()?;
        let receipt = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            protocol_version: descriptor.protocol_version,
            operation_id: descriptor.operation_id.clone(),
            job_id: descriptor.job_id.clone(),
            artifact_id: descriptor.artifact.artifact_id.clone(),
            size: descriptor.artifact.size,
            sha256: descriptor.artifact.sha256.clone(),
            local_path,
        };
        receipt.validate_for(descriptor)?;
        Ok(receipt)
    }

    /// Validate the receipt against the exact offered artifact.
    ///
    /// # Errors
    ///
    /// Rejects identity, size, digest, or path mismatches.
    pub fn validate_for(&self, descriptor: &SnapshotArtifactDescriptor) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_artifact_receipt")?;
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        validate_identifier("artifact_id", &self.artifact_id)?;
        validate_sha256(&self.sha256, "snapshot_artifact_receipt")?;
        self.local_path.validate()?;
        if self.local_path.semantics != ProtocolPathSemantics::ClientAbsolute {
            return Err(invalid(
                "snapshot_artifact_receipt",
                "receipt path must be client_absolute",
            ));
        }
        descriptor.validate()?;
        if self.protocol_version != descriptor.protocol_version
            || self.operation_id != descriptor.operation_id
            || self.job_id != descriptor.job_id
            || self.artifact_id != descriptor.artifact.artifact_id
            || self.size != descriptor.artifact.size
            || self.sha256 != descriptor.artifact.sha256
        {
            return Err(invalid(
                "snapshot_artifact_receipt",
                "receipt does not match the offered artifact",
            ));
        }
        Ok(())
    }
}

/// Successful terminal message emitted only after verified client receipt and cleanup.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBuildComplete {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Negotiated Ferry Remote Build Protocol version.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Operation identifier from the submitted request.
    pub operation_id: String,
    /// Provider-owned job identifier.
    pub job_id: String,
    /// Exact remote cleanup proof.
    #[serde(deserialize_with = "deserialize_cleanup_confirmation")]
    pub cleanup: CleanupConfirmation,
}

impl SnapshotBuildComplete {
    /// Construct one successful terminal message.
    ///
    /// # Errors
    ///
    /// Rejects incomplete cleanup or unsafe identifiers.
    pub fn new(
        operation_id: impl Into<String>,
        cleanup: CleanupConfirmation,
    ) -> RemoteBuildResult<Self> {
        let complete = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: operation_id.into(),
            job_id: cleanup.job_id.clone(),
            cleanup,
        };
        complete.validate()?;
        Ok(complete)
    }

    /// Validate that terminal success includes complete non-retaining cleanup.
    ///
    /// # Errors
    ///
    /// Rejects mismatched identity or incomplete cleanup evidence.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_build_complete")?;
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("job_id", &self.job_id)?;
        if self.cleanup.job_id != self.job_id
            || !self.cleanup.workspace_removed
            || !self.cleanup.signing_material_removed
            || self.cleanup.artifacts_retained
        {
            return Err(invalid(
                "snapshot_build_complete",
                "successful completion requires non-retaining cleanup proof",
            ));
        }
        Ok(())
    }
}

/// Stable, secret-free terminal or pre-job session failure.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSessionError {
    /// Snapshot-session message schema.
    pub schema_version: u32,
    /// Ferry Remote Build Protocol version understood by the sender.
    #[serde(deserialize_with = "deserialize_protocol_version")]
    pub protocol_version: ProtocolVersion,
    /// Operation identifier when a build start was decoded.
    pub operation_id: Option<String>,
    /// Provider job identifier when one was allocated.
    pub job_id: Option<String>,
    /// Stable namespaced error code.
    pub code: String,
    /// Bounded public summary, never raw subprocess or parser text.
    pub message: String,
    /// Whether retrying unchanged inputs may succeed.
    pub retryable: bool,
    /// Cleanup proof when cleanup completed after the failure.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_cleanup_confirmation"
    )]
    pub cleanup: Option<CleanupConfirmation>,
}

impl SnapshotSessionError {
    /// Construct one bounded, public session failure.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identifiers, control text, oversized text, or mismatched cleanup proof.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: Option<String>,
        job_id: Option<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        cleanup: Option<CleanupConfirmation>,
    ) -> RemoteBuildResult<Self> {
        let error = Self {
            schema_version: SNAPSHOT_SESSION_SCHEMA_VERSION,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id,
            job_id,
            code: code.into(),
            message: message.into(),
            retryable,
            cleanup,
        };
        error.validate()?;
        Ok(error)
    }

    /// Validate bounded public failure fields and optional cleanup identity.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, unsafe identifiers/text, or mismatched cleanup proof.
    pub fn validate(&self) -> RemoteBuildResult<()> {
        require_schema(self.schema_version, "snapshot_session_error")?;
        CURRENT_PROTOCOL_VERSION.negotiate(self.protocol_version)?;
        if let Some(operation_id) = &self.operation_id {
            validate_identifier("operation_id", operation_id)?;
        }
        if let Some(job_id) = &self.job_id {
            validate_identifier("job_id", job_id)?;
        }
        validate_public_identifier(
            &self.code,
            MAX_PUBLIC_ERROR_CODE_BYTES,
            "snapshot_session_error",
        )?;
        validate_public_text(
            &self.message,
            MAX_PUBLIC_ERROR_MESSAGE_BYTES,
            "snapshot_session_error",
        )?;
        if let Some(cleanup) = &self.cleanup
            && self.job_id.as_deref() != Some(cleanup.job_id.as_str())
        {
            return Err(invalid(
                "snapshot_session_error",
                "cleanup proof does not match the failed job",
            ));
        }
        Ok(())
    }
}

fn require_unsigned_xcarchive(
    signing: &SigningPlan,
    requested_artifacts: &BTreeSet<IosArtifactType>,
) -> RemoteBuildResult<()> {
    if signing.mode != SigningMode::UnsignedCompileOnly {
        return Err(invalid(
            "snapshot_build_parameters",
            "snapshot session v1 supports unsigned compile-only builds",
        ));
    }
    if requested_artifacts != &BTreeSet::from([IosArtifactType::Xcarchive]) {
        return Err(invalid(
            "snapshot_build_parameters",
            "snapshot session v1 returns exactly one Xcode archive",
        ));
    }
    Ok(())
}

fn validate_artifact_record(record: &ArtifactRecord) -> RemoteBuildResult<()> {
    validate_identifier("artifact_id", &record.artifact_id)?;
    if record.kind != ArtifactKind::Xcarchive {
        return Err(invalid(
            "snapshot_artifact_descriptor",
            "artifact kind must be xcarchive",
        ));
    }
    validate_portable_component_with_limit(&record.file_name, MAX_ARTIFACT_FILE_NAME_BYTES)?;
    if !record.file_name.to_ascii_lowercase().ends_with(".zip") {
        return Err(invalid(
            "snapshot_artifact_descriptor",
            "xcarchive transport filename must end with .zip",
        ));
    }
    if record.size == 0 || record.size > MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES {
        return Err(invalid(
            "snapshot_artifact_descriptor",
            "artifact size is outside the fixed limit",
        ));
    }
    validate_sha256(&record.sha256, "snapshot_artifact_descriptor")?;
    if let Some(media_type) = &record.media_type {
        validate_public_text(
            media_type,
            MAX_MEDIA_TYPE_BYTES,
            "snapshot_artifact_descriptor",
        )?;
    }
    Ok(())
}

fn validate_compile_evidence(compile: &CompilePhaseEvidence) -> RemoteBuildResult<()> {
    if compile.schema_version != COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION
        || compile.sealed_archive.schema_version != SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION
    {
        return Err(invalid(
            "snapshot_artifact_descriptor",
            "compile evidence schema is unsupported",
        ));
    }
    validate_identifier("job_id", &compile.job_id)?;
    validate_identifier("provider", &compile.provider)?;
    for digest in [
        &compile.request_sha256,
        &compile.source_sha256,
        &compile.cargo_lock_sha256,
        &compile.config_sha256,
        &compile.toolchain.developer_directory_sha256,
        &compile.sealed_archive.transport.sha256,
    ] {
        validate_sha256(digest, "snapshot_artifact_descriptor")?;
    }
    for version in [&compile.rustferry_version, &compile.worker_version] {
        validate_public_text(
            version,
            MAX_PUBLIC_VERSION_BYTES,
            "snapshot_artifact_descriptor",
        )?;
    }
    for text in [
        &compile.toolchain.worker_os,
        &compile.toolchain.worker_architecture,
        &compile.toolchain.xcode_version,
        &compile.toolchain.iphoneos_sdk_version,
        &compile.toolchain.iphoneos_sdk_build_version,
        &compile.toolchain.rust_version,
    ] {
        validate_public_text(
            text,
            MAX_PUBLIC_TOOLCHAIN_TEXT_BYTES,
            "snapshot_artifact_descriptor",
        )?;
    }
    if compile.toolchain.rust_target != IOS_DEVICE_RUST_TARGET
        || compile.started_at_unix_seconds > compile.finished_at_unix_seconds
        || compile.sealed_archive.contents.project_path != "."
    {
        return Err(invalid(
            "snapshot_artifact_descriptor",
            "compile evidence does not prove a bounded physical-iPhone archive",
        ));
    }
    validate_transfer_archive(
        &compile.sealed_archive.transport,
        MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES,
        "snapshot_artifact_descriptor",
    )?;
    validate_source_manifest(
        &compile.sealed_archive.contents,
        sealed_archive_source_limits(),
    )
    .map_err(|_| {
        invalid(
            "snapshot_artifact_descriptor",
            "sealed archive content manifest is invalid",
        )
    })
}

const fn sealed_archive_source_limits() -> SourceLimits {
    SourceLimits {
        max_file_count: 50_000,
        max_file_size: 512 * 1024 * 1024,
        max_total_size: MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES,
        max_depth: 128,
        max_ignore_file_size: 64 * 1024,
        max_ignore_rules: 1,
    }
}

fn validate_transfer_archive(
    archive: &SourceArchive,
    maximum: u64,
    event: &'static str,
) -> RemoteBuildResult<()> {
    if archive.size == 0 || archive.size > maximum {
        return Err(invalid(event, "transfer size is outside the fixed limit"));
    }
    validate_sha256(&archive.sha256, event)
}

fn require_schema(version: u32, event: &'static str) -> RemoteBuildResult<()> {
    if version == SNAPSHOT_SESSION_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(invalid(event, "snapshot session schema is unsupported"))
    }
}

fn validate_sha256(value: &str, event: &'static str) -> RemoteBuildResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(event, "SHA-256 must be lowercase hexadecimal"))
    }
}

fn validate_public_identifier(
    value: &str,
    maximum: usize,
    event: &'static str,
) -> RemoteBuildResult<()> {
    if !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Ok(())
    } else {
        Err(invalid(event, "public identifier is invalid"))
    }
}

fn validate_public_text(value: &str, maximum: usize, event: &'static str) -> RemoteBuildResult<()> {
    if !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(invalid(
            event,
            "public text is empty, oversized, or contains controls",
        ))
    }
}

fn validate_bundle_identifier(value: &str) -> RemoteBuildResult<()> {
    if value.len() > 255
        || value.split('.').count() < 2
        || value.split('.').any(|segment| {
            segment.is_empty()
                || segment.starts_with('-')
                || segment.ends_with('-')
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        Err(invalid(
            "snapshot_build_parameters",
            "bundle identifier is invalid",
        ))
    } else {
        Ok(())
    }
}

fn validate_ios_version(value: &str) -> RemoteBuildResult<()> {
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
        Err(invalid(
            "snapshot_build_parameters",
            "minimum iOS version is invalid",
        ))
    } else {
        Ok(())
    }
}

fn validate_portable_component(value: &str) -> RemoteBuildResult<()> {
    validate_portable_component_with_limit(value, 255)
}

fn validate_portable_component_with_limit(value: &str, maximum: usize) -> RemoteBuildResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || value == "."
        || value == ".."
        || value.contains(['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'])
        || value.ends_with(['.', ' '])
        || value.chars().any(char::is_control)
    {
        Err(invalid(
            "snapshot_artifact_descriptor",
            "filename component is not portable",
        ))
    } else {
        Ok(())
    }
}

const fn invalid(event: &'static str, reason: &'static str) -> RemoteBuildError {
    RemoteBuildError::InvalidEventPayload { event, reason }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProtocolVersion {
    major: u16,
    minor: u16,
}

fn deserialize_protocol_version<'de, D>(deserializer: D) -> Result<ProtocolVersion, D::Error>
where
    D: Deserializer<'de>,
{
    let version = StrictProtocolVersion::deserialize(deserializer)?;
    Ok(ProtocolVersion::new(version.major, version.minor))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictCleanupConfirmation {
    job_id: String,
    completed_at_ms: u64,
    workspace_removed: bool,
    signing_material_removed: bool,
    artifacts_retained: bool,
}

impl From<StrictCleanupConfirmation> for CleanupConfirmation {
    fn from(cleanup: StrictCleanupConfirmation) -> Self {
        Self {
            job_id: cleanup.job_id,
            completed_at_ms: cleanup.completed_at_ms,
            workspace_removed: cleanup.workspace_removed,
            signing_material_removed: cleanup.signing_material_removed,
            artifacts_retained: cleanup.artifacts_retained,
        }
    }
}

fn deserialize_cleanup_confirmation<'de, D>(
    deserializer: D,
) -> Result<CleanupConfirmation, D::Error>
where
    D: Deserializer<'de>,
{
    StrictCleanupConfirmation::deserialize(deserializer).map(Into::into)
}

fn deserialize_optional_cleanup_confirmation<'de, D>(
    deserializer: D,
) -> Result<Option<CleanupConfirmation>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StrictCleanupConfirmation>::deserialize(deserializer)
        .map(|cleanup| cleanup.map(Into::into))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use camino::Utf8PathBuf;

    use crate::{
        ApplePlatform, BundleIdentifier, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
        CompileToolchainEvidence, IosDeviceProductExpectation, MachOSliceEvidence,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningTarget,
        SigningTargetKind, SourceBundleRequest, UnsignedAppInspection,
        UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection, plan_source_bundle,
    };

    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        descriptor: SourceBundleDescriptor,
        request: IosDeviceBuildRequest,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = Utf8PathBuf::from_path_buf(directory.path().to_path_buf()).expect("UTF-8 path");
        fs::create_dir(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n",
        )
        .expect("Cargo.toml");
        fs::write(root.join("Cargo.lock"), "# fixture\n").expect("Cargo.lock");
        fs::write(root.join("ferry.toml"), "[app]\nname='App'\n").expect("ferry.toml");
        fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
        let plan =
            plan_source_bundle(&SourceBundleRequest::new(&root, &root)).expect("source plan");
        let archive = SourceArchive {
            size: 123,
            sha256: "a".repeat(64),
        };
        let descriptor = SourceBundleDescriptor::new(archive, plan.manifest().clone());
        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app")
                    .expect("bundle identifier"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
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
            profile: BuildProfile::Debug,
            source_mode: SourceMode::Snapshot,
            source_repository: None,
            source_revision: None,
            source: descriptor.manifest.clone(),
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        request.validate().expect("request");
        Fixture {
            _directory: directory,
            descriptor,
            request,
        }
    }

    fn artifact_descriptor(fixture: &Fixture) -> SnapshotArtifactDescriptor {
        let expectation = UnsignedXcarchiveExpectation {
            app_directory_name: "App.app".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            executable: "App".to_owned(),
            app_version: "1.0.0".to_owned(),
            build_number: "1".to_owned(),
            minimum_os: "16.0".to_owned(),
            sdk_version: "18.5".to_owned(),
            sdk_build_version: "22F76".to_owned(),
            nested_bundles: Vec::new(),
            required_resources: BTreeMap::new(),
        };
        let slice = MachOSliceEvidence {
            architecture: "arm64".to_owned(),
            platform: ApplePlatform::Ios,
            minimum_os: Some("16.0.0".to_owned()),
            sdk: Some("18.5.0".to_owned()),
        };
        let inspection = UnsignedXcarchiveInspection {
            application_path: "Applications/App.app".to_owned(),
            architectures: vec!["arm64".to_owned()],
            app: UnsignedAppInspection {
                app_directory_name: "App.app".to_owned(),
                bundle_identifier: "com.example.app".to_owned(),
                executable: "App".to_owned(),
                main_executable: vec![slice],
                nested_executables: BTreeMap::new(),
                extensions: Vec::new(),
                resources: BTreeMap::new(),
                entries: vec!["App".to_owned()],
            },
            entries: vec!["Products/Applications/App.app/App".to_owned()],
        };
        let transport = SourceArchive {
            size: 456,
            sha256: "b".repeat(64),
        };
        let compile = CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: "job-1".to_owned(),
            provider: "ssh-macos".to_owned(),
            request_sha256: "c".repeat(64),
            source_sha256: fixture.request.source.sha256.clone(),
            cargo_lock_sha256: "d".repeat(64),
            config_sha256: "e".repeat(64),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 15.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "16.4".to_owned(),
                iphoneos_sdk_version: "18.5".to_owned(),
                iphoneos_sdk_build_version: "22F76".to_owned(),
                developer_directory_sha256: "f".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: transport.clone(),
                contents: fixture.descriptor.manifest.clone(),
                expectation,
            },
            archive_inspection: inspection,
            started_at_unix_seconds: 100,
            finished_at_unix_seconds: 200,
        };
        SnapshotArtifactDescriptor::new(
            "operation-1",
            ArtifactRecord {
                artifact_id: "archive-1".to_owned(),
                kind: ArtifactKind::Xcarchive,
                file_name: "App-unsigned.xcarchive.zip".to_owned(),
                size: transport.size,
                sha256: transport.sha256,
                media_type: Some("application/zip".to_owned()),
            },
            compile,
        )
        .expect("artifact descriptor")
    }

    #[test]
    fn parameters_roundtrip_only_snapshot_unsigned_xcarchive() {
        let fixture = fixture();
        let parameters =
            SnapshotBuildParameters::from_request(&fixture.request).expect("snapshot parameters");
        let reconstructed = parameters
            .reconstruct_request(&fixture.descriptor, SourceArchiveLimits::default())
            .expect("reconstructed request");
        assert_eq!(reconstructed, fixture.request);

        let mut wrong_mode = fixture.request.clone();
        wrong_mode.source_mode = SourceMode::Git;
        wrong_mode.source_repository = Some("https://github.com/example/app".to_owned());
        wrong_mode.source_revision = Some("a".repeat(40));
        assert!(SnapshotBuildParameters::from_request(&wrong_mode).is_err());

        let mut wrong_artifacts = fixture.request.clone();
        wrong_artifacts.requested_artifacts = BTreeSet::from([IosArtifactType::AppBundle]);
        assert!(SnapshotBuildParameters::from_request(&wrong_artifacts).is_err());
    }

    #[test]
    fn build_start_binds_archive_to_separate_descriptor() {
        let fixture = fixture();
        let parameters =
            SnapshotBuildParameters::from_request(&fixture.request).expect("snapshot parameters");
        let start = SnapshotBuildStart::new(
            parameters,
            100,
            "9".repeat(64),
            fixture.descriptor.archive.clone(),
        )
        .expect("build start");
        assert_eq!(
            start
                .reconstruct_request(&fixture.descriptor, SourceArchiveLimits::default())
                .expect("bound request"),
            fixture.request
        );

        let mut substituted = fixture.descriptor.clone();
        substituted.archive.sha256 = "8".repeat(64);
        assert!(
            start
                .reconstruct_request(&substituted, SourceArchiveLimits::default())
                .is_err()
        );
    }

    #[test]
    fn build_start_enforces_the_interactive_descriptor_limit_boundary() {
        let fixture = fixture();
        let parameters =
            SnapshotBuildParameters::from_request(&fixture.request).expect("snapshot parameters");
        assert!(
            SnapshotBuildStart::new(
                parameters.clone(),
                MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES,
                "9".repeat(64),
                fixture.descriptor.archive.clone(),
            )
            .is_ok()
        );
        assert!(
            SnapshotBuildStart::new(
                parameters,
                MAX_SNAPSHOT_SESSION_DESCRIPTOR_BYTES + 1,
                "9".repeat(64),
                fixture.descriptor.archive.clone(),
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_receipt_and_completion_require_exact_proof() {
        let fixture = fixture();
        let descriptor = artifact_descriptor(&fixture);
        let receipt = SnapshotArtifactReceipt::new(
            &descriptor,
            ProtocolPath::new(
                ProtocolPathSemantics::ClientAbsolute,
                "/tmp/App-unsigned.xcarchive.zip",
            )
            .expect("client path"),
        )
        .expect("receipt");
        receipt.validate_for(&descriptor).expect("exact receipt");
        let mut changed = receipt.clone();
        changed.sha256 = "0".repeat(64);
        assert!(changed.validate_for(&descriptor).is_err());

        let cleanup = CleanupConfirmation {
            job_id: descriptor.job_id.clone(),
            completed_at_ms: 300,
            workspace_removed: true,
            signing_material_removed: true,
            artifacts_retained: false,
        };
        SnapshotBuildComplete::new(descriptor.operation_id.clone(), cleanup.clone())
            .expect("complete cleanup");
        let mut retained = cleanup;
        retained.artifacts_retained = true;
        assert!(SnapshotBuildComplete::new("operation-1", retained).is_err());
    }

    #[test]
    fn strict_json_rejects_unknown_outer_nested_version_and_cleanup_fields() {
        let accepted = SnapshotJobAccepted::new("operation-1", "job-1", 10).expect("job accepted");
        let mut accepted_json = serde_json::to_value(accepted).expect("accepted JSON");
        accepted_json
            .as_object_mut()
            .expect("accepted object")
            .insert("future".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SnapshotJobAccepted>(accepted_json).is_err());

        let version_json = serde_json::json!({
            "schema_version": 1,
            "protocol_version": {"major": 1, "minor": 0, "future": true},
            "operation_id": "operation-1",
            "job_id": "job-1",
            "state": "created",
            "created_at_ms": 10
        });
        assert!(serde_json::from_value::<SnapshotJobAccepted>(version_json).is_err());

        let complete_json = serde_json::json!({
            "schema_version": 1,
            "protocol_version": {"major": 1, "minor": 0},
            "operation_id": "operation-1",
            "job_id": "job-1",
            "cleanup": {
                "job_id": "job-1",
                "completed_at_ms": 10,
                "workspace_removed": true,
                "signing_material_removed": true,
                "artifacts_retained": false,
                "future": true
            }
        });
        assert!(serde_json::from_value::<SnapshotBuildComplete>(complete_json).is_err());
    }

    #[test]
    fn public_session_errors_are_bounded_and_cleanup_bound() {
        let cleanup = CleanupConfirmation {
            job_id: "job-1".to_owned(),
            completed_at_ms: 20,
            workspace_removed: true,
            signing_material_removed: true,
            artifacts_retained: false,
        };
        SnapshotSessionError::new(
            Some("operation-1".to_owned()),
            Some("job-1".to_owned()),
            "worker.build_failed",
            "Unsigned build failed",
            false,
            Some(cleanup.clone()),
        )
        .expect("safe error");
        assert!(
            SnapshotSessionError::new(
                Some("operation-1".to_owned()),
                Some("job-2".to_owned()),
                "worker.build_failed",
                "Unsigned build failed",
                false,
                Some(cleanup),
            )
            .is_err()
        );
        assert!(
            SnapshotSessionError::new(None, None, "worker.failed", "unsafe\u{1b}[2J", false, None,)
                .is_err()
        );
    }
}
