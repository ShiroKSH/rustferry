//! Production two-phase physical-iPhone compile and protected-signing pipeline.
//!
//! Compilation and signing are deliberately separate entry points. The compile
//! phase has no secret resolver. The signing phase consumes only the sealed
//! unsigned archive and the opaque references already present in the validated
//! request, and never invokes Cargo or project-controlled build scripts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{Read as _, Write as _},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_apple::{
    AppleBuildProfile, AppleDiscoveryOptions, CommandSpec, IosDeviceArchivePlan,
    IosDeviceArchiveRequest, IosDeviceArtifactDisposition, IosDeviceToolchain,
    build_ios_device_unsigned, discover_apple, plan_ios_device_unsigned, run_command,
};
use rustferry_remote::{
    AppleToolchainEvidence, ArtifactKind, ArtifactManifest, ArtifactRecord,
    ArtifactSigningEvidence, BuildProfile, CleanupStatus, IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK,
    IosArtifactType, IosDeviceBuildRequest, Secret, SecretBytes, SigningMode, SigningStatus,
    SigningTargetKind, SourceBundleRequest, UnsignedNestedBundleKind, UnsignedXcarchiveInspection,
    ValidationLevel, canonical_request_sha256 as remote_canonical_request_sha256,
    verify_materialized_bundle, verify_source_manifest,
};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::{
    export::{DevelopmentExportRequest, export_development_ipa},
    job::WorkerSecretResolver,
    keychain::{
        EphemeralSigningKeychain, KeychainCleanupConfirmation, KeychainOptions,
        SigningKeychainInput,
    },
    provisioning::{
        ProfileSecretInput, ProvisioningMaterialRequest, prepare_provisioning_materials,
    },
    sealed::{
        seal_unsigned_xcarchive, unseal_unsigned_xcarchive, validate_sealed_unsigned_archive,
    },
    signed_ipa::{
        SignedIpaValidationEvidence, SignedIpaValidationOptions, SignedIpaValidationRequest,
        validate_signed_development_ipa,
    },
};

pub use rustferry_remote::{CompilePhaseEvidence, CompileToolchainEvidence};

/// Version of the compile/sign handoff and public report schemas.
pub const PIPELINE_SCHEMA_VERSION: u32 = 1;

const MAX_PUBLIC_TEXT_BYTES: usize = 160;
const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
const FIXED_IPA_NAME: &str = "application-development.ipa";
const SIGNING_REPORT_NAME: &str = "signing-report.json";
const PROVISIONING_REPORT_NAME: &str = "provisioning-report.json";

/// Explicit executable locations used for fresh Apple toolchain discovery.
///
/// The pipeline never enumerates the process environment. Callers may supply
/// only search directories and an optional preferred Xcode developer directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineToolchainSelection {
    /// Preferred full-Xcode `Contents/Developer` directory.
    pub developer_directory: Option<Utf8PathBuf>,
    /// Explicit executable search directories. Conventional system directories
    /// are appended by `rustferry-apple`.
    pub executable_search_paths: Vec<Utf8PathBuf>,
}

impl PipelineToolchainSelection {
    /// Validate an explicit discovery selection.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, duplicate search paths, and unsafe Xcode paths.
    pub fn new(
        developer_directory: Option<Utf8PathBuf>,
        executable_search_paths: Vec<Utf8PathBuf>,
    ) -> Result<Self, PipelineError> {
        if developer_directory
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
            || executable_search_paths
                .iter()
                .any(|path| !path.is_absolute())
        {
            return Err(PipelineError::InvalidToolchainSelection);
        }
        let distinct = executable_search_paths.iter().collect::<BTreeSet<_>>();
        if distinct.len() != executable_search_paths.len() {
            return Err(PipelineError::InvalidToolchainSelection);
        }
        Ok(Self {
            developer_directory,
            executable_search_paths,
        })
    }
}

/// Public metadata supplied by the provider rather than project code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelinePublicMetadata {
    /// Provider-scoped job identifier.
    pub job_id: String,
    /// Provider implementation name.
    pub provider: String,
    /// Client version that submitted the request.
    pub rustferry_version: String,
}

impl PipelinePublicMetadata {
    /// Construct bounded, control-free public metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing values.
    pub fn new(
        job_id: impl Into<String>,
        provider: impl Into<String>,
        rustferry_version: impl Into<String>,
    ) -> Result<Self, PipelineError> {
        let metadata = Self {
            job_id: job_id.into(),
            provider: provider.into(),
            rustferry_version: rustferry_version.into(),
        };
        if !safe_public_identifier(&metadata.job_id)
            || !safe_public_identifier(&metadata.provider)
            || !safe_public_text(&metadata.rustferry_version)
        {
            return Err(PipelineError::InvalidPublicMetadata);
        }
        Ok(metadata)
    }
}

/// Local compile result; only `evidence` crosses the job boundary.
#[derive(Debug)]
pub struct CompilePhaseOutput {
    /// Exact sealed ZIP path for provider upload.
    pub sealed_archive_path: Utf8PathBuf,
    /// Redacted, serializable compile evidence.
    pub evidence: CompilePhaseEvidence,
}

/// Exact phase-A inputs. This type intentionally has no secret resolver or
/// signing-material field.
pub struct CompilePhaseRequest<'a> {
    /// Validated remote request containing references only.
    pub request: &'a IosDeviceBuildRequest,
    /// Exact source-selection request used to create the transported manifest.
    pub source_selection: &'a SourceBundleRequest,
    /// Loaded `ferry.toml` plus fixed Cargo target selection.
    pub apple_request: IosDeviceArchiveRequest,
    /// Fresh Apple discovery selection.
    pub toolchain: &'a PipelineToolchainSelection,
    /// New sealed ZIP destination outside the materialized source tree.
    pub sealed_archive_path: &'a Utf8Path,
    /// Provider-owned public metadata.
    pub metadata: &'a PipelinePublicMetadata,
}

/// Run the secret-free compile phase and seal its unsigned `.xcarchive`.
///
/// The supplied `IosDeviceArchiveRequest` must contain the `FerryConfig` loaded
/// from the verified project's `ferry.toml`. This function independently runs
/// semantic config validation, binds all request-visible config fields, plans
/// the physical-device build, rebuilds the plan, inspects the result, and seals
/// the exact archive. No secret resolver is accepted by this API.
///
/// # Errors
///
/// Returns a fixed, secret-free category for request, source, config, toolchain,
/// build, inspection, or sealing failure.
pub fn compile_unsigned_phase(
    phase: &CompilePhaseRequest<'_>,
) -> Result<CompilePhaseOutput, PipelineError> {
    let started_at_unix_seconds = unix_time_now()?;
    validate_compile_request(phase)?;
    verify_materialized_bundle(
        phase.source_selection.workspace_root(),
        &phase.request.source,
        phase.source_selection.limits(),
    )
    .map_err(|_| PipelineError::SourceVerificationFailed)?;

    let source_root = canonical_real_directory(phase.source_selection.workspace_root())?;
    let source_identity = Handle::from_path(&source_root)
        .map_err(|source| io_error("bind compile source root", source))?;
    let project_root = canonical_real_directory(phase.source_selection.project_root())?;
    let toolchain = discover_device_toolchain(phase.toolchain, &project_root)?;
    let planned = plan_ios_device_unsigned(&phase.apple_request, &toolchain)
        .map_err(|_| PipelineError::BuildPlanRejected)?;
    validate_device_plan(phase, &planned, &toolchain, &project_root)?;
    let rust_version = probe_rust_version(&toolchain, &project_root)?;
    let worker_os = probe_worker_os(&project_root)?;

    let outcome = build_ios_device_unsigned(&phase.apple_request, &toolchain)
        .map_err(|_| PipelineError::UnsignedBuildFailed)?;
    if outcome.plan != planned
        || outcome.archive.is_none()
        || outcome.app.is_none()
        || outcome.macho_validation.is_none()
        || outcome.archive_inspection.is_none()
    {
        return Err(PipelineError::BuildEvidenceMismatch);
    }
    ensure_same_directory(&source_root, &source_identity)?;
    verify_source_manifest(phase.source_selection, &phase.request.source)
        .map_err(|_| PipelineError::SourceChangedDuringBuild)?;

    let archive_path = outcome
        .archive
        .as_deref()
        .ok_or(PipelineError::BuildEvidenceMismatch)?;
    let sealed = seal_unsigned_xcarchive(
        archive_path,
        phase.sealed_archive_path,
        planned.archive_expectation.clone(),
    )
    .map_err(|_| PipelineError::ArchiveSealFailed)?;
    if sealed.inspection
        != outcome
            .archive_inspection
            .ok_or(PipelineError::BuildEvidenceMismatch)?
    {
        return Err(PipelineError::BuildEvidenceMismatch);
    }
    ensure_same_directory(&source_root, &source_identity)?;

    let request_sha256 = remote_canonical_request_sha256(phase.request)
        .map_err(|_| PipelineError::InvalidRequest)?;
    let config_sha256 = manifest_project_file_sha256(&phase.request.source, "ferry.toml")?;
    let cargo_lock_sha256 = manifest_cargo_lock_sha256(&phase.request.source)?;
    let finished_at_unix_seconds = unix_time_now()?;
    if finished_at_unix_seconds < started_at_unix_seconds {
        return Err(PipelineError::ClockInvalid);
    }
    let evidence = CompilePhaseEvidence {
        schema_version: PIPELINE_SCHEMA_VERSION,
        job_id: phase.metadata.job_id.clone(),
        provider: phase.metadata.provider.clone(),
        request_sha256,
        source_sha256: phase.request.source.sha256.clone(),
        cargo_lock_sha256,
        config_sha256,
        rustferry_version: phase.metadata.rustferry_version.clone(),
        worker_version: env!("CARGO_PKG_VERSION").to_owned(),
        toolchain: CompileToolchainEvidence {
            worker_os,
            worker_architecture: toolchain.host_arch.clone(),
            xcode_version: normalize_public_tool_text(&toolchain.xcode_version)?,
            iphoneos_sdk_version: toolchain.device_sdk.version.clone(),
            iphoneos_sdk_build_version: toolchain.device_sdk.build_version.clone(),
            developer_directory_sha256: sha256_bytes(toolchain.developer_dir.as_str().as_bytes()),
            rust_version,
            rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
        },
        sealed_archive: sealed.descriptor,
        archive_inspection: sealed.inspection,
        started_at_unix_seconds,
        finished_at_unix_seconds,
    };
    validate_compile_evidence(&evidence, phase.request)?;
    Ok(CompilePhaseOutput {
        sealed_archive_path: phase.sealed_archive_path.to_owned(),
        evidence,
    })
}

/// Exact phase-B protected-signing inputs.
pub struct ProtectedSignPhaseRequest<'a> {
    /// Same immutable signed request used by the compile job.
    pub request: &'a IosDeviceBuildRequest,
    /// Exact public compile handoff.
    pub compile: &'a CompilePhaseEvidence,
    /// Downloaded sealed ZIP bytes matching `compile.sealed_archive.transport`.
    pub sealed_archive_path: &'a Utf8Path,
    /// Existing isolated protected job root.
    pub job_root: &'a Utf8Path,
    /// Stable trusted root shared by every job running as this worker user.
    pub worker_root: &'a Utf8Path,
    /// Fresh output directory retained after successful cleanup.
    pub artifact_directory: &'a Utf8Path,
    /// Fresh Apple discovery selection for the protected runner.
    pub toolchain: &'a PipelineToolchainSelection,
    /// Deadline for each fixed Apple signing/export/validation command.
    pub command_timeout: Duration,
}

/// Public proof that every secret-bearing or untrusted extracted path was
/// removed before a successful protected phase returned.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProtectedCleanupEvidence {
    /// Original keychain search list restored.
    pub keychain_search_list_restored: bool,
    /// Ephemeral keychain database removed.
    pub keychain_removed: bool,
    /// Temporary identity files removed.
    pub keychain_signing_files_removed: bool,
    /// Keychain job directory removed.
    pub keychain_job_directory_removed: bool,
    /// Isolated provisioning HOME removed by the exporter.
    pub isolated_home_removed: bool,
    /// Export options removed by the exporter.
    pub export_options_removed: bool,
    /// Signed-IPA validation extraction removed.
    pub validation_workspace_removed: bool,
    /// Whole protected private workspace removed and absence observed.
    pub private_workspace_removed: bool,
}

impl ProtectedCleanupEvidence {
    /// Whether every cleanup invariant was independently observed.
    pub fn is_complete(self) -> bool {
        self.keychain_search_list_restored
            && self.keychain_removed
            && self.keychain_signing_files_removed
            && self.keychain_job_directory_removed
            && self.isolated_home_removed
            && self.export_options_removed
            && self.validation_workspace_removed
            && self.private_workspace_removed
    }
}

/// Stable public validation report optionally published as requested artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSigningReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Canonical remote request SHA-256.
    pub request_sha256: String,
    /// Sealed unsigned ZIP SHA-256.
    pub sealed_archive_sha256: String,
    /// Independent signed IPA validation.
    pub signed_ipa: SignedIpaValidationEvidence,
    /// Mandatory cleanup proof.
    pub cleanup: ProtectedCleanupEvidence,
}

/// Serializable public result from the protected signing phase.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSignPhaseEvidence {
    /// Final artifact manifest.
    pub artifact_manifest: ArtifactManifest,
    /// Stable signing/validation report.
    pub report: ProtectedSigningReport,
}

/// Local protected-sign result. Absolute paths are deliberately kept outside
/// the serializable public evidence.
#[derive(Debug)]
pub struct ProtectedSignPhaseOutput {
    /// Validated installable IPA.
    pub ipa_path: Utf8PathBuf,
    /// Requested public report files, sorted by filename.
    pub report_paths: Vec<Utf8PathBuf>,
    /// Redacted public evidence.
    pub evidence: ProtectedSignPhaseEvidence,
}

/// Run the protected signing phase without invoking Cargo or project code.
///
/// Secret resolution is limited to the identity, password, and profile
/// references in the validated signing plan. The sealed archive is verified
/// and re-inspected before the resolver is touched. Cleanup is attempted on all
/// paths after private material exists; cleanup failure takes precedence over
/// operation failure.
///
/// # Errors
///
/// Returns a fixed, secret-free category. No resolver message, command output,
/// filesystem path, profile value, device identifier, or secret is retained.
#[allow(clippy::too_many_lines)]
pub fn sign_protected_phase(
    phase: &ProtectedSignPhaseRequest<'_>,
    secrets: &mut dyn WorkerSecretResolver,
) -> Result<ProtectedSignPhaseOutput, PipelineError> {
    validate_protected_request(phase)?;
    let toolchain = discover_device_toolchain(phase.toolchain, phase.job_root)?;
    validate_rediscovered_toolchain(&toolchain, phase.compile)?;
    if probe_worker_os(phase.job_root)? != phase.compile.toolchain.worker_os
        || probe_rust_version(&toolchain, phase.job_root)? != phase.compile.toolchain.rust_version
    {
        return Err(PipelineError::ToolchainDiscoveryFailed);
    }

    let certificate = expected_certificate(phase.request)?;
    let now_unix_seconds = unix_time_now()?;
    let mut workspace = ProtectedWorkspace::create(phase.job_root)?;
    let setup = (|| {
        let unsealed_archive = workspace.path().join("unsigned.xcarchive");
        let unsealed = unseal_unsigned_xcarchive(
            phase.sealed_archive_path,
            &phase.compile.sealed_archive,
            &unsealed_archive,
        )
        .map_err(|_| PipelineError::ArchiveUnsealFailed)?;
        if unsealed.inspection != phase.compile.archive_inspection
            || unsealed.descriptor != phase.compile.sealed_archive
        {
            return Err(PipelineError::ArchiveHandoffMismatch);
        }
        Ok((
            unsealed_archive,
            workspace.create_child_directory("keychain")?,
            workspace.create_child_directory("profiles")?,
            workspace.create_child_directory("temporary")?,
            workspace.create_child_directory("validation")?,
            workspace.path().join("isolated-home"),
        ))
    })();
    let (
        unsealed_archive,
        keychain_root,
        profile_scratch,
        temporary_directory,
        validation_workspace,
        isolated_home,
    ) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            workspace.cleanup()?;
            return Err(error);
        }
    };

    let mut keychain = None;
    let operation = (|| {
        let signing = phase
            .request
            .signing
            .signing
            .as_ref()
            .ok_or(PipelineError::SigningPlanRejected)?;
        let identity_bytes = secrets
            .resolve(&signing.identity.private_key.reference)
            .map_err(|_| PipelineError::SecretResolutionFailed)?;
        let password_reference = signing
            .password
            .as_ref()
            .ok_or(PipelineError::SigningPlanRejected)?;
        let password_bytes = secrets
            .resolve(password_reference)
            .map_err(|_| PipelineError::SecretResolutionFailed)?;
        let password = secret_bytes_to_utf8(password_bytes)?;
        let input = SigningKeychainInput::new(identity_bytes, password)
            .map_err(|_| PipelineError::SigningIdentityRejected)?;
        let imported = EphemeralSigningKeychain::create(
            phase.worker_root.as_std_path(),
            keychain_root.as_std_path(),
            input,
            KeychainOptions::new(phase.command_timeout, Duration::from_hours(24))
                .map_err(|_| PipelineError::SigningIdentityRejected)?,
        )
        .map_err(|_| PipelineError::SigningIdentityRejected)?;
        if imported.validate_identity(certificate).is_err() {
            imported
                .cleanup()
                .map_err(|_| PipelineError::CleanupIncomplete)?;
            return Err(PipelineError::SigningIdentityRejected);
        }
        keychain = Some(imported);

        let profile_inputs = resolve_profile_inputs(phase.request, secrets)?;
        let prepared = prepare_provisioning_materials(ProvisioningMaterialRequest {
            job_root: workspace.path().as_std_path(),
            scratch_directory: profile_scratch.as_std_path(),
            signing_plan: &phase.request.signing,
            certificate,
            profiles: profile_inputs,
            now_unix_seconds,
            command_timeout: phase.command_timeout,
        })
        .map_err(|_| PipelineError::ProvisioningRejected)?;
        if !prepared.decoded_inputs_removed {
            return Err(PipelineError::CleanupIncomplete);
        }

        let team = phase
            .request
            .signing
            .team
            .as_ref()
            .map(|team| &team.expected)
            .ok_or(PipelineError::SigningPlanRejected)?;
        let expected_profile_uuids = prepared
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.target_name().to_owned(),
                    profile.profile().uuid.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let exported = export_development_ipa(&DevelopmentExportRequest {
            job_root: phase.job_root.as_std_path(),
            archive_path: unsealed_archive.as_std_path(),
            export_directory: phase.artifact_directory.as_std_path(),
            isolated_home: isolated_home.as_std_path(),
            temporary_directory: temporary_directory.as_std_path(),
            developer_directory: toolchain.developer_dir.as_std_path(),
            signing_plan: &phase.request.signing,
            team,
            certificate,
            profiles: &prepared.profiles,
            command_timeout: phase.command_timeout,
        })
        .map_err(|_| PipelineError::DevelopmentExportFailed)?;
        if !exported.cleanup.is_complete() {
            return Err(PipelineError::CleanupIncomplete);
        }
        let ipa_path = normalize_exported_ipa_path(
            phase.artifact_directory,
            Utf8Path::from_path(&exported.ipa_path).ok_or(PipelineError::ArtifactPathRejected)?,
        )?;
        let ipa_expectation = phase
            .request
            .ipa_expectation()
            .map_err(|_| PipelineError::InvalidRequest)?;
        let validation = validate_signed_development_ipa(SignedIpaValidationRequest {
            ipa_path: &ipa_path,
            workspace_root: &validation_workspace,
            ipa_expectation: &ipa_expectation,
            signing_plan: &phase.request.signing,
            certificate,
            expected_profile_uuids: &expected_profile_uuids,
            now_unix_seconds,
            options: SignedIpaValidationOptions::new(phase.command_timeout)
                .map_err(|_| PipelineError::SignedArtifactRejected)?,
        })
        .map_err(|_| PipelineError::SignedArtifactRejected)?;
        if !validation.cleanup_confirmed {
            return Err(PipelineError::CleanupIncomplete);
        }
        Ok(ProtectedOperationOutput {
            ipa_path,
            validation,
            isolated_home_removed: exported.cleanup.isolated_home_removed,
            export_options_removed: exported.cleanup.export_options_removed,
        })
    })();

    let keychain_cleanup = keychain.take().map(|keychain| {
        keychain
            .cleanup()
            .map_err(|_| PipelineError::CleanupIncomplete)
    });
    let private_cleanup = workspace.cleanup();
    let cleanup_failed =
        keychain_cleanup.as_ref().is_some_and(Result::is_err) || private_cleanup.is_err();
    if cleanup_failed {
        cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
        return Err(PipelineError::CleanupIncomplete);
    }
    let operation = match operation {
        Ok(operation) => operation,
        Err(error) => {
            cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
            return Err(error);
        }
    };
    let Some(Ok(keychain_cleanup)) = keychain_cleanup else {
        cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
        return Err(PipelineError::CleanupIncomplete);
    };
    let cleanup = cleanup_evidence(
        keychain_cleanup,
        operation.isolated_home_removed,
        operation.export_options_removed,
        operation.validation.cleanup_confirmed,
        true,
    );
    if !cleanup.is_complete() {
        cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
        return Err(PipelineError::CleanupIncomplete);
    }

    let report = ProtectedSigningReport {
        schema_version: PIPELINE_SCHEMA_VERSION,
        request_sha256: phase.compile.request_sha256.clone(),
        sealed_archive_sha256: phase.compile.sealed_archive.transport.sha256.clone(),
        signed_ipa: operation.validation.clone(),
        cleanup,
    };
    let Ok(report_bytes) = serde_json::to_vec_pretty(&report) else {
        cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
        return Err(PipelineError::ReportEncodingFailed);
    };
    if report_bytes.is_empty() || report_bytes.len() > MAX_REPORT_BYTES {
        cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
        return Err(PipelineError::ReportEncodingFailed);
    }
    let (records, report_paths) = match publish_requested_artifacts(
        phase.request,
        phase.artifact_directory,
        &operation.ipa_path,
        &operation.validation,
        &report_bytes,
    ) {
        Ok(published) => published,
        Err(error) => {
            cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
            return Err(error);
        }
    };
    let manifest = match build_artifact_manifest(phase, &operation.validation, records, cleanup) {
        Ok(manifest) => manifest,
        Err(error) => {
            cleanup_artifact_directory(phase.job_root, phase.artifact_directory)?;
            return Err(error);
        }
    };
    Ok(ProtectedSignPhaseOutput {
        ipa_path: operation.ipa_path,
        report_paths,
        evidence: ProtectedSignPhaseEvidence {
            artifact_manifest: manifest,
            report,
        },
    })
}

struct ProtectedOperationOutput {
    ipa_path: Utf8PathBuf,
    validation: SignedIpaValidationEvidence,
    isolated_home_removed: bool,
    export_options_removed: bool,
}

/// Secret-free pipeline failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineError {
    /// Remote request or its compile/sign mode is unsupported.
    InvalidRequest,
    /// Provider public metadata is malformed.
    InvalidPublicMetadata,
    /// Explicit toolchain-selection paths are malformed.
    InvalidToolchainSelection,
    /// Materialized source root or project binding is unsafe.
    UnsafePath,
    /// Exact source verification failed.
    SourceVerificationFailed,
    /// Project-controlled source changed during compilation.
    SourceChangedDuringBuild,
    /// Loaded `ferry.toml` or its binding to the request failed.
    ConfigRejected,
    /// Apple toolchain discovery or a public version probe failed.
    ToolchainDiscoveryFailed,
    /// Planned build was not the exact physical-device unsigned plan.
    BuildPlanRejected,
    /// Unsigned physical-device compilation failed.
    UnsignedBuildFailed,
    /// Build outputs did not match their precomputed plan.
    BuildEvidenceMismatch,
    /// Unsigned archive sealing failed.
    ArchiveSealFailed,
    /// Compile evidence was malformed or did not bind the request.
    CompileEvidenceRejected,
    /// Sealed archive verification/extraction failed.
    ArchiveUnsealFailed,
    /// Signing-side archive inspection differed from compile evidence.
    ArchiveHandoffMismatch,
    /// Manual-development signing plan was invalid.
    SigningPlanRejected,
    /// An explicit signing-plan secret reference could not be resolved.
    SecretResolutionFailed,
    /// Password bytes were not valid bounded UTF-8.
    SigningPasswordRejected,
    /// Imported identity did not match the signed request.
    SigningIdentityRejected,
    /// One or more profiles did not authorize their exact targets.
    ProvisioningRejected,
    /// Xcode manual-development export failed.
    DevelopmentExportFailed,
    /// Exported artifact path was unsafe or ambiguous.
    ArtifactPathRejected,
    /// Independent signed IPA validation failed.
    SignedArtifactRejected,
    /// A public report could not be encoded.
    ReportEncodingFailed,
    /// A public artifact could not be published or hashed.
    ArtifactPublicationFailed,
    /// Mandatory signing cleanup could not be proven.
    CleanupIncomplete,
    /// Worker wall clock was unavailable or moved backwards.
    ClockInvalid,
    /// Fixed filesystem operation failed.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Portable error category.
        kind: std::io::ErrorKind,
    },
}

impl fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "physical-iPhone pipeline request is invalid",
            Self::InvalidPublicMetadata => "provider public metadata is invalid",
            Self::InvalidToolchainSelection => "Apple toolchain selection is invalid",
            Self::UnsafePath => "pipeline path binding is unsafe",
            Self::SourceVerificationFailed => "materialized source verification failed",
            Self::SourceChangedDuringBuild => "source changed during untrusted compilation",
            Self::ConfigRejected => "ferry configuration is invalid or inconsistent",
            Self::ToolchainDiscoveryFailed => "physical-iPhone toolchain discovery failed",
            Self::BuildPlanRejected => "physical-iPhone build plan is invalid",
            Self::UnsignedBuildFailed => "unsigned physical-iPhone build failed",
            Self::BuildEvidenceMismatch => "unsigned build evidence is inconsistent",
            Self::ArchiveSealFailed => "unsigned archive sealing failed",
            Self::CompileEvidenceRejected => "compile evidence is invalid",
            Self::ArchiveUnsealFailed => "sealed archive verification failed",
            Self::ArchiveHandoffMismatch => "sealed archive handoff evidence differs",
            Self::SigningPlanRejected => "manual-development signing plan is invalid",
            Self::SecretResolutionFailed => "an explicit signing secret could not be resolved",
            Self::SigningPasswordRejected => "signing password bytes are invalid",
            Self::SigningIdentityRejected => "signing identity validation failed",
            Self::ProvisioningRejected => "provisioning profile validation failed",
            Self::DevelopmentExportFailed => "development IPA export failed",
            Self::ArtifactPathRejected => "exported artifact path is invalid",
            Self::SignedArtifactRejected => "signed IPA validation failed",
            Self::ReportEncodingFailed => "public signing report encoding failed",
            Self::ArtifactPublicationFailed => "validated artifact publication failed",
            Self::CleanupIncomplete => "protected signing cleanup is incomplete",
            Self::ClockInvalid => "worker wall clock is invalid",
            Self::Io { .. } => "fixed pipeline filesystem operation failed",
        })
    }
}

impl Error for PipelineError {}

fn validate_compile_request(phase: &CompilePhaseRequest<'_>) -> Result<(), PipelineError> {
    phase
        .request
        .validate()
        .map_err(|_| PipelineError::InvalidRequest)?;
    validate_compile_signing_request(phase.request)?;
    if !safe_public_identifier(&phase.metadata.job_id)
        || !safe_public_identifier(&phase.metadata.provider)
        || !safe_public_text(&phase.metadata.rustferry_version)
    {
        return Err(PipelineError::InvalidPublicMetadata);
    }
    if phase.apple_request.dry_run
        || phase.apple_request.config.validate_or_error().is_err()
        || phase.apple_request.config.app.name != phase.request.product_name
        || phase.apple_request.config.app.identifier != phase.request.bundle_identifier
        || phase.apple_request.config.ios.min_version != phase.request.minimum_ios_version
        || phase.apple_request.profile != expected_apple_profile(phase.request.profile)
    {
        return Err(PipelineError::ConfigRejected);
    }
    let source_root = canonical_real_directory(phase.source_selection.workspace_root())?;
    let project_root = canonical_real_directory(phase.source_selection.project_root())?;
    let configured_project = canonical_real_directory(&phase.apple_request.project_dir)?;
    let expected_project =
        expected_project_directory(&source_root, &phase.request.source.project_path)?;
    if project_root != expected_project || configured_project != expected_project {
        return Err(PipelineError::UnsafePath);
    }
    let output_parent = phase
        .sealed_archive_path
        .parent()
        .ok_or(PipelineError::UnsafePath)?;
    let output_parent = canonical_real_directory(output_parent)?;
    if !phase.sealed_archive_path.is_absolute()
        || !phase
            .sealed_archive_path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
        || phase.sealed_archive_path.exists()
        || output_parent.starts_with(&source_root)
    {
        return Err(PipelineError::UnsafePath);
    }
    manifest_project_file_sha256(&phase.request.source, "Cargo.toml")?;
    manifest_project_file_sha256(&phase.request.source, "ferry.toml")?;
    manifest_cargo_lock_sha256(&phase.request.source)?;
    validate_signing_targets(phase.request, &phase.apple_request)?;
    Ok(())
}

fn validate_compile_signing_request(request: &IosDeviceBuildRequest) -> Result<(), PipelineError> {
    match request.signing.mode {
        SigningMode::UnsignedCompileOnly => {
            if request.signing.signing.is_some()
                || request.signing.team.is_some()
                || request.signing.device.is_some()
                || !request.signing.provisioning.is_empty()
                || !request.signing.entitlements.is_empty()
                || request.signing.allow_provisioning_updates
                || request.requested_artifacts != BTreeSet::from([IosArtifactType::Xcarchive])
            {
                return Err(PipelineError::SigningPlanRejected);
            }
            request
                .signing
                .validate()
                .map_err(|_| PipelineError::SigningPlanRejected)
        }
        SigningMode::ManualDevelopment => validate_manual_development_request(request),
        _ => Err(PipelineError::SigningPlanRejected),
    }
}

fn validate_manual_development_request(
    request: &IosDeviceBuildRequest,
) -> Result<(), PipelineError> {
    if request.signing.mode != SigningMode::ManualDevelopment
        || request.signing.allow_provisioning_updates
        || request.signing.signing.is_none()
        || request.signing.team.is_none()
        || request.signing.device.is_none()
        || !request.requested_artifacts.contains(&IosArtifactType::Ipa)
        || request.requested_artifacts.iter().any(|artifact| {
            matches!(
                artifact,
                IosArtifactType::Xcarchive | IosArtifactType::AppBundle
            )
        })
    {
        return Err(PipelineError::SigningPlanRejected);
    }
    request
        .signing
        .validate()
        .map_err(|_| PipelineError::SigningPlanRejected)?;
    let certificate = expected_certificate(request)?;
    let team = &request
        .signing
        .team
        .as_ref()
        .ok_or(PipelineError::SigningPlanRejected)?
        .expected;
    if certificate.validate().is_err() || certificate.team.id() != team.id() {
        return Err(PipelineError::SigningPlanRejected);
    }
    Ok(())
}

fn expected_certificate(
    request: &IosDeviceBuildRequest,
) -> Result<&rustferry_remote::SigningCertificate, PipelineError> {
    request
        .signing
        .signing
        .as_ref()
        .map(|signing| &signing.identity.certificate)
        .ok_or(PipelineError::SigningPlanRejected)
}

fn validate_signing_targets(
    request: &IosDeviceBuildRequest,
    apple_request: &IosDeviceArchiveRequest,
) -> Result<(), PipelineError> {
    let toolchain_placeholder = request
        .signing
        .targets
        .iter()
        .map(|target| (target.bundle_identifier.as_str().to_owned(), target.kind))
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeSet::from([(
        request.bundle_identifier.clone(),
        SigningTargetKind::Application,
    )]);
    if apple_request.config.extensions.widget.enabled {
        expected.insert((
            format!("{}.widget", request.bundle_identifier),
            SigningTargetKind::Extension,
        ));
    }
    if apple_request.config.extensions.live_activity.enabled {
        expected.insert((
            format!("{}.liveactivity", request.bundle_identifier),
            SigningTargetKind::Extension,
        ));
        expected.insert((
            "org.rustferry.activity-model".to_owned(),
            SigningTargetKind::Framework,
        ));
    }
    expected.insert((
        "org.rustferry.runtime-bridge".to_owned(),
        SigningTargetKind::Framework,
    ));
    if toolchain_placeholder != expected {
        return Err(PipelineError::SigningPlanRejected);
    }
    Ok(())
}

fn validate_device_plan(
    phase: &CompilePhaseRequest<'_>,
    plan: &IosDeviceArchivePlan,
    toolchain: &IosDeviceToolchain,
    project_root: &Utf8Path,
) -> Result<(), PipelineError> {
    let device_root = project_root.join("target/ferry/ios/device");
    if plan.schema_version != 1
        || plan.rust_target != IOS_DEVICE_RUST_TARGET
        || plan.sdk != IOS_DEVICE_SDK
        || plan.destination != "generic/platform=iOS"
        || plan.disposition != IosDeviceArtifactDisposition::UnsignedCompileOnly
        || plan.profile != expected_apple_profile(phase.request.profile)
        || plan.commands.len() != 3
        || !plan.generated_root.starts_with(&device_root)
        || !plan.cargo_target_dir.starts_with(&device_root)
        || !plan.xcode_derived_data.starts_with(&device_root)
        || !plan.archive_path.starts_with(&device_root)
        || !plan.app_path.starts_with(&plan.archive_path)
        || plan.archive_expectation.app_directory_name != phase.request.product.app_directory_name
        || plan.archive_expectation.bundle_identifier != phase.request.bundle_identifier
        || plan.archive_expectation.executable != phase.request.product.executable
        || plan.archive_expectation.app_version != phase.request.product.app_version
        || plan.archive_expectation.build_number != phase.request.product.build_number
        || plan.archive_expectation.minimum_os != phase.request.minimum_ios_version
        || plan.archive_expectation.nested_bundles != phase.request.product.nested_bundles
        || plan.archive_expectation.sdk_version != toolchain.device_sdk.version
        || plan.archive_expectation.sdk_build_version != toolchain.device_sdk.build_version
        || plan
            .commands
            .iter()
            .any(|command| !command.program.is_absolute())
    {
        return Err(PipelineError::BuildPlanRejected);
    }
    validate_plan_bundle_graph(phase.request, plan)
}

fn validate_plan_bundle_graph(
    request: &IosDeviceBuildRequest,
    plan: &IosDeviceArchivePlan,
) -> Result<(), PipelineError> {
    let expected = request
        .signing
        .targets
        .iter()
        .map(|target| (target.bundle_identifier.as_str().to_owned(), target.kind))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::from([(
        plan.archive_expectation.bundle_identifier.clone(),
        SigningTargetKind::Application,
    )]);
    for bundle in &plan.archive_expectation.nested_bundles {
        let kind = match bundle.kind {
            UnsignedNestedBundleKind::AppExtension => SigningTargetKind::Extension,
            UnsignedNestedBundleKind::Framework => SigningTargetKind::Framework,
        };
        actual.insert((bundle.bundle_identifier.clone(), kind));
    }
    if actual == expected {
        Ok(())
    } else {
        Err(PipelineError::BuildPlanRejected)
    }
}

fn validate_compile_evidence(
    evidence: &CompilePhaseEvidence,
    request: &IosDeviceBuildRequest,
) -> Result<(), PipelineError> {
    validate_sealed_unsigned_archive(&evidence.sealed_archive)
        .map_err(|_| PipelineError::CompileEvidenceRejected)?;
    if evidence.schema_version != PIPELINE_SCHEMA_VERSION
        || !safe_public_identifier(&evidence.job_id)
        || !safe_public_identifier(&evidence.provider)
        || !safe_public_text(&evidence.rustferry_version)
        || !safe_public_text(&evidence.worker_version)
        || !is_lower_sha256(&evidence.request_sha256)
        || evidence.request_sha256
            != remote_canonical_request_sha256(request)
                .map_err(|_| PipelineError::InvalidRequest)?
        || evidence.source_sha256 != request.source.sha256
        || !is_lower_sha256(&evidence.cargo_lock_sha256)
        || !is_lower_sha256(&evidence.config_sha256)
        || evidence.finished_at_unix_seconds < evidence.started_at_unix_seconds
        || evidence.toolchain.rust_target != IOS_DEVICE_RUST_TARGET
        || !safe_public_text(&evidence.toolchain.worker_os)
        || !safe_public_text(&evidence.toolchain.worker_architecture)
        || !safe_public_text(&evidence.toolchain.xcode_version)
        || !safe_public_text(&evidence.toolchain.iphoneos_sdk_version)
        || !safe_public_text(&evidence.toolchain.iphoneos_sdk_build_version)
        || !safe_public_text(&evidence.toolchain.rust_version)
        || !is_lower_sha256(&evidence.toolchain.developer_directory_sha256)
        || evidence.sealed_archive.expectation.app_directory_name
            != request.product.app_directory_name
        || evidence.sealed_archive.expectation.bundle_identifier != request.bundle_identifier
        || evidence.sealed_archive.expectation.executable != request.product.executable
        || evidence.sealed_archive.expectation.app_version != request.product.app_version
        || evidence.sealed_archive.expectation.build_number != request.product.build_number
        || evidence.sealed_archive.expectation.minimum_os != request.minimum_ios_version
        || evidence.sealed_archive.expectation.nested_bundles != request.product.nested_bundles
        || !inspection_matches_expectation(
            &evidence.archive_inspection,
            &evidence.sealed_archive.expectation,
        )
    {
        return Err(PipelineError::CompileEvidenceRejected);
    }
    Ok(())
}

fn inspection_matches_expectation(
    inspection: &UnsignedXcarchiveInspection,
    expectation: &rustferry_remote::UnsignedXcarchiveExpectation,
) -> bool {
    let mut expected_extensions = expectation
        .nested_bundles
        .iter()
        .filter(|bundle| bundle.kind == UnsignedNestedBundleKind::AppExtension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    expected_extensions.sort();
    inspection.application_path == format!("Applications/{}", expectation.app_directory_name)
        && inspection.architectures.as_slice() == ["arm64"]
        && inspection.app.app_directory_name == expectation.app_directory_name
        && inspection.app.bundle_identifier == expectation.bundle_identifier
        && inspection.app.executable == expectation.executable
        && inspection.app.extensions == expected_extensions
        && inspection.app.resources == expectation.required_resources
        && !inspection.app.main_executable.is_empty()
}

fn validate_protected_request(phase: &ProtectedSignPhaseRequest<'_>) -> Result<(), PipelineError> {
    phase
        .request
        .validate()
        .map_err(|_| PipelineError::InvalidRequest)?;
    validate_manual_development_request(phase.request)?;
    validate_compile_evidence(phase.compile, phase.request)?;
    if !phase.worker_root.is_absolute()
        || !phase.job_root.is_absolute()
        || !phase.sealed_archive_path.is_absolute()
        || !phase.artifact_directory.is_absolute()
        || !phase
            .sealed_archive_path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
        || phase.artifact_directory.exists()
    {
        return Err(PipelineError::UnsafePath);
    }
    let worker_root = canonical_real_directory(phase.worker_root)?;
    let job_root = canonical_real_directory(phase.job_root)?;
    let artifact_parent = phase
        .artifact_directory
        .parent()
        .ok_or(PipelineError::UnsafePath)?;
    if job_root == worker_root
        || !job_root.starts_with(&worker_root)
        || canonical_real_directory(artifact_parent)? != job_root
        || phase
            .sealed_archive_path
            .starts_with(phase.artifact_directory)
    {
        return Err(PipelineError::UnsafePath);
    }
    let transport = fs::symlink_metadata(phase.sealed_archive_path)
        .map_err(|source| io_error("inspect sealed archive transport", source))?;
    if transport.file_type().is_symlink() || !transport.is_file() {
        return Err(PipelineError::UnsafePath);
    }
    SignedIpaValidationOptions::new(phase.command_timeout)
        .map_err(|_| PipelineError::InvalidRequest)?;
    Ok(())
}

fn discover_device_toolchain(
    selection: &PipelineToolchainSelection,
    current_dir: &Utf8Path,
) -> Result<IosDeviceToolchain, PipelineError> {
    let options = AppleDiscoveryOptions {
        developer_dir: selection.developer_directory.clone(),
        executable_search_paths: selection.executable_search_paths.clone(),
        current_dir: current_dir.to_owned(),
        host_os: std::env::consts::OS.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
    };
    discover_apple(&options)
        .and_then(|discovery| discovery.select_device_toolchain())
        .map_err(|_| PipelineError::ToolchainDiscoveryFailed)
}

fn validate_rediscovered_toolchain(
    toolchain: &IosDeviceToolchain,
    compile: &CompilePhaseEvidence,
) -> Result<(), PipelineError> {
    if normalize_public_tool_text(&toolchain.xcode_version)? != compile.toolchain.xcode_version
        || toolchain.device_sdk.version != compile.toolchain.iphoneos_sdk_version
        || toolchain.device_sdk.build_version != compile.toolchain.iphoneos_sdk_build_version
        || toolchain.host_arch != compile.toolchain.worker_architecture
        || sha256_bytes(toolchain.developer_dir.as_str().as_bytes())
            != compile.toolchain.developer_directory_sha256
    {
        return Err(PipelineError::ToolchainDiscoveryFailed);
    }
    Ok(())
}

fn probe_rust_version(
    toolchain: &IosDeviceToolchain,
    current_dir: &Utf8Path,
) -> Result<String, PipelineError> {
    let mut which = CommandSpec::new("locate selected rustc", &toolchain.rustup, current_dir);
    which.args = vec!["which".to_owned(), "rustc".to_owned()];
    let output = run_command(&which, None).map_err(|_| PipelineError::ToolchainDiscoveryFailed)?;
    let rustc = parse_one_absolute_path(&output.stdout)?;
    let mut version = CommandSpec::new("read selected rustc version", rustc, current_dir);
    version.args = vec!["--version".to_owned()];
    let output =
        run_command(&version, None).map_err(|_| PipelineError::ToolchainDiscoveryFailed)?;
    normalize_public_tool_output(&output.stdout)
}

fn probe_worker_os(current_dir: &Utf8Path) -> Result<String, PipelineError> {
    let program = Utf8Path::new("/usr/bin/sw_vers");
    let mut command = CommandSpec::new("read macOS version", program, current_dir);
    command.args = vec!["-productVersion".to_owned()];
    let output =
        run_command(&command, None).map_err(|_| PipelineError::ToolchainDiscoveryFailed)?;
    let version = normalize_public_tool_output(&output.stdout)?;
    normalize_public_tool_text(&format!("macOS {version}"))
}

fn parse_one_absolute_path(output: &[u8]) -> Result<Utf8PathBuf, PipelineError> {
    let text = std::str::from_utf8(output).map_err(|_| PipelineError::ToolchainDiscoveryFailed)?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let path = lines
        .next()
        .filter(|_| lines.next().is_none())
        .map(str::trim)
        .map(Utf8PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or(PipelineError::ToolchainDiscoveryFailed)?;
    path.canonicalize_utf8()
        .map_err(|_| PipelineError::ToolchainDiscoveryFailed)
}

fn resolve_profile_inputs(
    request: &IosDeviceBuildRequest,
    secrets: &mut dyn WorkerSecretResolver,
) -> Result<Vec<ProfileSecretInput>, PipelineError> {
    let mut inputs = Vec::with_capacity(request.signing.provisioning.len());
    for planned in &request.signing.provisioning {
        let bytes = secrets
            .resolve(&planned.profile)
            .map_err(|_| PipelineError::SecretResolutionFailed)?;
        inputs.push(
            ProfileSecretInput::new(planned.target.clone(), bytes)
                .map_err(|_| PipelineError::ProvisioningRejected)?,
        );
    }
    Ok(inputs)
}

fn secret_bytes_to_utf8(mut bytes: SecretBytes) -> Result<Secret, PipelineError> {
    if bytes.len() > 4 * 1024 {
        return Err(PipelineError::SigningPasswordRejected);
    }
    let value = String::from_utf8(bytes.expose_secret_bytes().to_vec())
        .map_err(|_| PipelineError::SigningPasswordRejected)?;
    bytes.clear();
    Ok(Secret::new(value))
}

fn normalize_exported_ipa_path(
    artifact_directory: &Utf8Path,
    exported: &Utf8Path,
) -> Result<Utf8PathBuf, PipelineError> {
    let directory = canonical_real_directory(artifact_directory)?;
    let exported = exported
        .canonicalize_utf8()
        .map_err(|_| PipelineError::ArtifactPathRejected)?;
    let metadata = fs::symlink_metadata(&exported)
        .map_err(|source| io_error("inspect exported IPA", source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || exported.parent() != Some(directory.as_path())
    {
        return Err(PipelineError::ArtifactPathRejected);
    }
    let destination = directory.join(FIXED_IPA_NAME);
    if exported != destination {
        if destination.exists() {
            return Err(PipelineError::ArtifactPathRejected);
        }
        fs::rename(&exported, &destination)
            .map_err(|source| io_error("normalize exported IPA name", source))?;
    }
    Ok(destination)
}

fn publish_requested_artifacts(
    request: &IosDeviceBuildRequest,
    artifact_directory: &Utf8Path,
    ipa_path: &Utf8Path,
    validation: &SignedIpaValidationEvidence,
    report_bytes: &[u8],
) -> Result<(Vec<ArtifactRecord>, Vec<Utf8PathBuf>), PipelineError> {
    let mut records = vec![ArtifactRecord {
        artifact_id: "iphone-ipa".to_owned(),
        kind: ArtifactKind::Ipa,
        file_name: FIXED_IPA_NAME.to_owned(),
        size: validation.ipa_size,
        sha256: validation.ipa_sha256.clone(),
        media_type: Some("application/octet-stream".to_owned()),
    }];
    verify_record(ipa_path, &records[0])?;
    let mut report_paths = Vec::new();
    for (requested, artifact_id, kind, file_name) in [
        (
            IosArtifactType::ProvisioningReport,
            "provisioning-report",
            ArtifactKind::ValidationReport,
            PROVISIONING_REPORT_NAME,
        ),
        (
            IosArtifactType::SigningReport,
            "signing-report",
            ArtifactKind::SigningReport,
            SIGNING_REPORT_NAME,
        ),
    ] {
        if !request.requested_artifacts.contains(&requested) {
            continue;
        }
        let path = artifact_directory.join(file_name);
        write_new_public_file(&path, report_bytes)?;
        let record = ArtifactRecord {
            artifact_id: artifact_id.to_owned(),
            kind,
            file_name: file_name.to_owned(),
            size: u64::try_from(report_bytes.len())
                .map_err(|_| PipelineError::ArtifactPublicationFailed)?,
            sha256: sha256_bytes(report_bytes),
            media_type: Some("application/json".to_owned()),
        };
        verify_record(&path, &record)?;
        report_paths.push(path);
        records.push(record);
    }
    records.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    report_paths.sort();
    Ok((records, report_paths))
}

#[allow(clippy::too_many_lines)]
fn build_artifact_manifest(
    phase: &ProtectedSignPhaseRequest<'_>,
    validation: &SignedIpaValidationEvidence,
    records: Vec<ArtifactRecord>,
    cleanup: ProtectedCleanupEvidence,
) -> Result<ArtifactManifest, PipelineError> {
    if !cleanup.is_complete() {
        return Err(PipelineError::CleanupIncomplete);
    }
    let main = validation
        .bundles
        .iter()
        .filter(|bundle| bundle.kind == SigningTargetKind::Application)
        .collect::<Vec<_>>();
    if main.len() != 1 {
        return Err(PipelineError::SignedArtifactRejected);
    }
    let main = main[0];
    let profile_uuid = main
        .profile_uuid
        .clone()
        .ok_or(PipelineError::SignedArtifactRejected)?;
    let profile_expiration = main
        .profile_expires_at_unix_seconds
        .map(rfc3339_from_unix)
        .transpose()?
        .ok_or(PipelineError::SignedArtifactRejected)?;
    let entitlements_sha256 = main
        .entitlements_sha256
        .clone()
        .ok_or(PipelineError::SignedArtifactRejected)?;
    let mut extensions = validation
        .bundles
        .iter()
        .filter(|bundle| bundle.kind == SigningTargetKind::Extension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    extensions.sort();
    extensions.dedup();

    let finished_at_unix_seconds = unix_time_now()?;
    if finished_at_unix_seconds < phase.compile.started_at_unix_seconds {
        return Err(PipelineError::ClockInvalid);
    }
    let mut manifest = ArtifactManifest::new(
        phase.request.operation_id.clone(),
        phase.compile.job_id.clone(),
    );
    manifest
        .project_id
        .clone_from(&phase.request.bundle_identifier);
    manifest
        .source_repository
        .clone_from(&phase.request.source_repository);
    manifest
        .source_revision
        .clone_from(&phase.request.source_revision);
    manifest.source_snapshot = phase.request.source_mode == rustferry_remote::SourceMode::Snapshot;
    manifest
        .source_sha256
        .clone_from(&phase.request.source.sha256);
    manifest
        .cargo_lock_sha256
        .clone_from(&phase.compile.cargo_lock_sha256);
    manifest
        .config_sha256
        .clone_from(&phase.compile.config_sha256);
    manifest
        .rustferry_version
        .clone_from(&phase.compile.rustferry_version);
    manifest
        .worker_version
        .clone_from(&phase.compile.worker_version);
    manifest.provider.clone_from(&phase.compile.provider);
    manifest.toolchain = AppleToolchainEvidence {
        worker_os: phase.compile.toolchain.worker_os.clone(),
        worker_architecture: phase.compile.toolchain.worker_architecture.clone(),
        xcode_version: phase.compile.toolchain.xcode_version.clone(),
        iphoneos_sdk_version: phase.compile.toolchain.iphoneos_sdk_version.clone(),
        rust_version: phase.compile.toolchain.rust_version.clone(),
        rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
    };
    manifest.app_name.clone_from(&phase.request.product_name);
    manifest
        .app_version
        .clone_from(&phase.compile.sealed_archive.expectation.app_version);
    manifest
        .build_number
        .clone_from(&phase.compile.sealed_archive.expectation.build_number);
    manifest
        .bundle_identifier
        .clone_from(&phase.request.bundle_identifier);
    build_profile_name(phase.request.profile).clone_into(&mut manifest.build_profile);
    "arm64".clone_into(&mut manifest.architecture);
    manifest.signing = ArtifactSigningEvidence {
        mode: SigningMode::ManualDevelopment,
        status: SigningStatus::ArtifactValidated,
        team_id: Some(validation.team_identifier.clone()),
        certificate_fingerprint: Some(validation.certificate_sha256_fingerprint.clone()),
        profile_uuid: Some(profile_uuid),
        profile_expiration: Some(profile_expiration),
        entitlements_sha256: Some(entitlements_sha256),
    };
    manifest.extensions = extensions;
    manifest.artifacts = records;
    manifest.validation_levels = BTreeSet::from([
        ValidationLevel::SourceValidated,
        ValidationLevel::RemoteBuilderValidated,
        ValidationLevel::DeviceTargetCompiled,
        ValidationLevel::DeviceBinaryBuilt,
        ValidationLevel::AppBundleBuilt,
        ValidationLevel::ArchiveBuilt,
        ValidationLevel::CertificateValidated,
        ValidationLevel::ProvisioningValidated,
        ValidationLevel::NestedCodeSigned,
        ValidationLevel::ApplicationSigned,
        ValidationLevel::IpaExported,
        ValidationLevel::ArtifactValidated,
    ]);
    manifest.started_at = rfc3339_from_unix(phase.compile.started_at_unix_seconds)?;
    manifest.finished_at = rfc3339_from_unix(finished_at_unix_seconds)?;
    manifest.cleanup_status = CleanupStatus::Confirmed;
    Ok(manifest)
}

#[allow(clippy::fn_params_excessive_bools)]
fn cleanup_evidence(
    keychain: KeychainCleanupConfirmation,
    isolated_home_removed: bool,
    export_options_removed: bool,
    validation_workspace_removed: bool,
    private_workspace_removed: bool,
) -> ProtectedCleanupEvidence {
    ProtectedCleanupEvidence {
        keychain_search_list_restored: keychain.search_list_restored,
        keychain_removed: keychain.keychain_removed,
        keychain_signing_files_removed: keychain.signing_files_removed,
        keychain_job_directory_removed: keychain.job_directory_removed,
        isolated_home_removed,
        export_options_removed,
        validation_workspace_removed,
        private_workspace_removed,
    }
}

struct ProtectedWorkspace {
    root: Utf8PathBuf,
    identity: Handle,
    temporary: Option<TempDir>,
}

impl ProtectedWorkspace {
    fn create(job_root: &Utf8Path) -> Result<Self, PipelineError> {
        let root = canonical_real_directory(job_root)?;
        let temporary = tempfile::Builder::new()
            .prefix("rustferry-protected-sign-v1-")
            .tempdir_in(&root)
            .map_err(|source| io_error("create protected signing workspace", source))?;
        let path = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
            .map_err(|_| PipelineError::UnsafePath)?;
        let identity = Handle::from_path(&path)
            .map_err(|source| io_error("bind protected signing workspace", source))?;
        Ok(Self {
            root: path,
            identity,
            temporary: Some(temporary),
        })
    }

    fn path(&self) -> &Utf8Path {
        &self.root
    }

    fn create_child_directory(&self, name: &str) -> Result<Utf8PathBuf, PipelineError> {
        if !safe_path_component(name) {
            return Err(PipelineError::UnsafePath);
        }
        self.verify()?;
        let path = self.root.join(name);
        fs::create_dir(&path)
            .map_err(|source| io_error("create protected workspace directory", source))?;
        self.verify()?;
        canonical_real_directory(&path)
    }

    fn verify(&self) -> Result<(), PipelineError> {
        let metadata = fs::symlink_metadata(&self.root)
            .map_err(|source| io_error("inspect protected signing workspace", source))?;
        let rebound = Handle::from_path(&self.root)
            .map_err(|source| io_error("rebind protected signing workspace", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || rebound != self.identity {
            return Err(PipelineError::UnsafePath);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), PipelineError> {
        self.verify()?;
        let temporary = self
            .temporary
            .take()
            .ok_or(PipelineError::CleanupIncomplete)?;
        temporary
            .close()
            .map_err(|_| PipelineError::CleanupIncomplete)?;
        if self.root.exists() {
            return Err(PipelineError::CleanupIncomplete);
        }
        Ok(())
    }
}

impl Drop for ProtectedWorkspace {
    fn drop(&mut self) {
        if let Some(temporary) = self.temporary.take() {
            let _ = temporary.close();
        }
    }
}

fn cleanup_artifact_directory(
    job_root: &Utf8Path,
    artifact_directory: &Utf8Path,
) -> Result<(), PipelineError> {
    if !artifact_directory.exists() {
        return Ok(());
    }
    let job_root = canonical_real_directory(job_root)?;
    let metadata = fs::symlink_metadata(artifact_directory)
        .map_err(|source| io_error("inspect failed artifact directory", source))?;
    let parent = artifact_directory
        .parent()
        .ok_or(PipelineError::CleanupIncomplete)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || canonical_real_directory(parent)? != job_root
    {
        return Err(PipelineError::CleanupIncomplete);
    }
    fs::remove_dir_all(artifact_directory).map_err(|_| PipelineError::CleanupIncomplete)?;
    if artifact_directory.exists() {
        return Err(PipelineError::CleanupIncomplete);
    }
    Ok(())
}

fn write_new_public_file(path: &Utf8Path, bytes: &[u8]) -> Result<(), PipelineError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o644);
    }
    let mut file = options
        .open(path)
        .map_err(|_| PipelineError::ArtifactPublicationFailed)?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(PipelineError::ArtifactPublicationFailed);
    }
    Ok(())
}

fn verify_record(path: &Utf8Path, record: &ArtifactRecord) -> Result<(), PipelineError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PipelineError::ArtifactPublicationFailed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != record.size
        || sha256_file(path)? != record.sha256
    {
        return Err(PipelineError::ArtifactPublicationFailed);
    }
    Ok(())
}

fn expected_project_directory(
    source_root: &Utf8Path,
    project_path: &str,
) -> Result<Utf8PathBuf, PipelineError> {
    if project_path == "." {
        return Ok(source_root.to_owned());
    }
    canonical_real_directory(&source_root.join(project_path))
}

fn canonical_real_directory(path: &Utf8Path) -> Result<Utf8PathBuf, PipelineError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect pipeline directory", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PipelineError::UnsafePath);
    }
    path.canonicalize_utf8()
        .map_err(|source| io_error("canonicalize pipeline directory", source))
}

fn ensure_same_directory(path: &Utf8Path, expected: &Handle) -> Result<(), PipelineError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect compile source root", source))?;
    let actual =
        Handle::from_path(path).map_err(|source| io_error("rebind compile source root", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || &actual != expected {
        return Err(PipelineError::SourceChangedDuringBuild);
    }
    Ok(())
}

fn manifest_project_file_sha256(
    manifest: &rustferry_remote::SourceManifest,
    file_name: &str,
) -> Result<String, PipelineError> {
    let path = if manifest.project_path == "." {
        file_name.to_owned()
    } else {
        format!("{}/{file_name}", manifest.project_path)
    };
    manifest
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.sha256.clone())
        .ok_or(PipelineError::SourceVerificationFailed)
}

fn manifest_cargo_lock_sha256(
    manifest: &rustferry_remote::SourceManifest,
) -> Result<String, PipelineError> {
    let mut components = if manifest.project_path == "." {
        Vec::new()
    } else {
        manifest.project_path.split('/').collect::<Vec<_>>()
    };
    loop {
        let candidate = if components.is_empty() {
            "Cargo.lock".to_owned()
        } else {
            format!("{}/Cargo.lock", components.join("/"))
        };
        if let Some(entry) = manifest
            .entries
            .iter()
            .find(|entry| entry.path == candidate)
        {
            return Ok(entry.sha256.clone());
        }
        if components.pop().is_none() {
            return Err(PipelineError::SourceVerificationFailed);
        }
    }
}

fn sha256_file(path: &Utf8Path) -> Result<String, PipelineError> {
    let before = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect artifact before hashing", source))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(PipelineError::ArtifactPublicationFailed);
    }
    let mut file =
        fs::File::open(path).map_err(|source| io_error("open artifact for hashing", source))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io_error("read artifact for hashing", source))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect artifact after hashing", source))?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || after.file_type().is_symlink()
        || !after.is_file()
    {
        return Err(PipelineError::ArtifactPublicationFailed);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn normalize_public_tool_output(output: &[u8]) -> Result<String, PipelineError> {
    let text = std::str::from_utf8(output).map_err(|_| PipelineError::ToolchainDiscoveryFailed)?;
    normalize_public_tool_text(text)
}

fn normalize_public_tool_text(value: &str) -> Result<String, PipelineError> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if safe_public_text(&normalized) {
        Ok(normalized)
    } else {
        Err(PipelineError::ToolchainDiscoveryFailed)
    }
}

const fn expected_apple_profile(profile: BuildProfile) -> AppleBuildProfile {
    match profile {
        BuildProfile::Debug => AppleBuildProfile::Debug,
        BuildProfile::Release => AppleBuildProfile::Release,
    }
}

const fn build_profile_name(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Debug => "debug",
        BuildProfile::Release => "release",
    }
}

fn unix_time_now() -> Result<u64, PipelineError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PipelineError::ClockInvalid)
}

fn rfc3339_from_unix(seconds: u64) -> Result<String, PipelineError> {
    let days = i64::try_from(seconds / 86_400).map_err(|_| PipelineError::ClockInvalid)?;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days)?;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> Result<(i64, u64, u64), PipelineError> {
    let days = days_since_epoch
        .checked_add(719_468)
        .ok_or(PipelineError::ClockInvalid)?;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok((
        year,
        u64::try_from(month).map_err(|_| PipelineError::ClockInvalid)?,
        u64::try_from(day).map_err(|_| PipelineError::ClockInvalid)?,
    ))
}

fn safe_public_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PUBLIC_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_public_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PUBLIC_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn safe_path_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(operation: &'static str, source: std::io::Error) -> PipelineError {
    PipelineError::Io {
        operation,
        kind: source.kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rustferry_remote::{
        BundleIdentifier, DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan,
        EntitlementSet, ProvisioningPlan, ProvisioningProfileType, SecretReference,
        SecretReferenceKind, SigningCertificate, SigningIdentity, SigningPlan,
        SigningPrivateKeyReference, SigningReference, SigningTarget,
    };

    use super::*;

    #[test]
    fn unix_time_format_is_utc_rfc3339() {
        assert_eq!(rfc3339_from_unix(0).expect("epoch"), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_from_unix(951_782_400).expect("leap day"),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(
            rfc3339_from_unix(1_700_000_000).expect("known timestamp"),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn cargo_lock_lookup_prefers_nearest_project_ancestor() {
        let manifest = rustferry_remote::SourceManifest {
            schema_version: 1,
            project_path: "apps/phone".to_owned(),
            entries: vec![
                source_entry("Cargo.lock", 'a'),
                source_entry("apps/Cargo.lock", 'b'),
                source_entry("apps/phone/Cargo.toml", 'c'),
                source_entry("apps/phone/ferry.toml", 'd'),
            ],
            total_size: 4,
            sha256: "e".repeat(64),
        };
        assert_eq!(
            manifest_cargo_lock_sha256(&manifest).expect("lock"),
            "b".repeat(64)
        );
        assert_eq!(
            manifest_project_file_sha256(&manifest, "ferry.toml").expect("config"),
            "d".repeat(64)
        );
    }

    #[test]
    fn resolver_is_called_only_for_explicit_plan_references() {
        let request = manual_request();
        let mut resolver = RecordingResolver::default();
        let profiles = resolve_profile_inputs(&request, &mut resolver).expect("profiles");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].target_name(), "App");
        assert_eq!(resolver.references, vec!["PROFILE"]);
    }

    #[test]
    fn request_hash_is_deterministic_and_secret_free() {
        let request = manual_request();
        let first = remote_canonical_request_sha256(&request).expect("hash");
        let second = remote_canonical_request_sha256(&request).expect("hash");
        assert_eq!(first, second);
        assert!(is_lower_sha256(&first));
        let json = serde_json::to_string(&request).expect("request JSON");
        assert!(!json.contains("profile-secret-bytes"));
        assert!(!json.contains("private-key-bytes"));
    }

    #[test]
    fn unsigned_compile_request_forbids_every_signing_input() {
        let mut request = manual_request();
        request.signing.mode = SigningMode::UnsignedCompileOnly;
        request.signing.signing = None;
        request.signing.team = None;
        request.signing.device = None;
        request.signing.provisioning.clear();
        request.signing.entitlements.clear();
        request.requested_artifacts = BTreeSet::from([IosArtifactType::Xcarchive]);

        assert_eq!(validate_compile_signing_request(&request), Ok(()));
        request.signing.team = Some(DevelopmentTeamPlan {
            expected: DevelopmentTeam::new("ABCDE12345", None).expect("team"),
        });
        assert_eq!(
            validate_compile_signing_request(&request),
            Err(PipelineError::SigningPlanRejected)
        );
    }

    fn source_entry(path: &str, digest: char) -> rustferry_remote::SourceManifestEntry {
        rustferry_remote::SourceManifestEntry {
            path: path.to_owned(),
            size: 1,
            sha256: digest.to_string().repeat(64),
            executable: false,
        }
    }

    fn manual_request() -> IosDeviceBuildRequest {
        let mut source_digest = Sha256::new();
        source_digest.update(b"rustferry-source-manifest-v1\0");
        source_digest.update(1_u64.to_be_bytes());
        source_digest.update(b".");
        source_digest.update(0_u64.to_be_bytes());
        source_digest.update(0_u64.to_be_bytes());
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("team");
        let certificate = SigningCertificate {
            common_name: "Apple Development".to_owned(),
            sha256_fingerprint: "A".repeat(64),
            team: team.clone(),
            expires_at_unix_seconds: u64::MAX,
        };
        let reference = |name| {
            SecretReference::new(SecretReferenceKind::Worker, name).expect("secret reference")
        };
        let signing = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate,
                    private_key: SigningPrivateKeyReference {
                        reference: reference("PRIVATE_KEY"),
                    },
                },
                password: Some(reference("PASSWORD")),
            }),
            team: Some(DevelopmentTeamPlan {
                expected: team.clone(),
            }),
            device: Some(DevicePlan::new("00008110-001234567890801E", None).expect("device")),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: reference("PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).expect("entitlements"),
            }],
            allow_provisioning_updates: false,
        };
        IosDeviceBuildRequest {
            protocol_version: rustferry_remote::CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-1".to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            minimum_ios_version: "16.0".to_owned(),
            product: rustferry_remote::IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1.0.0".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: rustferry_remote::SourceMode::Snapshot,
            source_repository: None,
            source_revision: None,
            source: rustferry_remote::SourceManifest {
                schema_version: 1,
                project_path: ".".to_owned(),
                entries: Vec::new(),
                total_size: 0,
                sha256: format!("{:x}", source_digest.finalize()),
            },
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Ipa]),
        }
    }

    #[derive(Default)]
    struct RecordingResolver {
        references: Vec<String>,
    }

    impl WorkerSecretResolver for RecordingResolver {
        fn resolve(
            &mut self,
            reference: &SecretReference,
        ) -> Result<SecretBytes, crate::job::WorkerHookFailure> {
            self.references.push(reference.name().to_owned());
            Ok(SecretBytes::new(b"profile-secret-bytes".to_vec()))
        }
    }
}
