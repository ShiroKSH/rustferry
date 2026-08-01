//! Cross-platform manifests and independent iPhone artifact inspection.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{Cursor, Read},
};

use camino::{Utf8Path, Utf8PathBuf};
use cap_std::{ambient_authority, fs::Dir};
use goblin::mach::{
    Mach, MachO, SingleArch,
    cputype::{
        CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_V8, CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86,
        CPU_TYPE_X86_64,
    },
    header::{MH_DYLIB, MH_EXECUTE},
    load_command::CommandVariant,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

use crate::signing::{SigningMode, SigningStatus};

/// Current artifact-manifest schema.
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: u32 = 1;

const MAX_IPA_ENTRIES: usize = 50_000;
const MAX_IPA_ENTRY_NAME: usize = 4_096;
const MAX_IPA_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_IPA_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_BUNDLE_DEPTH: usize = 128;
const RUNTIME_BRIDGE_BUNDLE_PATH: &str = "Frameworks/FerryRuntimeBridge.framework";
const RUNTIME_BRIDGE_INSTALL_NAME: &str = "@rpath/FerryRuntimeBridge.framework/FerryRuntimeBridge";
const ACTIVITY_MODEL_BUNDLE_PATH: &str = "Frameworks/FerryActivityModel.framework";
const ACTIVITY_MODEL_INSTALL_NAME: &str = "@rpath/FerryActivityModel.framework/FerryActivityModel";
const LIVE_ACTIVITY_BUNDLE_PATH: &str = "PlugIns/FerryLiveActivityExtension.appex";

/// One validation level proven by a concrete build or inspection step.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// Source paths and hashes were verified.
    SourceValidated,
    /// Remote builder identity and tools were inspected.
    RemoteBuilderValidated,
    /// Rust compiled for the physical-device target.
    DeviceTargetCompiled,
    /// A device Mach-O binary was produced.
    DeviceBinaryBuilt,
    /// A physical-device application bundle was produced.
    AppBundleBuilt,
    /// An Xcode archive was produced and inspected.
    ArchiveBuilt,
    /// Development certificate metadata was validated.
    CertificateValidated,
    /// Provisioning profile metadata was validated.
    ProvisioningValidated,
    /// Every nested code target was signed and checked.
    NestedCodeSigned,
    /// The main application signature was checked.
    ApplicationSigned,
    /// An IPA was exported by the Apple toolchain.
    IpaExported,
    /// Independent remote artifact validation passed.
    ArtifactValidated,
    /// Expected bytes and SHA-256 were verified on the client.
    DownloadedToClient,
    /// The application was installed on a physical device.
    InstallValidated,
    /// The application launched on a physical device.
    LaunchValidated,
    /// Runtime behavior was observed on a physical device.
    RuntimeValidated,
}

/// Artifact kind returned by a remote build.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Built `.app` directory, normally transported as an archive.
    App,
    /// Xcode `.xcarchive` directory, normally transported as an archive.
    Xcarchive,
    /// Installable iPhone application archive.
    Ipa,
    /// Compressed debug symbols.
    Dsym,
    /// Artifact manifest.
    Manifest,
    /// Signing evidence without secret material.
    SigningReport,
    /// Independent validation evidence.
    ValidationReport,
    /// Sanitized build log.
    SanitizedLog,
}

/// One downloadable artifact and its integrity metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    /// Provider-scoped immutable artifact identifier.
    pub artifact_id: String,
    /// Artifact kind.
    pub kind: ArtifactKind,
    /// Portable filename proposed to the client.
    pub file_name: String,
    /// Byte length reported by the producer.
    pub size: u64,
    /// Lowercase SHA-256 hex digest.
    pub sha256: String,
    /// Optional content type.
    pub media_type: Option<String>,
}

/// Worker and Apple toolchain evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppleToolchainEvidence {
    /// Worker operating-system version.
    pub worker_os: String,
    /// Worker architecture.
    pub worker_architecture: String,
    /// Xcode version selected for the job.
    pub xcode_version: String,
    /// iPhoneOS SDK version selected for the job.
    pub iphoneos_sdk_version: String,
    /// Rust compiler version.
    pub rust_version: String,
    /// Rust target triple; physical builds require `aarch64-apple-ios`.
    pub rust_target: String,
}

/// Public, non-secret signing evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSigningEvidence {
    /// Signing mode used by the worker.
    pub mode: SigningMode,
    /// Most advanced independently proven signing state.
    pub status: SigningStatus,
    /// Apple development Team ID.
    pub team_id: Option<String>,
    /// SHA-256 certificate fingerprint.
    pub certificate_fingerprint: Option<String>,
    /// Provisioning profile UUID.
    pub profile_uuid: Option<String>,
    /// RFC 3339 profile expiry.
    pub profile_expiration: Option<String>,
    /// SHA-256 of canonical entitlements.
    pub entitlements_sha256: Option<String>,
}

/// Cleanup result from the remote worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    /// Cleanup has not run yet.
    Pending,
    /// Source, signing inputs, and temporary keychain were removed.
    Confirmed,
    /// Cleanup completed with a safe warning.
    Warning,
    /// Cleanup could not be proven.
    Failed,
}

/// Immutable manifest binding source, worker, signing, and downloaded bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Client operation ID.
    pub operation_id: String,
    /// Provider job ID.
    pub job_id: String,
    /// Stable project ID.
    pub project_id: String,
    /// Source repository URL when Git source mode is used.
    pub source_repository: Option<String>,
    /// Exact commit SHA when Git source mode is used.
    pub source_revision: Option<String>,
    /// Whether explicit snapshot mode represented local changes.
    pub source_snapshot: bool,
    /// Deterministic source-manifest digest.
    pub source_sha256: String,
    /// Cargo lockfile digest.
    pub cargo_lock_sha256: String,
    /// Project configuration digest.
    pub config_sha256: String,
    /// `RustFerry` client version.
    pub rustferry_version: String,
    /// Remote worker version.
    pub worker_version: String,
    /// Provider identifier.
    pub provider: String,
    /// Apple and Rust toolchain evidence.
    pub toolchain: AppleToolchainEvidence,
    /// Application display name.
    pub app_name: String,
    /// Application semantic version.
    pub app_version: String,
    /// Application build number.
    pub build_number: String,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// Cargo/Xcode build profile.
    pub build_profile: String,
    /// Required device architecture.
    pub architecture: String,
    /// Public signing evidence.
    pub signing: ArtifactSigningEvidence,
    /// Embedded extension bundle identifiers.
    pub extensions: Vec<String>,
    /// Downloadable artifacts.
    pub artifacts: Vec<ArtifactRecord>,
    /// Individually proven validation levels.
    pub validation_levels: BTreeSet<ValidationLevel>,
    /// RFC 3339 job start time.
    pub started_at: String,
    /// RFC 3339 job completion time.
    pub finished_at: String,
    /// Worker cleanup status.
    pub cleanup_status: CleanupStatus,
}

impl ArtifactManifest {
    /// Construct an empty versioned manifest for a job.
    #[must_use]
    pub fn new(operation_id: impl Into<String>, job_id: impl Into<String>) -> Self {
        Self {
            schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            job_id: job_id.into(),
            project_id: String::new(),
            source_repository: None,
            source_revision: None,
            source_snapshot: false,
            source_sha256: String::new(),
            cargo_lock_sha256: String::new(),
            config_sha256: String::new(),
            rustferry_version: String::new(),
            worker_version: String::new(),
            provider: String::new(),
            toolchain: AppleToolchainEvidence {
                worker_os: String::new(),
                worker_architecture: String::new(),
                xcode_version: String::new(),
                iphoneos_sdk_version: String::new(),
                rust_version: String::new(),
                rust_target: String::new(),
            },
            app_name: String::new(),
            app_version: String::new(),
            build_number: String::new(),
            bundle_identifier: String::new(),
            build_profile: String::new(),
            architecture: String::new(),
            signing: ArtifactSigningEvidence {
                mode: SigningMode::UnsignedCompileOnly,
                status: SigningStatus::Unsigned,
                team_id: None,
                certificate_fingerprint: None,
                profile_uuid: None,
                profile_expiration: None,
                entitlements_sha256: None,
            },
            extensions: Vec::new(),
            artifacts: Vec::new(),
            validation_levels: BTreeSet::new(),
            started_at: String::new(),
            finished_at: String::new(),
            cleanup_status: CleanupStatus::Pending,
        }
    }

    /// Find exactly one artifact of the requested kind.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing or ambiguous.
    pub fn one_artifact(&self, kind: ArtifactKind) -> Result<&ArtifactRecord, ArtifactError> {
        let mut matches = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == kind);
        let artifact = matches
            .next()
            .ok_or(ArtifactError::ManifestArtifactMissing { kind })?;
        if matches.next().is_some() {
            return Err(ArtifactError::ManifestArtifactAmbiguous { kind });
        }
        Ok(artifact)
    }
}

/// Apple platform encoded in `LC_BUILD_VERSION`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplePlatform {
    /// Physical iOS device.
    Ios,
    /// iOS Simulator.
    IosSimulator,
    /// macOS.
    Macos,
    /// Mac Catalyst.
    MacCatalyst,
    /// visionOS device.
    VisionOs,
    /// visionOS Simulator.
    VisionOsSimulator,
    /// Another known Apple platform represented by its numeric value.
    Other(u32),
    /// Only legacy `LC_VERSION_MIN_IPHONEOS` was present; device status is not proven.
    LegacyIphoneOs,
}

/// Cross-platform Mach-O platform evidence for one architecture slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachOSliceEvidence {
    /// Architecture name.
    pub architecture: String,
    /// Apple platform.
    pub platform: ApplePlatform,
    /// Minimum operating-system version.
    pub minimum_os: Option<String>,
    /// SDK version recorded by the linker.
    pub sdk: Option<String>,
}

/// Expected metadata for client-side IPA inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpaExpectation {
    /// Exact main application directory name, including `.app`.
    pub app_directory_name: String,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// `CFBundleExecutable`.
    pub executable: String,
    /// Optional expected short version.
    pub app_version: Option<String>,
    /// Optional expected build number.
    pub build_number: Option<String>,
    /// Configured minimum iOS version.
    pub minimum_os: String,
    /// Exact generated extension and framework set.
    pub nested_bundles: Vec<UnsignedNestedBundleExpectation>,
    /// Whether a development provisioning profile must be embedded.
    pub provisioning_required: bool,
}

/// Evidence produced by cross-platform IPA inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpaInspection {
    /// Main application path under `Payload/`.
    pub app_path: String,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// Main executable name.
    pub executable: String,
    /// Main executable platform evidence.
    pub main_executable: Vec<MachOSliceEvidence>,
    /// Nested executable path to platform evidence.
    pub nested_executables: BTreeMap<String, Vec<MachOSliceEvidence>>,
    /// Embedded extension bundle identifiers.
    pub extensions: Vec<String>,
    /// Whether the main provisioning profile exists.
    pub provisioning_profile_present: bool,
    /// Sorted archive entries.
    pub entries: Vec<String>,
    /// IPA SHA-256.
    pub sha256: String,
    /// IPA byte size.
    pub size: u64,
}

/// Kind and expected package type of code nested inside an application bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnsignedNestedBundleKind {
    /// An iOS application extension (`.appex`, package type `XPC!`).
    AppExtension,
    /// An embedded dynamic framework (`.framework`, package type `FMWK`).
    Framework,
}

impl UnsignedNestedBundleKind {
    const fn package_type(self) -> &'static str {
        match self {
            Self::AppExtension => "XPC!",
            Self::Framework => "FMWK",
        }
    }

    const fn path_extension(self) -> &'static str {
        match self {
            Self::AppExtension => "appex",
            Self::Framework => "framework",
        }
    }
}

/// Expected identity of one generated extension or framework in an unsigned app.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsignedNestedBundleExpectation {
    /// Slash-separated path relative to the main `.app` root.
    pub relative_path: String,
    /// Exact nested bundle identifier.
    pub bundle_identifier: String,
    /// Exact `CFBundleExecutable` and executable filename.
    pub executable: String,
    /// Expected nested code kind.
    pub kind: UnsignedNestedBundleKind,
}

/// Client-owned product identity used to validate both unsigned and signed outputs.
///
/// Unlike [`UnsignedXcarchiveExpectation`], this contains no worker-selected SDK fields. Every
/// value is derived before provider submission and is therefore safe to use as an independent
/// artifact expectation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IosDeviceProductExpectation {
    /// Exact main application directory name, including `.app`.
    pub app_directory_name: String,
    /// Exact main `CFBundleExecutable` and executable filename.
    pub executable: String,
    /// Exact `CFBundleShortVersionString`.
    pub app_version: String,
    /// Exact `CFBundleVersion`.
    pub build_number: String,
    /// Exact generated extension and framework set.
    pub nested_bundles: Vec<UnsignedNestedBundleExpectation>,
}

/// Exact generated-product invariants for an unsigned physical-iPhone archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsignedXcarchiveExpectation {
    /// Exact application directory name, including `.app`.
    pub app_directory_name: String,
    /// Main application bundle identifier.
    pub bundle_identifier: String,
    /// Exact `CFBundleExecutable` and executable filename.
    pub executable: String,
    /// Exact `CFBundleShortVersionString`.
    pub app_version: String,
    /// Exact `CFBundleVersion`.
    pub build_number: String,
    /// Configured minimum iOS version.
    pub minimum_os: String,
    /// Exact selected iPhoneOS SDK version encoded by newly built code.
    pub sdk_version: String,
    /// Exact selected iPhoneOS SDK build version injected into processed plists.
    pub sdk_build_version: String,
    /// Exact generated extension and framework set.
    pub nested_bundles: Vec<UnsignedNestedBundleExpectation>,
    /// Required app-relative resource path to lowercase SHA-256.
    pub required_resources: BTreeMap<String, String>,
}

/// Cross-platform evidence for one unsigned physical-iPhone `.app` directory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsignedAppInspection {
    /// Exact application directory name.
    pub app_directory_name: String,
    /// Main application bundle identifier.
    pub bundle_identifier: String,
    /// Main executable name.
    pub executable: String,
    /// Main executable device-platform evidence.
    pub main_executable: Vec<MachOSliceEvidence>,
    /// Every other Mach-O path relative to the app and its device evidence.
    pub nested_executables: BTreeMap<String, Vec<MachOSliceEvidence>>,
    /// Sorted extension bundle identifiers.
    pub extensions: Vec<String>,
    /// Verified required resource hashes.
    pub resources: BTreeMap<String, String>,
    /// Sorted app-relative files and directories inspected.
    pub entries: Vec<String>,
}

/// Cross-platform evidence for an unsigned physical-iPhone `.xcarchive`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsignedXcarchiveInspection {
    /// Main application path relative to `Products/`.
    pub application_path: String,
    /// Architectures declared by the archive metadata.
    pub architectures: Vec<String>,
    /// Independently inspected application evidence.
    pub app: UnsignedAppInspection,
    /// Sorted archive-relative files and directories inspected.
    pub entries: Vec<String>,
}

/// Artifact or integrity validation failure.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// File-system operation failed.
    #[error("{action} `{path}` failed: {message}")]
    Io {
        /// Operation description.
        action: &'static str,
        /// Safe artifact path.
        path: Utf8PathBuf,
        /// I/O error text.
        message: String,
    },
    /// ZIP parsing or entry access failed.
    #[error("IPA `{path}` is not a valid ZIP archive: {message}")]
    Zip {
        /// IPA path.
        path: Utf8PathBuf,
        /// ZIP error text.
        message: String,
    },
    /// Archive safety or structure invariant failed.
    #[error("IPA `{path}` failed validation: {reason}")]
    InvalidIpa {
        /// IPA path.
        path: Utf8PathBuf,
        /// Secret-safe reason.
        reason: String,
    },
    /// Unsigned app or Xcode archive structure failed validation.
    #[error("Apple bundle `{path}` failed validation: {reason}")]
    InvalidAppleBundle {
        /// App or archive root.
        path: Utf8PathBuf,
        /// Secret-safe failed invariant.
        reason: String,
    },
    /// Mach-O parsing failed.
    #[error("Mach-O validation failed: {0}")]
    InvalidMachO(String),
    /// A Simulator binary was found where a device binary was required.
    #[error("This artifact targets iOS Simulator, not a physical iPhone")]
    SimulatorBinary,
    /// No arm64 slice was found.
    #[error("physical-iPhone executable does not contain arm64")]
    Arm64Missing,
    /// Platform evidence was missing or not physical iOS.
    #[error("Mach-O platform is not proven to be physical iOS: {0}")]
    DevicePlatformUnproven(String),
    /// Artifact manifest omitted an expected kind.
    #[error("artifact manifest does not contain {kind:?}")]
    ManifestArtifactMissing {
        /// Missing kind.
        kind: ArtifactKind,
    },
    /// Artifact manifest contains duplicate records for a kind.
    #[error("artifact manifest contains multiple {kind:?} records")]
    ManifestArtifactAmbiguous {
        /// Ambiguous kind.
        kind: ArtifactKind,
    },
    /// Downloaded bytes did not match the manifest.
    #[error("Downloaded artifact failed integrity verification: {reason}")]
    Integrity {
        /// Integrity mismatch.
        reason: String,
    },
}

/// Inspect a Mach-O and require physical-iPhone arm64 platform evidence.
///
/// # Errors
///
/// Rejects malformed binaries, archives embedded as fat slices, Simulator platforms, missing
/// `LC_BUILD_VERSION`, non-iOS slices, or a missing arm64 slice.
pub fn inspect_physical_iphone_macho(
    bytes: &[u8],
) -> Result<Vec<MachOSliceEvidence>, ArtifactError> {
    let parsed =
        Mach::parse(bytes).map_err(|error| ArtifactError::InvalidMachO(error.to_string()))?;
    let mut evidence = Vec::new();
    match parsed {
        Mach::Binary(binary) => evidence.push(inspect_macho_slice(&binary)?),
        Mach::Fat(container) => {
            for entry in &container {
                match entry.map_err(|error| ArtifactError::InvalidMachO(error.to_string()))? {
                    SingleArch::MachO(binary) => evidence.push(inspect_macho_slice(&binary)?),
                    SingleArch::Archive(_) => {
                        return Err(ArtifactError::InvalidMachO(
                            "fat executable contains a static archive slice".to_owned(),
                        ));
                    }
                }
            }
        }
    }
    if !evidence.iter().any(|slice| slice.architecture == "arm64") {
        return Err(ArtifactError::Arm64Missing);
    }
    for slice in &evidence {
        match slice.platform {
            ApplePlatform::Ios => {}
            ApplePlatform::IosSimulator => return Err(ArtifactError::SimulatorBinary),
            platform => {
                return Err(ArtifactError::DevicePlatformUnproven(format!(
                    "{} slice reports {platform:?}",
                    slice.architecture
                )));
            }
        }
    }
    evidence.sort_by(|left, right| left.architecture.cmp(&right.architecture));
    Ok(evidence)
}

fn inspect_macho_slice(binary: &MachO<'_>) -> Result<MachOSliceEvidence, ArtifactError> {
    let architecture = architecture_name(binary.header.cputype);
    let mut platform = None;
    let mut minimum_os = None;
    let mut sdk = None;
    for command in &binary.load_commands {
        match &command.command {
            CommandVariant::BuildVersion(build) => {
                let parsed_platform = apple_platform(build.platform);
                if platform.replace(parsed_platform).is_some() {
                    return Err(ArtifactError::InvalidMachO(format!(
                        "{architecture} slice has multiple LC_BUILD_VERSION commands"
                    )));
                }
                minimum_os = Some(decode_apple_version(build.minos));
                sdk = Some(decode_apple_version(build.sdk));
            }
            CommandVariant::VersionMinIphoneos(version) if platform.is_none() => {
                platform = Some(ApplePlatform::LegacyIphoneOs);
                minimum_os = Some(decode_apple_version(version.version));
                sdk = Some(decode_apple_version(version.sdk));
            }
            _ => {}
        }
    }
    let platform = platform.ok_or_else(|| {
        ArtifactError::DevicePlatformUnproven(format!(
            "{architecture} slice has no Apple platform load command"
        ))
    })?;
    Ok(MachOSliceEvidence {
        architecture,
        platform,
        minimum_os,
        sdk,
    })
}

fn apple_platform(value: u32) -> ApplePlatform {
    match value {
        1 => ApplePlatform::Macos,
        2 => ApplePlatform::Ios,
        6 => ApplePlatform::MacCatalyst,
        7 => ApplePlatform::IosSimulator,
        11 => ApplePlatform::VisionOs,
        12 => ApplePlatform::VisionOsSimulator,
        other => ApplePlatform::Other(other),
    }
}

fn architecture_name(cputype: u32) -> String {
    match cputype {
        CPU_TYPE_ARM64 => "arm64".to_owned(),
        CPU_TYPE_ARM => "arm".to_owned(),
        CPU_TYPE_X86_64 => "x86_64".to_owned(),
        CPU_TYPE_X86 => "x86".to_owned(),
        other => format!("cpu-{other:#x}"),
    }
}

fn decode_apple_version(value: u32) -> String {
    format!(
        "{}.{}.{}",
        (value >> 16) & 0xffff,
        (value >> 8) & 0xff,
        value & 0xff
    )
}

/// Verify a downloaded file's expected size and SHA-256.
///
/// # Errors
///
/// Returns an integrity error when metadata or bytes differ.
pub fn verify_downloaded_file(
    path: &Utf8Path,
    expected: &ArtifactRecord,
) -> Result<(), ArtifactError> {
    let metadata = path.metadata().map_err(|error| ArtifactError::Io {
        action: "read metadata for",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(ArtifactError::Integrity {
            reason: format!("`{path}` is not a regular file"),
        });
    }
    if metadata.len() != expected.size {
        return Err(ArtifactError::Integrity {
            reason: format!(
                "expected {} bytes for {}, downloaded {}",
                expected.size,
                expected.file_name,
                metadata.len()
            ),
        });
    }
    let actual = sha256_file(path)?;
    if !constant_time_ascii_eq(actual.as_bytes(), expected.sha256.as_bytes()) {
        return Err(ArtifactError::Integrity {
            reason: format!("SHA-256 mismatch for {}", expected.file_name),
        });
    }
    Ok(())
}

/// Inspect ZIP safety, payload metadata, and every discoverable nested Mach-O without Apple tools.
///
/// Remote `codesign` and profile validation remain separate required evidence. This client check
/// binds downloaded bytes to the manifest and rejects Simulator binaries; it does not claim to
/// reproduce Apple's signature verifier.
///
/// # Errors
///
/// Rejects unsafe or malformed ZIPs, structure/metadata mismatches, missing profiles, Simulator
/// code, unexpected source/signing material, or violated resource limits.
#[allow(clippy::too_many_lines)]
pub fn inspect_ipa(
    path: &Utf8Path,
    expectation: &IpaExpectation,
) -> Result<IpaInspection, ArtifactError> {
    let size = path
        .metadata()
        .map_err(|error| ArtifactError::Io {
            action: "read metadata for",
            path: path.to_owned(),
            message: error.to_string(),
        })?
        .len();
    let sha256 = sha256_file(path)?;
    let file = File::open(path).map_err(|error| ArtifactError::Io {
        action: "open",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| ArtifactError::Zip {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    if archive.len() > MAX_IPA_ENTRIES {
        return invalid_ipa(
            path,
            format!("archive has more than {MAX_IPA_ENTRIES} entries"),
        );
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut exact = BTreeSet::new();
    let mut folded = BTreeMap::<String, String>::new();
    let mut total_size = 0_u64;
    let mut app_info_plists = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ArtifactError::Zip {
                path: path.to_owned(),
                message: error.to_string(),
            })?;
        let name = entry.name().to_owned();
        validate_zip_name(path, &name)?;
        if !exact.insert(name.clone()) {
            return invalid_ipa(path, format!("duplicate ZIP entry `{name}`"));
        }
        let fold = canonical_archive_key(&name);
        if let Some(previous) = folded.insert(fold, name.clone())
            && previous != name
        {
            return invalid_ipa(
                path,
                format!("case-colliding ZIP entries `{previous}` and `{name}`"),
            );
        }
        if entry.size() > MAX_IPA_ENTRY_SIZE {
            return invalid_ipa(path, format!("entry `{name}` exceeds the per-file limit"));
        }
        total_size =
            total_size
                .checked_add(entry.size())
                .ok_or_else(|| ArtifactError::InvalidIpa {
                    path: path.to_owned(),
                    reason: "uncompressed size overflow".to_owned(),
                })?;
        if total_size > MAX_IPA_TOTAL_SIZE {
            return invalid_ipa(
                path,
                "uncompressed IPA exceeds the total-size limit".to_owned(),
            );
        }
        if entry.compressed_size() > 0
            && entry.size() > 1024 * 1024
            && entry.size() / entry.compressed_size() > MAX_COMPRESSION_RATIO
        {
            return invalid_ipa(
                path,
                format!("entry `{name}` exceeds the compression-ratio limit"),
            );
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            if kind != 0 && kind != 0o040_000 && kind != 0o100_000 {
                return invalid_ipa(path, format!("entry `{name}` is a link or special file"));
            }
        }
        reject_sensitive_or_generated_name(path, &name)?;
        if is_main_info_plist(&name) {
            app_info_plists.push(name.clone());
        }
        if !entry.is_dir() {
            let declared_size = entry.size();
            let unpacked_size =
                std::io::copy(&mut entry, &mut std::io::sink()).map_err(|error| {
                    ArtifactError::InvalidIpa {
                        path: path.to_owned(),
                        reason: format!(
                            "entry `{name}` failed ZIP integrity verification: {error}"
                        ),
                    }
                })?;
            if unpacked_size != declared_size {
                return invalid_ipa(
                    path,
                    format!(
                        "entry `{name}` declared {declared_size} bytes but unpacked {unpacked_size}"
                    ),
                );
            }
        }
        entries.push(name);
    }
    if app_info_plists.len() != 1 {
        return invalid_ipa(
            path,
            format!(
                "expected exactly one Payload/<App>.app/Info.plist, found {}",
                app_info_plists.len()
            ),
        );
    }
    let info_path = app_info_plists.pop().unwrap_or_default();
    let app_path = info_path.trim_end_matches("/Info.plist").to_owned();
    let expected_app_path = format!("Payload/{}", expectation.app_directory_name);
    if app_path != expected_app_path {
        return invalid_ipa(
            path,
            format!("application path is `{app_path}`, expected `{expected_app_path}`"),
        );
    }
    let info = read_zip_plist(&mut archive, path, &info_path)?;
    let bundle_identifier = plist_string(path, &info, "CFBundleIdentifier")?;
    let executable = plist_string(path, &info, "CFBundleExecutable")?;
    if bundle_identifier != expectation.bundle_identifier {
        return invalid_ipa(
            path,
            format!(
                "CFBundleIdentifier mismatch: expected `{}`, found `{bundle_identifier}`",
                expectation.bundle_identifier
            ),
        );
    }
    if executable != expectation.executable {
        return invalid_ipa(
            path,
            format!(
                "CFBundleExecutable mismatch: expected `{}`, found `{executable}`",
                expectation.executable
            ),
        );
    }
    if let Some(expected) = &expectation.app_version {
        let actual = plist_string(path, &info, "CFBundleShortVersionString")?;
        if &actual != expected {
            return invalid_ipa(
                path,
                format!("app version mismatch: expected `{expected}`, found `{actual}`"),
            );
        }
    }
    if let Some(expected) = &expectation.build_number {
        let actual = plist_string(path, &info, "CFBundleVersion")?;
        if &actual != expected {
            return invalid_ipa(
                path,
                format!("build number mismatch: expected `{expected}`, found `{actual}`"),
            );
        }
    }
    let minimum_os = plist_string(path, &info, "MinimumOSVersion")?;
    validate_ipa_minimum_os(path, "application", &minimum_os, &expectation.minimum_os)?;

    let executable_path = format!("{app_path}/{executable}");
    let main_bytes = read_zip_entry(&mut archive, path, &executable_path)?;
    let main_executable = inspect_physical_iphone_macho(&main_bytes)?;
    validate_ipa_macho_minimum_os(
        path,
        &executable_path,
        &main_executable,
        &expectation.minimum_os,
    )?;
    let profile_path = format!("{app_path}/embedded.mobileprovision");
    let provisioning_profile_present = exact.contains(&profile_path);
    if expectation.provisioning_required && !provisioning_profile_present {
        return invalid_ipa(path, "embedded.mobileprovision is missing".to_owned());
    }

    let mut extensions = Vec::new();
    let mut nested_executables = BTreeMap::new();
    let mut expected_nested = BTreeMap::new();
    for expected in &expectation.nested_bundles {
        if expected_nested
            .insert(expected.relative_path.as_str(), expected)
            .is_some()
        {
            return invalid_ipa(
                path,
                format!(
                    "duplicate nested bundle expectation `{}`",
                    expected.relative_path
                ),
            );
        }
    }
    let mut actual_nested = BTreeSet::new();
    let nested_plists = entries
        .iter()
        .filter(|name| {
            name.starts_with(&format!("{app_path}/"))
                && (name.ends_with(".appex/Info.plist") || name.ends_with(".framework/Info.plist"))
        })
        .cloned()
        .collect::<Vec<_>>();
    for nested_info_path in nested_plists {
        let nested_info = read_zip_plist(&mut archive, path, &nested_info_path)?;
        let nested_executable = plist_string(path, &nested_info, "CFBundleExecutable")?;
        let nested_root = nested_info_path.trim_end_matches("/Info.plist");
        let relative_root = nested_root
            .strip_prefix(&format!("{app_path}/"))
            .ok_or_else(|| ArtifactError::InvalidIpa {
                path: path.to_owned(),
                reason: format!("nested bundle `{nested_root}` escaped the main application"),
            })?;
        let expected =
            expected_nested
                .get(relative_root)
                .ok_or_else(|| ArtifactError::InvalidIpa {
                    path: path.to_owned(),
                    reason: format!("unexpected nested bundle `{relative_root}`"),
                })?;
        let actual_kind = if nested_info_path.ends_with(".appex/Info.plist") {
            UnsignedNestedBundleKind::AppExtension
        } else {
            UnsignedNestedBundleKind::Framework
        };
        let nested_bundle_identifier = plist_string(path, &nested_info, "CFBundleIdentifier")?;
        if expected.kind != actual_kind
            || expected.executable != nested_executable
            || expected.bundle_identifier != nested_bundle_identifier
        {
            return invalid_ipa(
                path,
                format!("nested bundle `{relative_root}` differs from its request expectation"),
            );
        }
        if let Some(expected_version) = &expectation.app_version {
            let actual_version = plist_string(path, &nested_info, "CFBundleShortVersionString")?;
            if actual_version != *expected_version {
                return invalid_ipa(
                    path,
                    format!("nested bundle `{relative_root}` has an unexpected app version"),
                );
            }
        }
        if let Some(expected_build) = &expectation.build_number {
            let actual_build = plist_string(path, &nested_info, "CFBundleVersion")?;
            if actual_build != *expected_build {
                return invalid_ipa(
                    path,
                    format!("nested bundle `{relative_root}` has an unexpected build number"),
                );
            }
        }
        let nested_minimum_os = plist_string(path, &nested_info, "MinimumOSVersion")?;
        validate_ipa_minimum_os(
            path,
            relative_root,
            &nested_minimum_os,
            &expectation.minimum_os,
        )?;
        let nested_path = format!("{nested_root}/{nested_executable}");
        let nested_bytes = read_zip_entry(&mut archive, path, &nested_path)?;
        let nested_evidence = inspect_physical_iphone_macho(&nested_bytes)?;
        validate_ipa_macho_minimum_os(
            path,
            &nested_path,
            &nested_evidence,
            &expectation.minimum_os,
        )?;
        if actual_kind == UnsignedNestedBundleKind::AppExtension {
            extensions.push(nested_bundle_identifier);
        }
        actual_nested.insert(relative_root.to_owned());
        nested_executables.insert(nested_path, nested_evidence);
    }
    if actual_nested
        != expected_nested
            .keys()
            .map(|path| (*path).to_owned())
            .collect()
    {
        return invalid_ipa(
            path,
            "nested bundle set differs from the request".to_owned(),
        );
    }
    for name in entries.iter().filter(|name| {
        name.starts_with(&format!("{app_path}/Frameworks/")) && has_ascii_extension(name, "dylib")
    }) {
        let bytes = read_zip_entry(&mut archive, path, name)?;
        nested_executables.insert(name.clone(), inspect_physical_iphone_macho(&bytes)?);
    }
    extensions.sort();
    entries.sort();
    Ok(IpaInspection {
        app_path,
        bundle_identifier,
        executable,
        main_executable,
        nested_executables,
        extensions,
        provisioning_profile_present,
        entries,
        sha256,
        size,
    })
}

fn validate_ipa_minimum_os(
    path: &Utf8Path,
    context: &str,
    actual: &str,
    expected: &str,
) -> Result<(), ArtifactError> {
    let actual = parse_apple_version(actual);
    let expected = parse_apple_version(expected);
    if actual.is_none() || actual != expected {
        return invalid_ipa(
            path,
            format!("{context} minimum iOS version does not match the request"),
        );
    }
    Ok(())
}

fn validate_ipa_macho_minimum_os(
    path: &Utf8Path,
    relative: &str,
    evidence: &[MachOSliceEvidence],
    expected: &str,
) -> Result<(), ArtifactError> {
    let expected = parse_apple_version(expected).ok_or_else(|| ArtifactError::InvalidIpa {
        path: path.to_owned(),
        reason: "request minimum iOS version is invalid".to_owned(),
    })?;
    if evidence
        .iter()
        .any(|slice| slice.minimum_os.as_deref().and_then(parse_apple_version) != Some(expected))
    {
        return invalid_ipa(
            path,
            format!("Mach-O `{relative}` minimum iOS version does not match the request"),
        );
    }
    Ok(())
}

/// Inspect an unsigned physical-iPhone `.xcarchive` without trusting Xcode's exit status.
///
/// The archive must contain exactly one generated application below `Products/Applications`.
/// Archive and app metadata, generated resources, all nested bundles, and every runtime Mach-O
/// are checked independently. Signing material and non-empty Mach-O signature payloads are
/// forbidden because this function validates the credential-free compilation phase.
///
/// # Errors
///
/// Rejects generic or ambiguous archives, unsafe filesystem objects, metadata/resource drift,
/// unexpected nested products or code, Simulator/non-arm64 code, and signing material.
pub fn inspect_unsigned_xcarchive(
    path: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<UnsignedXcarchiveInspection, ArtifactError> {
    validate_unsigned_expectation(path, expectation)?;
    let filesystem = ArtifactFilesystem::open_ambient(path)?;
    let tree = scan_real_tree(&filesystem)?;
    let expected_app = format!("Products/Applications/{}", expectation.app_directory_name);

    let product_children = direct_children(&tree, "Products");
    if product_children != BTreeSet::from(["Products/Applications".to_owned()]) {
        return invalid_apple_bundle(
            path,
            format!(
                "Products must contain only Applications, found {product_children:?}; generic or multi-product archives are not accepted"
            ),
        );
    }
    let application_children = direct_children(&tree, "Products/Applications");
    if application_children != BTreeSet::from([expected_app.clone()]) {
        return invalid_apple_bundle(
            path,
            format!("expected exactly `{expected_app}`, found {application_children:?}"),
        );
    }
    require_tree_directory(path, &tree, &expected_app)?;

    let archive_info = read_filesystem_plist(&filesystem, Utf8Path::new("Info.plist"))?;
    let properties = archive_info
        .get("ApplicationProperties")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: path.to_owned(),
            reason: "archive Info.plist has no ApplicationProperties dictionary; this is not an Organizer-style app archive".to_owned(),
        })?;
    let application_path = required_plist_string(
        path,
        properties,
        "ApplicationPath",
        "archive ApplicationProperties",
    )?;
    let expected_application_path = format!("Applications/{}", expectation.app_directory_name);
    if application_path != expected_application_path {
        return invalid_apple_bundle(
            path,
            format!(
                "archive ApplicationPath is `{application_path}`, expected `{expected_application_path}`"
            ),
        );
    }
    validate_plist_identity(
        path,
        properties,
        "archive ApplicationProperties",
        &expectation.bundle_identifier,
        &expectation.app_version,
        &expectation.build_number,
    )?;
    let architectures = plist_string_array(
        path,
        properties,
        "Architectures",
        "archive ApplicationProperties",
    )?;
    if architectures != ["arm64"] {
        return invalid_apple_bundle(
            path,
            format!("archive architectures are {architectures:?}, expected exactly [\"arm64\"]"),
        );
    }
    for key in [
        "SigningIdentity",
        "Team",
        "ProvisioningProfile",
        "ApplicationIdentifier",
    ] {
        if let Some(value) = properties.get(key)
            && !plist_value_is_empty(value)
        {
            return invalid_apple_bundle(
                path,
                format!("unsigned archive contains non-empty signing metadata `{key}`"),
            );
        }
    }

    let app_filesystem = filesystem.open_subdirectory(Utf8Path::new(&expected_app))?;
    let app = inspect_unsigned_app_bundle_from_capability(&app_filesystem, expectation)?;
    app_filesystem.verify_ambient_binding()?;
    let inspection = UnsignedXcarchiveInspection {
        application_path,
        architectures,
        app,
        entries: tree.relative_paths(),
    };
    filesystem.verify_ambient_binding()?;
    Ok(inspection)
}

/// Inspect an unsigned physical-iPhone `.app` directory and every runtime code object.
///
/// # Errors
///
/// Rejects unsafe filesystem objects, identity/resource mismatches, an unexpected bundle or
/// executable, signing material, non-arm64 slices, or non-device Apple platforms.
#[allow(clippy::too_many_lines)]
pub fn inspect_unsigned_app_bundle(
    path: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<UnsignedAppInspection, ArtifactError> {
    validate_unsigned_expectation(path, expectation)?;
    let filesystem = ArtifactFilesystem::open_ambient(path)?;
    let inspection = inspect_unsigned_app_bundle_from_capability(&filesystem, expectation)?;
    filesystem.verify_ambient_binding()?;
    Ok(inspection)
}

#[allow(clippy::too_many_lines)]
fn inspect_unsigned_app_bundle_from_capability(
    filesystem: &ArtifactFilesystem,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<UnsignedAppInspection, ArtifactError> {
    let path = filesystem.display_path();
    if path.file_name() != Some(expectation.app_directory_name.as_str()) {
        return invalid_apple_bundle(
            path,
            format!(
                "application directory name is {:?}, expected `{}`",
                path.file_name(),
                expectation.app_directory_name
            ),
        );
    }
    let tree = scan_real_tree(filesystem)?;
    let info = read_filesystem_plist(filesystem, Utf8Path::new("Info.plist"))?;
    validate_plist_identity(
        path,
        &info,
        "application Info.plist",
        &expectation.bundle_identifier,
        &expectation.app_version,
        &expectation.build_number,
    )?;
    validate_plist_string(
        path,
        &info,
        "application Info.plist",
        "CFBundleExecutable",
        &expectation.executable,
    )?;
    validate_plist_string(
        path,
        &info,
        "application Info.plist",
        "CFBundlePackageType",
        "APPL",
    )?;
    validate_minimum_os(
        path,
        &info,
        "application Info.plist",
        &expectation.minimum_os,
    )?;
    if info
        .get("LSRequiresIPhoneOS")
        .and_then(plist::Value::as_boolean)
        != Some(true)
    {
        return invalid_apple_bundle(path, "application does not require iPhoneOS".to_owned());
    }
    validate_supported_platform(path, &info, "application Info.plist", expectation)?;
    let capabilities = plist_string_array(
        path,
        &info,
        "UIRequiredDeviceCapabilities",
        "application Info.plist",
    )?;
    if !capabilities.iter().any(|capability| capability == "arm64") {
        return invalid_apple_bundle(
            path,
            "application does not declare the arm64 device capability".to_owned(),
        );
    }

    let expected_nested = expectation
        .nested_bundles
        .iter()
        .map(|bundle| (bundle.relative_path.clone(), bundle))
        .collect::<BTreeMap<_, _>>();
    let live_activity_enabled = expected_nested.contains_key(LIVE_ACTIVITY_BUNDLE_PATH);
    let actual_nested = tree
        .entries
        .iter()
        .filter(|entry| entry.kind == TreeEntryKind::Directory)
        .filter(|entry| {
            ["appex", "framework"]
                .iter()
                .any(|extension| has_ascii_extension(&entry.relative, extension))
        })
        .map(|entry| entry.relative.clone())
        .collect::<BTreeSet<_>>();
    let expected_nested_paths = expected_nested.keys().cloned().collect::<BTreeSet<_>>();
    if actual_nested != expected_nested_paths {
        return invalid_apple_bundle(
            path,
            format!(
                "nested bundle set mismatch: expected {expected_nested_paths:?}, found {actual_nested:?}"
            ),
        );
    }
    for entry in &tree.entries {
        if entry.kind == TreeEntryKind::Directory
            && (has_ascii_extension(&entry.relative, "app")
                || has_ascii_extension(&entry.relative, "xpc"))
        {
            return invalid_apple_bundle(
                path,
                format!("unexpected nested product `{}`", entry.relative),
            );
        }
    }

    let mut extensions = Vec::new();
    let mut expected_code = BTreeMap::new();
    expected_code.insert(
        expectation.executable.clone(),
        ExpectedMachOKind::Executable,
    );
    for (relative, expected) in &expected_nested {
        let nested_info_path = Utf8Path::new(relative).join("Info.plist");
        let nested_info = read_filesystem_plist(filesystem, &nested_info_path)?;
        validate_plist_string(
            path,
            &nested_info,
            relative,
            "CFBundleIdentifier",
            &expected.bundle_identifier,
        )?;
        validate_plist_string(
            path,
            &nested_info,
            relative,
            "CFBundleExecutable",
            &expected.executable,
        )?;
        validate_plist_string(
            path,
            &nested_info,
            relative,
            "CFBundlePackageType",
            expected.kind.package_type(),
        )?;
        let (nested_version, nested_build) = match expected.kind {
            UnsignedNestedBundleKind::AppExtension => (
                expectation.app_version.as_str(),
                expectation.build_number.as_str(),
            ),
            UnsignedNestedBundleKind::Framework => ("1.0", "1"),
        };
        validate_plist_string(
            path,
            &nested_info,
            relative,
            "CFBundleShortVersionString",
            nested_version,
        )?;
        validate_plist_string(
            path,
            &nested_info,
            relative,
            "CFBundleVersion",
            nested_build,
        )?;
        validate_minimum_os(path, &nested_info, relative, &expectation.minimum_os)?;
        validate_supported_platform(path, &nested_info, relative, expectation)?;
        if expected.kind == UnsignedNestedBundleKind::AppExtension {
            validate_extension_point(path, &nested_info, relative)?;
            extensions.push(expected.bundle_identifier.clone());
        }
        let executable_path = format!("{relative}/{}", expected.executable);
        let kind = match expected.kind {
            UnsignedNestedBundleKind::AppExtension => ExpectedMachOKind::Executable,
            UnsignedNestedBundleKind::Framework => ExpectedMachOKind::DynamicLibrary,
        };
        expected_code.insert(executable_path, kind);
    }

    let mut resources = BTreeMap::new();
    for (relative, expected_sha256) in &expectation.required_resources {
        let bytes = read_checked_file(filesystem, Utf8Path::new(relative), MAX_IPA_ENTRY_SIZE)?;
        let actual_sha256 = sha256_bytes(&bytes);
        if !constant_time_ascii_eq(actual_sha256.as_bytes(), expected_sha256.as_bytes()) {
            return invalid_apple_bundle(
                path,
                format!("required resource `{relative}` has the wrong SHA-256"),
            );
        }
        if relative == "FerryResources.json" {
            validate_ferry_resource_metadata(path, &bytes, expectation)?;
        }
        resources.insert(relative.clone(), actual_sha256);
    }

    let mut discovered_code = BTreeMap::new();
    for entry in tree
        .entries
        .iter()
        .filter(|entry| entry.kind == TreeEntryKind::File)
    {
        let file_path = Utf8Path::new(&entry.relative);
        let is_macho = file_has_macho_magic(filesystem, file_path)?;
        let expected_kind = expected_code.get(&entry.relative).copied();
        let swift_runtime = is_permitted_swift_runtime(&entry.relative);
        if !is_macho {
            if expected_kind.is_some() || has_ascii_extension(&entry.relative, "dylib") {
                return invalid_apple_bundle(
                    path,
                    format!("expected Mach-O code at `{}`", entry.relative),
                );
            }
            continue;
        }
        let Some(kind) =
            expected_kind.or(swift_runtime.then_some(ExpectedMachOKind::DynamicLibrary))
        else {
            return invalid_apple_bundle(
                path,
                format!("unexpected Mach-O code hidden at `{}`", entry.relative),
            );
        };
        validate_executable_mode(filesystem, &entry.relative, file_path)?;
        let bytes = read_checked_file(filesystem, file_path, MAX_IPA_ENTRY_SIZE)?;
        let evidence = inspect_expected_unsigned_macho(
            path,
            &entry.relative,
            &bytes,
            ExpectedUnsignedMachO {
                kind,
                linkage: ferry_macho_linkage(&entry.relative, live_activity_enabled),
                minimum_os: &expectation.minimum_os,
                sdk: &expectation.sdk_version,
                prebuilt_swift_runtime: swift_runtime,
            },
        )?;
        discovered_code.insert(entry.relative.clone(), evidence);
    }
    for expected_path in expected_code.keys() {
        if !discovered_code.contains_key(expected_path) {
            return invalid_apple_bundle(
                path,
                format!("expected executable `{expected_path}` is missing"),
            );
        }
    }
    let main_executable = discovered_code
        .remove(&expectation.executable)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: path.to_owned(),
            reason: format!("main executable `{}` is missing", expectation.executable),
        })?;
    extensions.sort();
    Ok(UnsignedAppInspection {
        app_directory_name: expectation.app_directory_name.clone(),
        bundle_identifier: expectation.bundle_identifier.clone(),
        executable: expectation.executable.clone(),
        main_executable,
        nested_executables: discovered_code,
        extensions,
        resources,
        entries: tree.relative_paths(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeEntryKind {
    Directory,
    File,
}

#[derive(Clone, Debug)]
struct TreeEntry {
    relative: String,
    kind: TreeEntryKind,
}

#[derive(Debug)]
struct TreeIndex {
    entries: Vec<TreeEntry>,
}

impl TreeIndex {
    fn relative_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.relative.clone())
            .collect()
    }
}

struct ArtifactFilesystem {
    display_path: Utf8PathBuf,
    directory: Dir,
    binding: ArtifactBinding,
}

struct ArtifactBinding {
    root_display_path: Utf8PathBuf,
    root_directory: Dir,
    root_identity: same_file::Handle,
    relative: Utf8PathBuf,
    expected_identity: same_file::Handle,
}

impl ArtifactFilesystem {
    fn open_ambient(display_path: &Utf8Path) -> Result<Self, ArtifactError> {
        validate_ambient_directory(display_path)?;
        let directory =
            Dir::open_ambient_dir(display_path, ambient_authority()).map_err(|error| {
                ArtifactError::Io {
                    action: "open artifact directory",
                    path: display_path.to_owned(),
                    message: error.to_string(),
                }
            })?;
        let root_identity = directory_handle(&directory).map_err(|error| ArtifactError::Io {
            action: "identify open artifact directory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
        let expected_identity =
            directory_handle(&directory).map_err(|error| ArtifactError::Io {
                action: "identify open artifact directory",
                path: display_path.to_owned(),
                message: error.to_string(),
            })?;
        let root_directory = directory.try_clone().map_err(|error| ArtifactError::Io {
            action: "clone open artifact directory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
        let filesystem = Self {
            display_path: display_path.to_owned(),
            directory,
            binding: ArtifactBinding {
                root_display_path: display_path.to_owned(),
                root_directory,
                root_identity,
                relative: Utf8PathBuf::from("."),
                expected_identity,
            },
        };
        filesystem.verify_ambient_binding()?;
        Ok(filesystem)
    }

    fn open_subdirectory(&self, relative: &Utf8Path) -> Result<Self, ArtifactError> {
        validate_portable_relative_path(
            self.display_path(),
            "artifact subdirectory",
            relative.as_str(),
        )?;
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|error| ArtifactError::Io {
                action: "clone artifact directory handle",
                path: self.display_path.clone(),
                message: error.to_string(),
            })?;
        let mut display_path = self.display_path.clone();
        for component in relative.components() {
            let camino::Utf8Component::Normal(component) = component else {
                return invalid_apple_bundle(
                    self.display_path(),
                    format!("unsafe artifact subdirectory `{relative}`"),
                );
            };
            display_path.push(component);
            directory =
                open_child_directory(self.display_path(), &display_path, &directory, component)?;
        }
        let expected_identity =
            directory_handle(&directory).map_err(|error| ArtifactError::Io {
                action: "identify open artifact subdirectory",
                path: display_path.clone(),
                message: error.to_string(),
            })?;
        let binding_relative = if self.binding.relative.as_str() == "." {
            relative.to_owned()
        } else {
            self.binding.relative.join(relative)
        };
        let root_directory =
            self.binding
                .root_directory
                .try_clone()
                .map_err(|error| ArtifactError::Io {
                    action: "clone artifact binding root",
                    path: self.binding.root_display_path.clone(),
                    message: error.to_string(),
                })?;
        let root_identity =
            directory_handle(&root_directory).map_err(|error| ArtifactError::Io {
                action: "identify artifact binding root",
                path: self.binding.root_display_path.clone(),
                message: error.to_string(),
            })?;
        Ok(Self {
            display_path,
            directory,
            binding: ArtifactBinding {
                root_display_path: self.binding.root_display_path.clone(),
                root_directory,
                root_identity,
                relative: binding_relative,
                expected_identity,
            },
        })
    }

    fn display_path(&self) -> &Utf8Path {
        &self.display_path
    }

    fn display_entry(&self, relative: &Utf8Path) -> Utf8PathBuf {
        self.display_path.join(relative)
    }

    fn verify_ambient_binding(&self) -> Result<(), ArtifactError> {
        validate_ambient_directory(&self.binding.root_display_path)?;
        let current_root =
            same_file::Handle::from_path(&self.binding.root_display_path).map_err(|error| {
                ArtifactError::Io {
                    action: "reidentify artifact root path",
                    path: self.binding.root_display_path.clone(),
                    message: error.to_string(),
                }
            })?;
        let open_root =
            directory_handle(&self.binding.root_directory).map_err(|error| ArtifactError::Io {
                action: "reidentify open artifact root",
                path: self.binding.root_display_path.clone(),
                message: error.to_string(),
            })?;
        if current_root != self.binding.root_identity || open_root != self.binding.root_identity {
            return invalid_apple_bundle(
                &self.binding.root_display_path,
                "artifact root path was replaced during validation".to_owned(),
            );
        }
        let open_expected =
            directory_handle(&self.directory).map_err(|error| ArtifactError::Io {
                action: "reidentify open artifact directory",
                path: self.display_path.clone(),
                message: error.to_string(),
            })?;
        if open_expected != self.binding.expected_identity {
            return invalid_apple_bundle(
                &self.binding.root_display_path,
                "open artifact directory identity changed during validation".to_owned(),
            );
        }
        if self.binding.relative.as_str() != "." {
            let mut current =
                self.binding
                    .root_directory
                    .try_clone()
                    .map_err(|error| ArtifactError::Io {
                        action: "clone artifact root for path rebinding",
                        path: self.binding.root_display_path.clone(),
                        message: error.to_string(),
                    })?;
            let mut display_path = self.binding.root_display_path.clone();
            for component in self.binding.relative.components() {
                let camino::Utf8Component::Normal(component) = component else {
                    return invalid_apple_bundle(
                        &self.binding.root_display_path,
                        "artifact binding contains an unsafe component".to_owned(),
                    );
                };
                display_path.push(component);
                current = open_child_directory(
                    &self.binding.root_display_path,
                    &display_path,
                    &current,
                    component,
                )?;
            }
            let current_identity =
                directory_handle(&current).map_err(|error| ArtifactError::Io {
                    action: "reidentify rebound artifact directory",
                    path: display_path,
                    message: error.to_string(),
                })?;
            if current_identity != self.binding.expected_identity {
                return invalid_apple_bundle(
                    &self.binding.root_display_path,
                    format!(
                        "artifact subdirectory `{}` was replaced during validation",
                        self.binding.relative
                    ),
                );
            }
        }
        Ok(())
    }
}

fn validate_ambient_directory(path: &Utf8Path) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ArtifactError::Io {
        action: "inspect artifact directory path",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid_apple_bundle(path, "artifact root is not a real directory".to_owned());
    }
    Ok(())
}

fn directory_handle(directory: &Dir) -> std::io::Result<same_file::Handle> {
    same_file::Handle::from_file(directory.try_clone()?.into_std_file())
}

fn open_child_directory(
    root: &Utf8Path,
    display_path: &Utf8Path,
    parent: &Dir,
    component: &str,
) -> Result<Dir, ArtifactError> {
    let before = parent
        .symlink_metadata(component)
        .map_err(|error| ArtifactError::Io {
            action: "inspect artifact subdirectory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return invalid_apple_bundle(
            root,
            format!("artifact entry `{display_path}` is a link or not a directory"),
        );
    }
    let opened = parent
        .open_dir(component)
        .map_err(|error| ArtifactError::Io {
            action: "open artifact subdirectory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    let opened_handle = directory_handle(&opened).map_err(|error| ArtifactError::Io {
        action: "identify open artifact subdirectory",
        path: display_path.to_owned(),
        message: error.to_string(),
    })?;
    let after = parent
        .symlink_metadata(component)
        .map_err(|error| ArtifactError::Io {
            action: "reinspect artifact subdirectory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    if after.file_type().is_symlink() || !after.is_dir() {
        return invalid_apple_bundle(
            root,
            format!("artifact entry `{display_path}` changed type"),
        );
    }
    let current = parent
        .open_dir(component)
        .map_err(|error| ArtifactError::Io {
            action: "reopen artifact subdirectory",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    let current_handle = directory_handle(&current).map_err(|error| ArtifactError::Io {
        action: "reidentify artifact subdirectory",
        path: display_path.to_owned(),
        message: error.to_string(),
    })?;
    if opened_handle != current_handle {
        return invalid_apple_bundle(
            root,
            format!("artifact subdirectory `{display_path}` changed while being opened"),
        );
    }
    Ok(opened)
}

#[derive(Clone, Copy, Debug)]
enum ExpectedMachOKind {
    Executable,
    DynamicLibrary,
}

#[derive(Clone, Copy, Debug)]
enum FerryMachOLinkage {
    None,
    RuntimeBridge { activity_model_required: bool },
    ActivityModel,
    LiveActivityExtension,
}

#[derive(Clone, Copy, Debug)]
struct ExpectedUnsignedMachO<'a> {
    kind: ExpectedMachOKind,
    linkage: FerryMachOLinkage,
    minimum_os: &'a str,
    sdk: &'a str,
    prebuilt_swift_runtime: bool,
}

fn ferry_macho_linkage(relative: &str, live_activity_enabled: bool) -> FerryMachOLinkage {
    match Utf8Path::new(relative).parent().map(Utf8Path::as_str) {
        Some(RUNTIME_BRIDGE_BUNDLE_PATH) => FerryMachOLinkage::RuntimeBridge {
            activity_model_required: live_activity_enabled,
        },
        Some(ACTIVITY_MODEL_BUNDLE_PATH) => FerryMachOLinkage::ActivityModel,
        Some(LIVE_ACTIVITY_BUNDLE_PATH) => FerryMachOLinkage::LiveActivityExtension,
        _ => FerryMachOLinkage::None,
    }
}

fn validate_unsigned_expectation(
    root: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    validate_expectation_identity(root, expectation)?;
    validate_nested_expectations(root, expectation)?;
    validate_resource_expectations(root, expectation)
}

fn validate_expectation_identity(
    root: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    validate_portable_component(
        root,
        "application directory",
        &expectation.app_directory_name,
    )?;
    if !has_ascii_extension(&expectation.app_directory_name, "app") {
        return invalid_apple_bundle(
            root,
            "expected application directory must end with `.app`".to_owned(),
        );
    }
    validate_portable_component(root, "main executable", &expectation.executable)?;
    for (label, value) in [
        ("bundle identifier", expectation.bundle_identifier.as_str()),
        ("app version", expectation.app_version.as_str()),
        ("build number", expectation.build_number.as_str()),
        ("SDK build version", expectation.sdk_build_version.as_str()),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return invalid_apple_bundle(root, format!("expected {label} is empty or unsafe"));
        }
    }
    parse_apple_version(&expectation.minimum_os).ok_or_else(|| {
        ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!(
                "expected minimum iOS version `{}` is not numeric",
                expectation.minimum_os
            ),
        }
    })?;
    parse_apple_version(&expectation.sdk_version).ok_or_else(|| {
        ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!(
                "expected iPhoneOS SDK version `{}` is not numeric",
                expectation.sdk_version
            ),
        }
    })?;
    Ok(())
}

fn validate_nested_expectations(
    root: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    let mut canonical_paths = BTreeMap::new();
    let mut bundle_identifiers = BTreeSet::from([expectation.bundle_identifier.clone()]);
    for nested in &expectation.nested_bundles {
        validate_portable_relative_path(root, "nested bundle", &nested.relative_path)?;
        validate_portable_component(root, "nested executable", &nested.executable)?;
        if !has_ascii_extension(&nested.relative_path, nested.kind.path_extension()) {
            return invalid_apple_bundle(
                root,
                format!(
                    "nested {:?} path `{}` has the wrong extension",
                    nested.kind, nested.relative_path
                ),
            );
        }
        let relative = Utf8Path::new(&nested.relative_path);
        let expected_parent = match nested.kind {
            UnsignedNestedBundleKind::AppExtension => Utf8Path::new("PlugIns"),
            UnsignedNestedBundleKind::Framework => Utf8Path::new("Frameworks"),
        };
        if relative.parent() != Some(expected_parent) {
            return invalid_apple_bundle(
                root,
                format!(
                    "nested {:?} `{}` is not directly below `{expected_parent}`",
                    nested.kind, nested.relative_path
                ),
            );
        }
        let canonical = canonical_archive_key(&nested.relative_path);
        if let Some(previous) = canonical_paths.insert(canonical, nested.relative_path.clone()) {
            return invalid_apple_bundle(
                root,
                format!(
                    "nested bundle paths `{previous}` and `{}` collide",
                    nested.relative_path
                ),
            );
        }
        if nested.bundle_identifier.trim().is_empty()
            || !bundle_identifiers.insert(nested.bundle_identifier.clone())
        {
            return invalid_apple_bundle(
                root,
                format!(
                    "nested bundle identifier `{}` is empty or duplicated",
                    nested.bundle_identifier
                ),
            );
        }
    }
    if !expectation
        .nested_bundles
        .iter()
        .any(|nested| nested.relative_path == RUNTIME_BRIDGE_BUNDLE_PATH)
    {
        return invalid_apple_bundle(
            root,
            format!("generated archive expectation omitted `{RUNTIME_BRIDGE_BUNDLE_PATH}`"),
        );
    }
    let has_activity_model = expectation
        .nested_bundles
        .iter()
        .any(|nested| nested.relative_path == ACTIVITY_MODEL_BUNDLE_PATH);
    let has_live_activity = expectation
        .nested_bundles
        .iter()
        .any(|nested| nested.relative_path == LIVE_ACTIVITY_BUNDLE_PATH);
    if has_activity_model != has_live_activity {
        return invalid_apple_bundle(
            root,
            "FerryActivityModel and FerryLiveActivityExtension expectations must be present together"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_resource_expectations(
    root: &Utf8Path,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    for required in ["FerryResources.json", "FerryIcon.png", "FerrySplash.png"] {
        if !expectation.required_resources.contains_key(required) {
            return invalid_apple_bundle(
                root,
                format!("required generated resource expectation `{required}` is missing"),
            );
        }
    }
    for (relative, digest) in &expectation.required_resources {
        validate_portable_relative_path(root, "required resource", relative)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return invalid_apple_bundle(
                root,
                format!("resource `{relative}` has a non-canonical SHA-256 expectation"),
            );
        }
    }
    Ok(())
}

fn validate_portable_component(
    root: &Utf8Path,
    label: &str,
    component: &str,
) -> Result<(), ArtifactError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_IPA_ENTRY_NAME
        || component.contains(['/', '\\', '\0', ':'])
        || component.chars().any(char::is_control)
    {
        return invalid_apple_bundle(root, format!("{label} `{component}` is not portable"));
    }
    Ok(())
}

fn validate_portable_relative_path(
    root: &Utf8Path,
    label: &str,
    relative: &str,
) -> Result<(), ArtifactError> {
    if relative.is_empty()
        || relative.len() > MAX_IPA_ENTRY_NAME
        || relative.starts_with(['/', '\\'])
        || relative.contains(['\\', '\0'])
        || relative.chars().any(char::is_control)
    {
        return invalid_apple_bundle(root, format!("{label} path `{relative}` is unsafe"));
    }
    for component in relative.split('/') {
        validate_portable_component(root, label, component)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn scan_real_tree(filesystem: &ArtifactFilesystem) -> Result<TreeIndex, ArtifactError> {
    let root = filesystem.display_path();
    let mut entries = Vec::new();
    let root_directory = filesystem
        .directory
        .try_clone()
        .map_err(|error| ArtifactError::Io {
            action: "clone artifact root handle",
            path: root.to_owned(),
            message: error.to_string(),
        })?;
    let mut stack = vec![(root_directory, String::new(), 0_usize)];
    let mut exact = BTreeSet::new();
    let mut canonical = BTreeMap::<String, String>::new();
    let mut total_size = 0_u64;
    while let Some((directory, prefix, depth)) = stack.pop() {
        let display_directory = if prefix.is_empty() {
            root.to_owned()
        } else {
            root.join(&prefix)
        };
        let iterator = directory.entries().map_err(|error| ArtifactError::Io {
            action: "read directory",
            path: display_directory.clone(),
            message: error.to_string(),
        })?;
        let mut children = Vec::new();
        for child in iterator {
            let child = child.map_err(|error| ArtifactError::Io {
                action: "read entry from",
                path: display_directory.clone(),
                message: error.to_string(),
            })?;
            let name = child.file_name().into_string().map_err(|name| {
                ArtifactError::InvalidAppleBundle {
                    path: root.to_owned(),
                    reason: format!(
                        "artifact contains a non-UTF-8 name: {}",
                        name.to_string_lossy()
                    ),
                }
            })?;
            children.push((name, child));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, child) in children {
            validate_portable_component(root, "artifact entry", &name)?;
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            validate_portable_relative_path(root, "artifact entry", &relative)?;
            if !exact.insert(relative.clone()) {
                return invalid_apple_bundle(root, format!("duplicate entry `{relative}`"));
            }
            let collision_key = canonical_archive_key(&relative);
            if let Some(previous) = canonical.insert(collision_key, relative.clone())
                && previous != relative
            {
                return invalid_apple_bundle(
                    root,
                    format!("case/Unicode-colliding entries `{previous}` and `{relative}`"),
                );
            }
            if entries.len() >= MAX_IPA_ENTRIES {
                return invalid_apple_bundle(
                    root,
                    format!("artifact has more than {MAX_IPA_ENTRIES} entries"),
                );
            }
            let display_path = root.join(&relative);
            let file_type = child.file_type().map_err(|error| ArtifactError::Io {
                action: "inspect artifact entry type",
                path: display_path.clone(),
                message: error.to_string(),
            })?;
            reject_forbidden_bundle_entry(root, &relative)?;
            let kind = if file_type.is_dir() {
                if depth + 1 > MAX_BUNDLE_DEPTH {
                    return invalid_apple_bundle(
                        root,
                        format!("entry `{relative}` exceeds maximum nesting depth"),
                    );
                }
                let child_directory = open_child_directory(root, &display_path, &directory, &name)?;
                let metadata = child_directory
                    .try_clone()
                    .and_then(|directory| directory.into_std_file().metadata())
                    .map_err(|error| ArtifactError::Io {
                        action: "inspect open artifact directory",
                        path: display_path.clone(),
                        message: error.to_string(),
                    })?;
                reject_dangerous_mode(root, &relative, &metadata)?;
                stack.push((child_directory, relative.clone(), depth + 1));
                TreeEntryKind::Directory
            } else if file_type.is_file() {
                let file = open_scanned_file(root, &display_path, &directory, &child)?;
                let metadata = file.metadata().map_err(|error| ArtifactError::Io {
                    action: "inspect open artifact file",
                    path: display_path.clone(),
                    message: error.to_string(),
                })?;
                reject_dangerous_mode(root, &relative, &metadata)?;
                reject_hardlinked_file(root, &relative, &metadata)?;
                if metadata.len() > MAX_IPA_ENTRY_SIZE {
                    return invalid_apple_bundle(
                        root,
                        format!("entry `{relative}` exceeds the per-file limit"),
                    );
                }
                total_size = total_size.checked_add(metadata.len()).ok_or_else(|| {
                    ArtifactError::InvalidAppleBundle {
                        path: root.to_owned(),
                        reason: "artifact logical size overflow".to_owned(),
                    }
                })?;
                if total_size > MAX_IPA_TOTAL_SIZE {
                    return invalid_apple_bundle(
                        root,
                        "artifact exceeds the total logical-size limit".to_owned(),
                    );
                }
                TreeEntryKind::File
            } else {
                return invalid_apple_bundle(
                    root,
                    format!("entry `{relative}` is a link or special file"),
                );
            };
            entries.push(TreeEntry { relative, kind });
        }
    }
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(TreeIndex { entries })
}

fn open_scanned_file(
    root: &Utf8Path,
    display_path: &Utf8Path,
    parent: &Dir,
    entry: &cap_std::fs::DirEntry,
) -> Result<File, ArtifactError> {
    let file = entry
        .open()
        .map(cap_std::fs::File::into_std)
        .map_err(|error| ArtifactError::Io {
            action: "open artifact file",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    let metadata = file.metadata().map_err(|error| ArtifactError::Io {
        action: "inspect open artifact file",
        path: display_path.to_owned(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() {
        return invalid_apple_bundle(
            root,
            format!("artifact entry `{display_path}` changed type"),
        );
    }
    let name = entry.file_name();
    let after = parent
        .symlink_metadata(&name)
        .map_err(|error| ArtifactError::Io {
            action: "reinspect artifact file",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    if after.file_type().is_symlink() || !after.is_file() {
        return invalid_apple_bundle(
            root,
            format!("artifact entry `{display_path}` changed type"),
        );
    }
    let current = parent
        .open(&name)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| ArtifactError::Io {
            action: "reopen artifact file",
            path: display_path.to_owned(),
            message: error.to_string(),
        })?;
    if !open_files_match(&file, &current).map_err(|error| ArtifactError::Io {
        action: "reidentify artifact file",
        path: display_path.to_owned(),
        message: error.to_string(),
    })? {
        return invalid_apple_bundle(
            root,
            format!("artifact file `{display_path}` changed while being opened"),
        );
    }
    Ok(file)
}

fn direct_children(tree: &TreeIndex, parent: &str) -> BTreeSet<String> {
    tree.entries
        .iter()
        .filter(|entry| Utf8Path::new(&entry.relative).parent() == Some(Utf8Path::new(parent)))
        .map(|entry| entry.relative.clone())
        .collect()
}

fn require_tree_directory(
    root: &Utf8Path,
    tree: &TreeIndex,
    relative: &str,
) -> Result<(), ArtifactError> {
    if tree
        .entries
        .iter()
        .any(|entry| entry.relative == relative && entry.kind == TreeEntryKind::Directory)
    {
        Ok(())
    } else {
        invalid_apple_bundle(root, format!("required directory `{relative}` is missing"))
    }
}

fn reject_forbidden_bundle_entry(root: &Utf8Path, relative: &str) -> Result<(), ArtifactError> {
    let lower = relative.to_lowercase();
    let components = lower.split('/').collect::<Vec<_>>();
    let last = components.last().copied().unwrap_or_default();
    let forbidden_suffixes = [
        ".p12",
        ".p8",
        ".key",
        ".pem",
        ".mobileprovision",
        ".entitlements",
        ".xcent",
        ".swift",
        ".m",
        ".mm",
        ".a",
    ];
    if components.iter().any(|component| {
        matches!(
            *component,
            "_codesignature" | "sc_info" | "keychains" | "credentials" | "secrets"
        )
    }) || last == "embedded.mobileprovision"
        || last == "project.pbxproj"
        || forbidden_suffixes
            .iter()
            .any(|suffix| last.ends_with(suffix))
    {
        return invalid_apple_bundle(
            root,
            format!("forbidden signing, secret, source, or generated entry `{relative}`"),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn reject_dangerous_mode(
    root: &Utf8Path,
    relative: &str,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.mode() & 0o6000 != 0 {
        return invalid_apple_bundle(
            root,
            format!("entry `{relative}` has setuid or setgid mode bits"),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_executable_mode(
    filesystem: &ArtifactFilesystem,
    relative: &str,
    path: &Utf8Path,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    let root = filesystem.display_path();
    let display_path = filesystem.display_entry(path);
    let (file, _) = open_checked_file(filesystem, path, MAX_IPA_ENTRY_SIZE)?;
    let metadata = file.metadata().map_err(|error| ArtifactError::Io {
        action: "inspect executable mode for",
        path: display_path,
        message: error.to_string(),
    })?;
    if metadata.mode() & 0o111 == 0 {
        return invalid_apple_bundle(
            root,
            format!("Mach-O `{relative}` has no executable mode bit"),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_mode(
    _filesystem: &ArtifactFilesystem,
    _relative: &str,
    _path: &Utf8Path,
) -> Result<(), ArtifactError> {
    Ok(())
}

#[cfg(not(unix))]
fn reject_dangerous_mode(
    _root: &Utf8Path,
    _relative: &str,
    _metadata: &Metadata,
) -> Result<(), ArtifactError> {
    Ok(())
}

fn reject_hardlinked_file(
    root: &Utf8Path,
    relative: &str,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if has_multiple_file_links(metadata) {
        return invalid_apple_bundle(
            root,
            format!("entry `{relative}` is a hard-linked regular file"),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn has_multiple_file_links(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.nlink() != 1
}

#[cfg(not(unix))]
fn has_multiple_file_links(_metadata: &Metadata) -> bool {
    // Stable std does not expose Windows link counts. Source ZIP extraction creates
    // fresh files, while open-handle identity checks below still prevent path swaps.
    false
}

fn read_checked_file(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
    limit: u64,
) -> Result<Vec<u8>, ArtifactError> {
    let root = filesystem.display_path();
    let display_path = filesystem.display_entry(relative);
    let (mut file, before) = open_checked_file(filesystem, relative, limit)?;
    let capacity =
        usize::try_from(before.len()).map_err(|_| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("file `{display_path}` is too large for this worker"),
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ArtifactError::Io {
            action: "read",
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    if bytes.len() as u64 != before.len() {
        return invalid_apple_bundle(
            root,
            format!("file `{display_path}` changed size while it was read"),
        );
    }
    verify_open_file_stable(filesystem, relative, &file, &before)?;
    Ok(bytes)
}

fn file_has_macho_magic(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
) -> Result<bool, ArtifactError> {
    let display_path = filesystem.display_entry(relative);
    let (mut file, before) = open_checked_file(filesystem, relative, MAX_IPA_ENTRY_SIZE)?;
    let mut magic = [0_u8; 4];
    let mut filled = 0;
    while filled < magic.len() {
        let count = file
            .read(&mut magic[filled..])
            .map_err(|error| ArtifactError::Io {
                action: "read Mach-O magic from",
                path: display_path.clone(),
                message: error.to_string(),
            })?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    verify_open_file_stable(filesystem, relative, &file, &before)?;
    Ok(filled == 4
        && matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
                | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
        ))
}

fn open_checked_file(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
    limit: u64,
) -> Result<(File, Metadata), ArtifactError> {
    let root = filesystem.display_path();
    validate_portable_relative_path(root, "artifact file", relative.as_str())?;
    let display_path = filesystem.display_entry(relative);
    let before = filesystem
        .directory
        .symlink_metadata(relative)
        .map_err(|error| ArtifactError::Io {
            action: "inspect artifact file",
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return invalid_apple_bundle(root, format!("`{display_path}` is not a regular file"));
    }
    let file = filesystem
        .directory
        .open(relative)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| ArtifactError::Io {
            action: "open artifact file through root capability",
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    let opened = file.metadata().map_err(|error| ArtifactError::Io {
        action: "inspect open file",
        path: display_path.clone(),
        message: error.to_string(),
    })?;
    reject_dangerous_mode(root, relative.as_str(), &opened)?;
    reject_hardlinked_file(root, relative.as_str(), &opened)?;
    if !opened.is_file() || opened.len() > limit {
        return invalid_apple_bundle(
            root,
            format!("file `{display_path}` exceeds the read limit"),
        );
    }
    verify_capability_file_path(filesystem, relative, &file)?;
    Ok((file, opened))
}

fn verify_open_file_stable(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
    file: &File,
    before: &Metadata,
) -> Result<(), ArtifactError> {
    let root = filesystem.display_path();
    let display_path = filesystem.display_entry(relative);
    let opened_after = file.metadata().map_err(|error| ArtifactError::Io {
        action: "reinspect open file",
        path: display_path.clone(),
        message: error.to_string(),
    })?;
    if !same_file_identity(before, &opened_after)
        || before.len() != opened_after.len()
        || before.modified().ok() != opened_after.modified().ok()
    {
        return invalid_apple_bundle(
            root,
            format!("file `{display_path}` changed while being read"),
        );
    }
    verify_capability_file_path(filesystem, relative, file)
}

fn verify_capability_file_path(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
    opened: &File,
) -> Result<(), ArtifactError> {
    let root = filesystem.display_path();
    let display_path = filesystem.display_entry(relative);
    let current_metadata = filesystem
        .directory
        .symlink_metadata(relative)
        .map_err(|error| ArtifactError::Io {
            action: "reinspect artifact file through root capability",
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    if current_metadata.file_type().is_symlink() || !current_metadata.is_file() {
        return invalid_apple_bundle(root, format!("artifact file `{display_path}` changed type"));
    }
    let current = filesystem
        .directory
        .open(relative)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| ArtifactError::Io {
            action: "reopen artifact file through root capability",
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    if !open_files_match(opened, &current).map_err(|error| ArtifactError::Io {
        action: "reidentify artifact file through root capability",
        path: display_path.clone(),
        message: error.to_string(),
    })? {
        return invalid_apple_bundle(
            root,
            format!("artifact file `{display_path}` changed while being accessed"),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

fn open_files_match(left: &File, right: &File) -> std::io::Result<bool> {
    let left = same_file::Handle::from_file(left.try_clone()?)?;
    let right = same_file::Handle::from_file(right.try_clone()?)?;
    Ok(left == right)
}

fn read_filesystem_plist(
    filesystem: &ArtifactFilesystem,
    relative: &Utf8Path,
) -> Result<plist::Dictionary, ArtifactError> {
    let root = filesystem.display_path();
    let display_path = filesystem.display_entry(relative);
    let bytes = read_checked_file(filesystem, relative, 16 * 1024 * 1024)?;
    let value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|error| {
        ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("plist `{display_path}` is invalid: {error}"),
        }
    })?;
    value
        .into_dictionary()
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("plist `{display_path}` is not a dictionary"),
        })
}

fn required_plist_string(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    key: &str,
    context: &str,
) -> Result<String, ArtifactError> {
    dictionary
        .get(key)
        .and_then(plist::Value::as_string)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("{context} has no string `{key}`"),
        })
}

fn validate_plist_string(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    context: &str,
    key: &str,
    expected: &str,
) -> Result<(), ArtifactError> {
    let actual = required_plist_string(root, dictionary, key, context)?;
    if actual != expected {
        return invalid_apple_bundle(
            root,
            format!("{context} `{key}` is `{actual}`, expected `{expected}`"),
        );
    }
    Ok(())
}

fn validate_plist_identity(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    context: &str,
    bundle_identifier: &str,
    app_version: &str,
    build_number: &str,
) -> Result<(), ArtifactError> {
    for (key, expected) in [
        ("CFBundleIdentifier", bundle_identifier),
        ("CFBundleShortVersionString", app_version),
        ("CFBundleVersion", build_number),
    ] {
        validate_plist_string(root, dictionary, context, key, expected)?;
    }
    Ok(())
}

fn plist_string_array(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    key: &str,
    context: &str,
) -> Result<Vec<String>, ArtifactError> {
    let values = dictionary
        .get(key)
        .and_then(plist::Value::as_array)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("{context} has no array `{key}`"),
        })?;
    values
        .iter()
        .map(|value| {
            value.as_string().map(ToOwned::to_owned).ok_or_else(|| {
                ArtifactError::InvalidAppleBundle {
                    path: root.to_owned(),
                    reason: format!("{context} `{key}` contains a non-string value"),
                }
            })
        })
        .collect()
}

fn validate_minimum_os(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    context: &str,
    expected: &str,
) -> Result<(), ArtifactError> {
    let actual = required_plist_string(root, dictionary, "MinimumOSVersion", context)?;
    if parse_apple_version(&actual) != parse_apple_version(expected) {
        return invalid_apple_bundle(
            root,
            format!("{context} MinimumOSVersion is `{actual}`, expected `{expected}`"),
        );
    }
    Ok(())
}

fn validate_supported_platform(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    context: &str,
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    let platforms = plist_string_array(root, dictionary, "CFBundleSupportedPlatforms", context)?;
    if platforms != ["iPhoneOS"] {
        return invalid_apple_bundle(
            root,
            format!("{context} supported platforms are {platforms:?}, expected iPhoneOS"),
        );
    }
    validate_plist_string(root, dictionary, context, "DTPlatformName", "iphoneos")?;
    let sdk_name = required_plist_string(root, dictionary, "DTSDKName", context)?;
    let Some(sdk_suffix) = sdk_name.strip_prefix("iphoneos") else {
        return invalid_apple_bundle(
            root,
            format!("{context} DTSDKName `{sdk_name}` is not an iPhoneOS SDK"),
        );
    };
    if parse_apple_version(sdk_suffix) != parse_apple_version(&expectation.sdk_version) {
        return invalid_apple_bundle(
            root,
            format!(
                "{context} DTSDKName is `{sdk_name}`, expected iphoneos{}",
                expectation.sdk_version
            ),
        );
    }
    validate_plist_string(
        root,
        dictionary,
        context,
        "DTSDKBuild",
        &expectation.sdk_build_version,
    )
}

fn validate_extension_point(
    root: &Utf8Path,
    dictionary: &plist::Dictionary,
    context: &str,
) -> Result<(), ArtifactError> {
    let extension = dictionary
        .get("NSExtension")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("extension `{context}` has no NSExtension dictionary"),
        })?;
    validate_plist_string(
        root,
        extension,
        context,
        "NSExtensionPointIdentifier",
        "com.apple.widgetkit-extension",
    )
}

fn plist_value_is_empty(value: &plist::Value) -> bool {
    match value {
        plist::Value::String(value) => value.trim().is_empty(),
        plist::Value::Array(value) => value.is_empty(),
        plist::Value::Dictionary(value) => value.is_empty(),
        _ => false,
    }
}

fn validate_ferry_resource_metadata(
    root: &Utf8Path,
    bytes: &[u8],
    expectation: &UnsignedXcarchiveExpectation,
) -> Result<(), ArtifactError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("FerryResources.json is invalid JSON: {error}"),
        })?;
    let object = value
        .as_object()
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: "FerryResources.json is not an object".to_owned(),
        })?;
    let expected_strings = [
        ("generator", "cargo-ferry"),
        ("rust_target", "aarch64-apple-ios"),
        ("bundle_identifier", expectation.bundle_identifier.as_str()),
    ];
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || expected_strings.iter().any(|(key, expected)| {
            object.get(*key).and_then(serde_json::Value::as_str) != Some(*expected)
        })
        || object
            .get("ui_backend")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
    {
        return invalid_apple_bundle(
            root,
            "FerryResources.json does not describe the expected physical-iOS build".to_owned(),
        );
    }
    Ok(())
}

fn is_permitted_swift_runtime(relative: &str) -> bool {
    let path = Utf8Path::new(relative);
    path.parent() == Some(Utf8Path::new("Frameworks"))
        && path
            .file_name()
            .is_some_and(|name| name.starts_with("libswift") && has_ascii_extension(name, "dylib"))
}

fn inspect_expected_unsigned_macho(
    root: &Utf8Path,
    relative: &str,
    bytes: &[u8],
    expected: ExpectedUnsignedMachO<'_>,
) -> Result<Vec<MachOSliceEvidence>, ArtifactError> {
    let evidence = inspect_physical_iphone_macho(bytes).map_err(|error| {
        ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("Mach-O `{relative}` is not physical-iPhone code: {error}"),
        }
    })?;
    if evidence.len() != 1 || evidence[0].architecture != "arm64" {
        return invalid_apple_bundle(
            root,
            format!(
                "Mach-O `{relative}` slices are {:?}, expected exactly one arm64 slice",
                evidence
                    .iter()
                    .map(|slice| slice.architecture.as_str())
                    .collect::<Vec<_>>()
            ),
        );
    }
    validate_unsigned_macho_header(root, relative, bytes, expected.kind, expected.linkage)?;
    validate_recorded_macho_versions(
        root,
        relative,
        &evidence[0],
        expected.minimum_os,
        expected.sdk,
        expected.prebuilt_swift_runtime,
    )?;
    Ok(evidence)
}

fn validate_unsigned_macho_header(
    root: &Utf8Path,
    relative: &str,
    bytes: &[u8],
    expected_kind: ExpectedMachOKind,
    expected_linkage: FerryMachOLinkage,
) -> Result<(), ArtifactError> {
    let parsed = Mach::parse(bytes).map_err(|error| ArtifactError::InvalidAppleBundle {
        path: root.to_owned(),
        reason: format!("Mach-O `{relative}` is malformed: {error}"),
    })?;
    let mut slice_count = 0_usize;
    match parsed {
        Mach::Binary(binary) => {
            slice_count += 1;
            validate_macho_binary_header(root, relative, &binary, expected_kind, expected_linkage)?;
        }
        Mach::Fat(container) => {
            for entry in &container {
                match entry.map_err(|error| ArtifactError::InvalidAppleBundle {
                    path: root.to_owned(),
                    reason: format!("Mach-O `{relative}` fat slice is malformed: {error}"),
                })? {
                    SingleArch::MachO(binary) => {
                        slice_count += 1;
                        validate_macho_binary_header(
                            root,
                            relative,
                            &binary,
                            expected_kind,
                            expected_linkage,
                        )?;
                    }
                    SingleArch::Archive(_) => {
                        return invalid_apple_bundle(
                            root,
                            format!("Mach-O `{relative}` contains a static archive slice"),
                        );
                    }
                }
            }
        }
    }
    if slice_count != 1 {
        return invalid_apple_bundle(
            root,
            format!("Mach-O `{relative}` does not have exactly one slice"),
        );
    }
    Ok(())
}

fn validate_macho_binary_header(
    root: &Utf8Path,
    relative: &str,
    binary: &MachO<'_>,
    expected_kind: ExpectedMachOKind,
    expected_linkage: FerryMachOLinkage,
) -> Result<(), ArtifactError> {
    if binary.header.cputype != CPU_TYPE_ARM64
        || !matches!(
            binary.header.cpusubtype(),
            CPU_SUBTYPE_ARM64_ALL | CPU_SUBTYPE_ARM64_V8
        )
    {
        return invalid_apple_bundle(
            root,
            format!("Mach-O `{relative}` does not use the expected arm64 CPU subtype"),
        );
    }
    let expected_filetype = match expected_kind {
        ExpectedMachOKind::Executable => MH_EXECUTE,
        ExpectedMachOKind::DynamicLibrary => MH_DYLIB,
    };
    if binary.header.filetype != expected_filetype {
        return invalid_apple_bundle(
            root,
            format!(
                "Mach-O `{relative}` file type is {:#x}, expected {expected_filetype:#x}",
                binary.header.filetype
            ),
        );
    }
    for command in &binary.load_commands {
        if let CommandVariant::CodeSignature(signature) = &command.command
            && signature.datasize != 0
        {
            return invalid_apple_bundle(
                root,
                format!("unsigned Mach-O `{relative}` contains a non-empty code signature"),
            );
        }
    }
    validate_ferry_macho_linkage(root, relative, binary, expected_linkage)
}

fn validate_ferry_macho_linkage(
    root: &Utf8Path,
    relative: &str,
    binary: &MachO<'_>,
    expected: FerryMachOLinkage,
) -> Result<(), ArtifactError> {
    let expected_install_name = match expected {
        FerryMachOLinkage::RuntimeBridge { .. } => Some(RUNTIME_BRIDGE_INSTALL_NAME),
        FerryMachOLinkage::ActivityModel => Some(ACTIVITY_MODEL_INSTALL_NAME),
        FerryMachOLinkage::None | FerryMachOLinkage::LiveActivityExtension => None,
    };
    if let Some(expected_install_name) = expected_install_name {
        let id_commands = binary
            .load_commands
            .iter()
            .filter(|command| matches!(&command.command, CommandVariant::IdDylib(_)))
            .count();
        if id_commands != 1 || binary.name != Some(expected_install_name) {
            return invalid_apple_bundle(
                root,
                format!(
                    "Mach-O `{relative}` dylib ID is {:?} across {id_commands} LC_ID_DYLIB commands, expected exactly `{expected_install_name}`",
                    binary.name
                ),
            );
        }
    }

    let expected_dependencies: Option<&[&str]> = match expected {
        FerryMachOLinkage::RuntimeBridge {
            activity_model_required: true,
        }
        | FerryMachOLinkage::LiveActivityExtension => Some(&[ACTIVITY_MODEL_INSTALL_NAME]),
        FerryMachOLinkage::RuntimeBridge {
            activity_model_required: false,
        }
        | FerryMachOLinkage::ActivityModel => Some(&[]),
        FerryMachOLinkage::None => None,
    };
    let Some(expected_dependencies) = expected_dependencies else {
        return Ok(());
    };
    let mut actual_dependencies = binary
        .libs
        .iter()
        .skip(1)
        .copied()
        .filter(|dependency| is_ferry_framework_dependency(dependency))
        .collect::<Vec<_>>();
    actual_dependencies.sort_unstable();
    let mut expected_dependencies = expected_dependencies.to_vec();
    expected_dependencies.sort_unstable();
    if actual_dependencies != expected_dependencies {
        return invalid_apple_bundle(
            root,
            format!(
                "Mach-O `{relative}` Ferry framework dependencies are {actual_dependencies:?}, expected {expected_dependencies:?}"
            ),
        );
    }
    Ok(())
}

fn is_ferry_framework_dependency(dependency: &str) -> bool {
    dependency.split('/').any(|component| {
        matches!(
            component,
            "FerryRuntimeBridge.framework" | "FerryActivityModel.framework"
        )
    })
}

fn validate_recorded_macho_versions(
    root: &Utf8Path,
    relative: &str,
    evidence: &MachOSliceEvidence,
    expected_minimum_os: &str,
    expected_sdk: &str,
    prebuilt_swift_runtime: bool,
) -> Result<(), ArtifactError> {
    let expected_minimum = parse_apple_version(expected_minimum_os).ok_or_else(|| {
        ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("invalid expected minimum OS `{expected_minimum_os}`"),
        }
    })?;
    let expected_sdk =
        parse_apple_version(expected_sdk).ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("invalid expected SDK `{expected_sdk}`"),
        })?;
    let actual_minimum = evidence
        .minimum_os
        .as_deref()
        .and_then(parse_apple_version)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("Mach-O `{relative}` has no numeric minimum OS"),
        })?;
    let actual_sdk = evidence
        .sdk
        .as_deref()
        .and_then(parse_apple_version)
        .ok_or_else(|| ArtifactError::InvalidAppleBundle {
            path: root.to_owned(),
            reason: format!("Mach-O `{relative}` has no numeric SDK"),
        })?;
    let versions_match = if prebuilt_swift_runtime {
        actual_minimum <= expected_minimum && actual_sdk <= expected_sdk
    } else {
        actual_minimum == expected_minimum && actual_sdk == expected_sdk
    };
    if !versions_match {
        return invalid_apple_bundle(
            root,
            format!(
                "Mach-O `{relative}` records minOS {:?} and SDK {:?}; expected minOS {:?} and SDK {:?}{}",
                actual_minimum,
                actual_sdk,
                expected_minimum,
                expected_sdk,
                if prebuilt_swift_runtime {
                    " or older compatible Swift-runtime values"
                } else {
                    ""
                }
            ),
        );
    }
    Ok(())
}

fn parse_apple_version(value: &str) -> Option<[u32; 3]> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    let mut version = [0_u32; 3];
    for (index, component) in components.iter().enumerate() {
        version[index] = component.parse().ok()?;
    }
    Some(version)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn invalid_apple_bundle<T>(path: &Utf8Path, reason: String) -> Result<T, ArtifactError> {
    Err(ArtifactError::InvalidAppleBundle {
        path: path.to_owned(),
        reason,
    })
}

fn read_zip_plist<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &Utf8Path,
    name: &str,
) -> Result<plist::Dictionary, ArtifactError> {
    let bytes = read_zip_entry(archive, path, name)?;
    let value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|error| {
        ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("plist `{name}` is invalid: {error}"),
        }
    })?;
    value
        .into_dictionary()
        .ok_or_else(|| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("plist `{name}` is not a dictionary"),
        })
}

fn read_zip_entry<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &Utf8Path,
    name: &str,
) -> Result<Vec<u8>, ArtifactError> {
    let entry = archive
        .by_name(name)
        .map_err(|error| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("required entry `{name}` is missing: {error}"),
        })?;
    if entry.size() > MAX_IPA_ENTRY_SIZE {
        return invalid_ipa(path, format!("entry `{name}` exceeds the read limit"));
    }
    let capacity = usize::try_from(entry.size()).map_err(|_| ArtifactError::InvalidIpa {
        path: path.to_owned(),
        reason: format!("entry `{name}` is too large for this client"),
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    entry
        .take(MAX_IPA_ENTRY_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ArtifactError::Io {
            action: "read entry from",
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    if bytes.len() > capacity {
        return invalid_ipa(path, format!("entry `{name}` exceeded its declared size"));
    }
    Ok(bytes)
}

fn plist_string(
    path: &Utf8Path,
    dictionary: &plist::Dictionary,
    key: &str,
) -> Result<String, ArtifactError> {
    dictionary
        .get(key)
        .and_then(plist::Value::as_string)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("Info.plist has no string `{key}`"),
        })
}

fn is_main_info_plist(name: &str) -> bool {
    let components = name.split('/').collect::<Vec<_>>();
    components.len() == 3
        && components[0] == "Payload"
        && has_ascii_extension(components[1], "app")
        && components[2] == "Info.plist"
}

fn validate_zip_name(path: &Utf8Path, name: &str) -> Result<(), ArtifactError> {
    if name.is_empty()
        || name.len() > MAX_IPA_ENTRY_NAME
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
    {
        return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
    }
    let trimmed = name.trim_end_matches('/');
    if trimmed.is_empty() {
        return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
    }
    for (index, component) in trimmed.split('/').enumerate() {
        if component.is_empty() || component == "." || component == ".." {
            return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
        }
        if index == 0 && component.len() >= 2 && component.as_bytes()[1] == b':' {
            return invalid_ipa(path, format!("Windows drive path in ZIP entry `{name}`"));
        }
    }
    Ok(())
}

fn canonical_archive_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

fn has_ascii_extension(path: &str, expected: &str) -> bool {
    path.rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case(expected))
}

fn reject_sensitive_or_generated_name(path: &Utf8Path, name: &str) -> Result<(), ArtifactError> {
    let lower = name.to_lowercase();
    let forbidden_suffixes = [
        ".p12",
        ".p8",
        ".key",
        ".pem",
        ".mobileprovision.bak",
        ".xcodeproj/project.pbxproj",
        ".swift",
        ".m",
        ".mm",
    ];
    if forbidden_suffixes
        .iter()
        .any(|suffix| lower.ends_with(suffix))
        || lower.contains("/keychains/")
        || lower.contains("/credentials/")
        || lower.contains("/secrets/")
    {
        return invalid_ipa(
            path,
            format!("forbidden sensitive/generated entry `{name}`"),
        );
    }
    Ok(())
}

fn sha256_file(path: &Utf8Path) -> Result<String, ArtifactError> {
    let mut file = File::open(path).map_err(|error| ArtifactError::Io {
        action: "open",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).map_err(|error| ArtifactError::Io {
            action: "hash",
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(lower_hex(&digest.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn invalid_ipa<T>(path: &Utf8Path, reason: String) -> Result<T, ArtifactError> {
    Err(ArtifactError::InvalidIpa {
        path: path.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin_arm64(platform: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            0xfeed_facfu32,
            CPU_TYPE_ARM64,
            0,
            2,
            1,
            24,
            0,
            0,
            0x32,
            24,
            platform,
            0x0011_0000,
            0x0012_0200,
            0,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn device_and_simulator_arm64_are_not_confused() {
        let device = inspect_physical_iphone_macho(&thin_arm64(2)).unwrap();
        assert_eq!(device[0].architecture, "arm64");
        assert_eq!(device[0].platform, ApplePlatform::Ios);

        let simulator = inspect_physical_iphone_macho(&thin_arm64(7)).unwrap_err();
        assert!(matches!(simulator, ArtifactError::SimulatorBinary));
    }

    #[test]
    fn legacy_iphoneos_command_is_not_promoted_to_device_proof() {
        let mut bytes = thin_arm64(2);
        bytes[32..36].copy_from_slice(&0x25_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&16_u32.to_le_bytes());
        bytes.truncate(48);
        bytes[20..24].copy_from_slice(&16_u32.to_le_bytes());
        let error = inspect_physical_iphone_macho(&bytes).unwrap_err();
        assert!(matches!(error, ArtifactError::DevicePlatformUnproven(_)));
    }

    #[test]
    fn artifact_kind_must_be_unique() {
        let mut manifest = ArtifactManifest::new("operation", "job");
        assert!(matches!(
            manifest.one_artifact(ArtifactKind::Ipa),
            Err(ArtifactError::ManifestArtifactMissing { .. })
        ));
        let record = ArtifactRecord {
            artifact_id: "ipa".to_owned(),
            kind: ArtifactKind::Ipa,
            file_name: "Weather-development.ipa".to_owned(),
            size: 1,
            sha256: "00".repeat(32),
            media_type: Some("application/zip".to_owned()),
        };
        manifest.artifacts.push(record.clone());
        assert_eq!(manifest.one_artifact(ArtifactKind::Ipa).unwrap(), &record);
        manifest.artifacts.push(record);
        assert!(matches!(
            manifest.one_artifact(ArtifactKind::Ipa),
            Err(ArtifactError::ManifestArtifactAmbiguous { .. })
        ));
    }

    #[test]
    fn unsafe_zip_names_are_rejected() {
        let path = Utf8Path::new("fixture.ipa");
        for name in ["../secret", "/absolute", "C:/windows", "Payload\\bad"] {
            assert!(validate_zip_name(path, name).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn archive_collision_key_normalizes_unicode_and_case() {
        assert_eq!(
            canonical_archive_key("Payload/Café.app/FILE"),
            canonical_archive_key("payload/Cafe\u{301}.app/file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn capability_reads_cannot_escape_or_validate_a_replaced_root() {
        use std::os::unix::fs::symlink;

        for replacement_is_symlink in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let parent = Utf8Path::from_path(temporary.path()).unwrap();
            let root = parent.join("artifact.app");
            let moved = parent.join("opened-artifact.app");
            let outside = parent.join("outside");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(root.join("payload"), b"trusted bytes").unwrap();
            fs::write(outside.join("payload"), b"outside bytes").unwrap();

            let filesystem = ArtifactFilesystem::open_ambient(&root).unwrap();
            let scanned = scan_real_tree(&filesystem).unwrap();
            assert_eq!(scanned.relative_paths(), ["payload"]);
            fs::rename(&root, &moved).unwrap();
            if replacement_is_symlink {
                symlink(&outside, &root).unwrap();
            } else {
                fs::create_dir(&root).unwrap();
                fs::write(root.join("payload"), b"outside bytes").unwrap();
            }

            let bytes = read_checked_file(&filesystem, Utf8Path::new("payload"), 1024).unwrap();
            assert_eq!(bytes, b"trusted bytes");
            assert!(filesystem.verify_ambient_binding().is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn capability_subdirectory_cannot_validate_a_replaced_nested_path() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(temporary.path()).unwrap();
        let root = parent.join("artifact.xcarchive");
        let original = root.join("Products/Applications/App.app");
        let moved = root.join("Products/Applications/opened-App.app");
        fs::create_dir_all(&original).unwrap();
        fs::write(original.join("payload"), b"trusted bytes").unwrap();

        let filesystem = ArtifactFilesystem::open_ambient(&root).unwrap();
        let app = filesystem
            .open_subdirectory(Utf8Path::new("Products/Applications/App.app"))
            .unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("payload"), b"replacement bytes").unwrap();

        let bytes = read_checked_file(&app, Utf8Path::new("payload"), 1024).unwrap();
        assert_eq!(bytes, b"trusted bytes");
        assert!(app.verify_ambient_binding().is_err());
        assert!(filesystem.verify_ambient_binding().is_ok());
    }
}
